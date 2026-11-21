"""Bounded, local parser for a UTF-8 Sysmon Event XML export."""
from datetime import timezone
from ipaddress import ip_address
from uuid import UUID
from xml.etree import ElementTree as ET

from app.detection import parse_time
from app.response import digest


NAMESPACE = {"w": "http://schemas.microsoft.com/win/2004/08/events/event"}
PROVIDER = "Microsoft-Windows-Sysmon"
CHANNEL = f"{PROVIDER}/Operational"
MAX_BYTES = 2_000_000
MAX_EVENTS = 1_000


def normalize(element):
    system = element.find("w:System", NAMESPACE)
    if system is None:
        raise ValueError("Missing System element")
    provider = system.find("w:Provider", NAMESPACE)
    if provider is None or provider.get("Name") != PROVIDER:
        return None
    kind = int(system.findtext("w:EventID", namespaces=NAMESPACE) or "0")
    if kind not in {1, 3}:
        return None
    channel = system.findtext("w:Channel", namespaces=NAMESPACE)
    if channel != CHANNEL:
        raise ValueError("Unexpected Sysmon channel")
    host = (system.findtext("w:Computer", namespaces=NAMESPACE) or "").strip().lower()
    record = int(system.findtext("w:EventRecordID", namespaces=NAMESPACE) or "0")
    time = system.find("w:TimeCreated", NAMESPACE)
    if not host or len(host) > 253 or record <= 0 or time is None:
        raise ValueError("Missing Sysmon source identity")
    time = parse_time(time.get("SystemTime")).astimezone(timezone.utc).isoformat(timespec="microseconds")
    fields = {}
    for field in element.findall("w:EventData/w:Data", NAMESPACE):
        key = field.get("Name")
        if key in fields:
            raise ValueError("Duplicate Sysmon event field")
        fields[key] = field.text or ""
    image = fields.get("Image", "").strip().lower()
    if not image or len(image) > 512:
        raise ValueError("Missing or oversized Sysmon image path")
    identity = {"host": host, "channel": channel, "record": record, "time": time}
    event = {"id": digest(identity), **identity, "event_id": kind,
             "process_guid": str(UUID(fields.get("ProcessGuid", ""))), "image": image}
    if kind == 3:
        direction = fields.get("Initiated", "").lower()
        destination = str(ip_address(fields.get("DestinationIp", "")))
        port = int(fields.get("DestinationPort", "0"))
        protocol = fields.get("Protocol", "").lower()
        if direction not in {"true", "false"} or not 1 <= port <= 65535 or protocol not in {"tcp", "udp"}:
            raise ValueError("Invalid Sysmon network fields")
        event.update(initiated=direction == "true", destination=destination, port=port, protocol=protocol)
    return event


def load_sysmon(path):
    with open(path, "rb") as stream:
        raw = stream.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError("Sysmon export exceeds size limit")
    source = raw.decode("utf-8-sig")
    upper = source.upper()
    if "<!DOCTYPE" in upper or "<!ENTITY" in upper:
        raise ValueError("DTD and entity declarations are unsupported")
    root = ET.fromstring(source)
    tag = f"{{{NAMESPACE['w']}}}Event"
    if root.tag == tag:
        entries = [root]
    elif root.tag == "Events":
        entries = list(root)
    else:
        raise ValueError("Expected a Sysmon Event or Events wrapper")
    if len(entries) > MAX_EVENTS or any(node.tag != tag for node in entries):
        raise ValueError("Unexpected event export shape or count")
    return [event for node in entries if (event := normalize(node)) is not None]
