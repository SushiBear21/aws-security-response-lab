"""Offline SIEM, case evidence and approval-gated endpoint state simulation."""
import argparse
from contextlib import closing, contextmanager
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
import sys
import time
from uuid import uuid4

from app.endpoint_siem import CORRELATION, COUNTS, IMAGE, RULE, SCHEMA, TIMELINE, WINDOW_SECONDS
from app.finding_router import routing_evidence
from app.response import canonical, digest, require_approved_action, verify_payload
from app.sysmon import load_sysmon

TTL_SECONDS = 600
EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
ACTIONS = {"isolate": ("connected", "isolated"), "rollback": ("isolated", "connected")}
TABLES = SCHEMA + """
CREATE TABLE IF NOT EXISTS settings (id INTEGER PRIMARY KEY CHECK (id = 1), policy_sha256 TEXT);
CREATE TABLE IF NOT EXISTS cases (id TEXT PRIMARY KEY, evidence TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS endpoints (
    host TEXT PRIMARY KEY, isolated_by TEXT, generation INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS proposals (id TEXT PRIMARY KEY, body TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS decisions (sequence INTEGER PRIMARY KEY, body TEXT NOT NULL);
"""


def read_policy(path):
    policy = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(policy, dict) or set(policy) != {"assets", "suppressions"}:
        raise ValueError("Expected assets and suppressions")
    if not isinstance(policy["assets"], dict) or not isinstance(policy["suppressions"], list):
        raise ValueError("Invalid inventory or suppression collection")
    for host, asset in policy["assets"].items():
        if (not host or host != host.lower() or not isinstance(asset, dict)
                or set(asset) != {"owner", "criticality"}
                or not all(isinstance(v, str) and v.strip() for v in asset.values())):
            raise ValueError("Invalid asset inventory entry")
    for rule in policy["suppressions"]:
        if (not isinstance(rule, dict) or set(rule) != {"host", "image", "destination", "port", "reason"}
                or rule["host"] not in policy["assets"] or rule["image"] != IMAGE
                or not isinstance(rule["destination"], str)
                or type(rule["port"]) is not int or not 1 <= rule["port"] <= 65535
                or not isinstance(rule["reason"], str) or not rule["reason"].strip()):
            raise ValueError("Invalid narrow suppression entry")
    return policy


def suppress(network, policy):
    fields = ("host", "image", "destination", "port")
    return next((item["reason"] for item in policy["suppressions"]
                 if all(item[k] == network[k] for k in fields)), None)


class Workbench:
    def __init__(self, path, clock=None):
        self.path = path
        self.clock = clock or (lambda: int(time.time()))
        with closing(sqlite3.connect(path)) as db:
            db.executescript(TABLES)

    @contextmanager
    def transaction(self):
        with closing(sqlite3.connect(self.path, timeout=10)) as db, db:
            db.row_factory = sqlite3.Row
            db.execute("BEGIN IMMEDIATE")
            yield db

    def ingest(self, events, policy):
        with self.transaction() as db:
            config = digest(policy)
            saved = db.execute("SELECT policy_sha256 FROM settings WHERE id=1").fetchone()
            if saved and saved[0] != config:
                raise ValueError("Use a new database for a changed inventory or tuning policy")
            db.execute("INSERT OR IGNORE INTO settings VALUES (1, ?)", (config,))
            inserted = 0
            for entry in events:
                raw = canonical(entry)
                old = db.execute("SELECT payload FROM events WHERE id=?", (entry["id"],)).fetchone()
                if old:
                    if old[0] != raw:
                        raise ValueError("Conflicting delivery for the same event identity")
                    continue
                delta = datetime.fromisoformat(entry["time"]) - EPOCH
                micros = ((delta.days * 86400 + delta.seconds) * 1_000_000 + delta.microseconds)
                db.execute(
                    "INSERT INTO events (id, host, process_guid, event_id, at, clock_us, image, initiated, payload) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (entry["id"], entry["host"], entry["process_guid"], entry["event_id"],
                     entry["time"], micros, entry["image"], entry.get("initiated"), raw),
                )
                inserted += 1
            return {"inserted": inserted, "duplicate_events": len(events) - inserted,
                    **self._route_cases(db, policy)}

    def _route_cases(self, db, policy):
        matches = db.execute(CORRELATION, (IMAGE, WINDOW_SECONDS * 1_000_000))
        suppressions = {}
        created = []
        for row in matches:
            process, network = json.loads(row["process"]), json.loads(row["network"])
            reason = suppress(network, policy)
            if reason:
                suppressions[network["id"]] = reason
                continue
            host, guid = process["host"], process["process_guid"]
            finding = {
                "source": "sysmon-lab", "finding_id": digest([RULE, host, guid]), "rule": RULE,
                "host": host, "process_guid": guid, "scope": "synthetic_or_owned_lab",
                "response_state": "no_response_requested",
            }
            case_id, event_bytes, finding_bytes = routing_evidence(
                {"process": process, "network": network}, finding
            )
            asset = policy["assets"].get(host)
            record = {
                "case_id": case_id, "finding": json.loads(finding_bytes), "trigger": json.loads(event_bytes),
                "trigger_sha256": digest(json.loads(event_bytes)), "finding_sha256": digest(finding),
                "asset": asset, "containment_eligible": asset is not None,
                "policy_sha256": digest(policy),
            }
            cursor = db.execute("INSERT OR IGNORE INTO cases VALUES (?, ?)", (case_id, canonical(record)))
            if cursor.rowcount:
                created.append(case_id)
        return {"new_cases": sorted(created), "suppressed_network_events": suppressions}

    @staticmethod
    def _case(db, case_id):
        row = db.execute("SELECT evidence FROM cases WHERE id=?", (case_id,)).fetchone()
        if row is None:
            raise ValueError("Unknown case")
        return json.loads(row[0])

    @staticmethod
    def _proposal(db, run_id):
        row = db.execute("SELECT body FROM proposals WHERE id=?", (run_id,)).fetchone()
        if row is None:
            raise ValueError("Unknown proposal")
        return json.loads(row[0])

    @staticmethod
    def _endpoint(db, host):
        row = db.execute("SELECT isolated_by, generation FROM endpoints WHERE host=?", (host,)).fetchone()
        return tuple(row) if row else (None, 0)

    def _log(self, db, kind, actor, item):
        db.execute("INSERT INTO decisions (body) VALUES (?)", (canonical({
            "at": self.clock(), "event": kind, "actor": actor,
            "run_id": item["run_id"], "payload_sha256": item["payload_sha256"],
        }),))

    def propose(self, case_id, action):
        before, after = ACTIONS[action]
        with self.transaction() as db:
            record = self._case(db, case_id)
            host = record["finding"]["host"]
            owner, generation = self._endpoint(db, host)
            expected_owner = case_id if before == "isolated" else None
            if not record["containment_eligible"] or owner != expected_owner:
                raise ValueError("Endpoint outside the simulated response boundary or state has changed")
            payload = {"scope": "local_simulation", "case_id": case_id, "host": host, "action": action,
                       "expected_state": before, "desired_state": after, "generation": generation,
                       "case_evidence_sha256": digest(record)}
            item = {"run_id": uuid4().hex, "state": "PENDING", "payload_json": canonical(payload),
                    "payload_sha256": digest(payload)}
            db.execute("INSERT INTO proposals VALUES (?, ?)", (item["run_id"], canonical(item)))
            self._log(db, "proposed", "lab-operator", item)
            return item

    def approve(self, run_id, confirmed_digest):
        with self.transaction() as db:
            item = self._proposal(db, run_id)
            verify_payload(item)
            if item["state"] != "PENDING" or confirmed_digest != item["payload_sha256"]:
                raise ValueError("Approval requires a pending proposal and its exact payload digest")
            item.update(state="APPROVED", approved_sha256=confirmed_digest, expires_at=self.clock() + TTL_SECONDS)
            db.execute("UPDATE proposals SET body=? WHERE id=?", (canonical(item), run_id))
            self._log(db, "approved", "lab-reviewer", item)
            return item

    def execute(self, run_id):
        with self.transaction() as db:
            item = self._proposal(db, run_id)
            try:
                payload = verify_payload(item)
                before, after = ACTIONS[payload["action"]]
                case_id, host = payload["case_id"], payload["host"]
                case = self._case(db, case_id)
                proposed_generation = payload.get("generation")
                expected_payload = {
                    "scope": "local_simulation", "case_id": case_id, "host": case["finding"]["host"],
                    "action": payload["action"], "expected_state": before, "desired_state": after,
                    "generation": proposed_generation, "case_evidence_sha256": digest(case),
                }
                if (type(proposed_generation) is not int or proposed_generation < 0
                        or payload != expected_payload or not case["containment_eligible"]):
                    raise ValueError("Proposal target or transition is outside the simulated boundary")
                owner, generation = self._endpoint(db, host)
                if item["state"] == "EXECUTED":
                    return {"status": "already_executed", "desired_state_present":
                            owner == (case_id if after == "isolated" else None)}
                expected_owner = case_id if before == "isolated" else None
                require_approved_action(
                    item, self.clock(), (owner, generation), (expected_owner, proposed_generation)
                )
                db.execute(
                    "INSERT INTO endpoints VALUES (?, ?, ?) ON CONFLICT(host) DO UPDATE "
                    "SET isolated_by=excluded.isolated_by, generation=excluded.generation",
                    (host, case_id if after == "isolated" else None, generation + 1),
                )
                item["state"] = "EXECUTED"
                db.execute("UPDATE proposals SET body=? WHERE id=?", (canonical(item), run_id))
                self._log(db, "executed", "lab-operator", item)
                return {"status": "executed", "state": after, "scope": "local_simulation"}
            except ValueError as error:
                self._log(db, "execution_denied", "lab-operator", item)
                reason = str(error)
        raise ValueError(reason)

    def report(self):
        with self.transaction() as db:
            cases = []
            for row in db.execute("SELECT evidence FROM cases ORDER BY id"):
                case = json.loads(row[0])
                finding = case["finding"]
                host = finding["host"]
                timeline = [json.loads(e[0]) for e in db.execute(TIMELINE, (host, finding["process_guid"]))]
                owner, _ = self._endpoint(db, host)
                cases.append({**case, "timeline": timeline, "timeline_sha256": digest(timeline),
                              "simulated_state": "isolated" if owner else "connected",
                              "isolation_owner": owner})
            return {
                "scope": "local_simulation", "cases": cases,
                "siem_event_counts": [dict(row) for row in db.execute(COUNTS)],
                "proposals": [json.loads(row[0]) for row in db.execute("SELECT body FROM proposals ORDER BY id")],
                "decisions": [json.loads(row[0]) for row in db.execute("SELECT body FROM decisions ORDER BY sequence")],
            }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", required=True, type=Path)
    commands = parser.add_subparsers(dest="command", required=True)
    ingest = commands.add_parser("ingest")
    ingest.add_argument("--xml", required=True, type=Path)
    ingest.add_argument("--policy", required=True, type=Path)
    commands.add_parser("report")
    proposal = commands.add_parser("propose")
    proposal.add_argument("--case", required=True)
    proposal.add_argument("--action", choices=ACTIONS, required=True)
    approval = commands.add_parser("approve")
    approval.add_argument("--run", required=True)
    approval.add_argument("--digest", required=True)
    execute = commands.add_parser("execute")
    execute.add_argument("--run", required=True)
    args = parser.parse_args()
    lab = Workbench(args.db)
    try:
        if args.command == "ingest":
            result = lab.ingest(load_sysmon(args.xml), read_policy(args.policy))
        elif args.command == "propose":
            result = lab.propose(args.case, args.action)
        elif args.command == "approve":
            result = lab.approve(args.run, args.digest)
        elif args.command == "execute":
            result = lab.execute(args.run)
        else:
            result = lab.report()
    except (ValueError, OSError, SyntaxError) as error:
        print(error, file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
