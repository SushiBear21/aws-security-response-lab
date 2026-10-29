import hashlib
import json
import os
from datetime import datetime, timezone

import boto3

from app.detection import normalize_event, parse_time


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def encode(value):
    return json.dumps(
        value,
        sort_keys=True,
        allow_nan=False,
        separators=(",", ":"),
    ).encode("utf-8")


def put_json(client, bucket, key, body):
    client.put_object(
        Bucket=bucket,
        Key=key,
        Body=body,
        ContentType="application/json",
        ServerSideEncryption="AES256",
    )


def lambda_handler(event, context):
    received_at = utc_now()
    stage = "validation"

    try:
        incident = normalize_event(
            event,
            os.environ["EXPECTED_ACCOUNT"],
            os.environ["EXPECTED_REGION"],
            os.environ["TARGET_GROUP_ID"],
        )

        if incident is None:
            print(json.dumps({
                "event": "event_ignored",
                "request_id": context.aws_request_id,
            }))
            return {"status": "ignored"}

        incident["received_at"] = received_at
        incident["detected_at"] = utc_now()
        incident["request_id"] = context.aws_request_id
        incident["detector_version"] = "lesson-3"

        latency = (
            parse_time(incident["detected_at"])
            - parse_time(incident["source_event_time"])
        ).total_seconds()

        incident["event_to_detection_seconds"] = (
            round(latency, 3) if latency >= 0 else None
        )

        # Every delivery attempt has its own evidence directory.
        # Repeated source events retain the same logical incident ID.
        prefix = (
            f"incidents/{incident['incident_id']}/"
            f"attempts/{context.aws_request_id}"
        )

        client = boto3.client("s3")
        bucket = os.environ["EVIDENCE_BUCKET"]

        event_bytes = encode(event)
        incident_bytes = encode(incident)

        stage = "evidence_storage"

        put_json(client, bucket, f"{prefix}/event.json", event_bytes)
        put_json(client, bucket, f"{prefix}/incident.json", incident_bytes)

        persisted_at = utc_now()

        completion = {
            "incident_id": incident["incident_id"],
            "request_id": context.aws_request_id,
            "persisted_at": persisted_at,
            "event_sha256": hashlib.sha256(event_bytes).hexdigest(),
            "incident_sha256": hashlib.sha256(incident_bytes).hexdigest(),
        }

        put_json(
            client,
            bucket,
            f"{prefix}/complete.json",
            encode(completion),
        )

        print(json.dumps({
            "event": "incident_processed",
            "incident_id": incident["incident_id"],
            "request_id": context.aws_request_id,
            "severity": incident["severity"],
            "event_to_detection_seconds":
                incident["event_to_detection_seconds"],
            "incident_key": f"{prefix}/incident.json",
        }))

        return {
            "status": "complete",
            "incident_id": incident["incident_id"],
            "incident_key": f"{prefix}/incident.json",
        }

    except Exception as error:
        print(json.dumps({
            "event": "processing_failed",
            "stage": stage,
            "request_id": context.aws_request_id,
            "error_type": type(error).__name__,
        }))
        raise RuntimeError("Security detector failed.") from None