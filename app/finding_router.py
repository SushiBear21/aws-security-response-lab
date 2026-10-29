import hashlib
import json
import os
from datetime import datetime, timezone

import boto3

from app.findings import normalize_findings


def now():
    return datetime.now(timezone.utc).isoformat()


def encode(value):
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def put(client, bucket, key, body):
    client.put_object(
        Bucket=bucket,
        Key=key,
        Body=body,
        ContentType="application/json",
        ServerSideEncryption="AES256",
    )


def lambda_handler(event, context):
    received_at = now()
    stage = "normalization"

    try:
        findings = normalize_findings(event)

        if not findings:
            print(json.dumps({
                "event": "finding_event_ignored",
                "request_id": context.aws_request_id,
            }))
            return {"status": "ignored"}

        bucket = os.environ["EVIDENCE_BUCKET"]
        topic = os.environ["ALERT_TOPIC_ARN"]
        s3 = boto3.client("s3")
        sns = boto3.client("sns")

        results = []

        for finding in findings:
            finding["received_at"] = received_at
            finding["eventbridge_event_id"] = event.get("id")
            finding["request_id"] = context.aws_request_id

            # Source-specific identity keeps the two integration paths distinct.
            identity = (
                finding["source"] + "|" + finding["finding_id"]
            )
            identity_hash = hashlib.sha256(identity.encode()).hexdigest()

            prefix = (
                f"findings/{finding['source']}/{identity_hash}/"
                f"attempts/{context.aws_request_id}"
            )

            event_bytes = encode(event)
            finding_bytes = encode(finding)

            stage = "evidence_storage"

            put(s3, bucket, f"{prefix}/event.json", event_bytes)
            put(s3, bucket, f"{prefix}/finding.json", finding_bytes)

            persisted_at = now()

            stage = "notification"

            alert = {
                "type": "LAB_FINDING_ROUTER_NOTIFICATION",
                "source": finding["source"],
                "finding_id": finding["finding_id"],
                "title": finding["title"],
                "sample_status": finding["sample_status"],
                "severity_original": finding["severity_original"],
                "evidence_uri":
                    f"s3://{bucket}/{prefix}/finding.json",
                "response_state": "no_response_requested",
                "interpretation": (
                    "Lab integration notification. Sample status must be "
                    "verified from source evidence. No quarantine invoked."
                ),
            }

            notification = sns.publish(
                TopicArn=topic,
                Subject="P3 LAB: Security finding routed",
                Message=json.dumps(alert, indent=2),
            )

            published_at = now()

            completion = {
                "source": finding["source"],
                "finding_id": finding["finding_id"],
                "received_at": received_at,
                "persisted_at": persisted_at,
                "published_at": published_at,
                "request_id": context.aws_request_id,
                "sns_message_id": notification["MessageId"],
                "event_sha256": hashlib.sha256(event_bytes).hexdigest(),
                "finding_sha256":
                    hashlib.sha256(finding_bytes).hexdigest(),
                "receipt_to_publish_seconds": round(
                    (
                        datetime.fromisoformat(published_at)
                        - datetime.fromisoformat(received_at)
                    ).total_seconds(),
                    3,
                ),
            }

            stage = "completion_storage"
            put(
                s3, bucket, f"{prefix}/complete.json",
                encode(completion),
            )

            result = {
                "event": "finding_routed",
                "source": finding["source"],
                "finding_id": finding["finding_id"],
                "sample_status": finding["sample_status"],
                "finding_key": f"{prefix}/finding.json",
                "sns_message_id": notification["MessageId"],
                "receipt_to_publish_seconds":
                    completion["receipt_to_publish_seconds"],
            }

            print(json.dumps(result))
            results.append(result)

        return {"status": "complete", "results": results}

    except Exception as error:
        print(json.dumps({
            "event": "finding_router_failed",
            "stage": stage,
            "request_id": context.aws_request_id,
            "error_type": type(error).__name__,
        }))
        raise RuntimeError("Finding router failed.") from None