import hashlib
import json
import os
from datetime import datetime, timezone

import boto3

from app.detection import normalize_event, parse_time
from app.investigate import collect_evidence


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def encode(value):
    return json.dumps(
        value,
        sort_keys=True,
        allow_nan=False,
        separators=(",", ":"),
    ).encode("utf-8")


def elapsed(start, end):
    value = (parse_time(end) - parse_time(start)).total_seconds()
    return round(value, 3) if value >= 0 else None


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

        incident.update({
            "received_at": received_at,
            "detected_at": utc_now(),
            "request_id": context.aws_request_id,
            "detector_version": "lessons-4-5",
        })

        incident["event_to_detection_seconds"] = elapsed(
            incident["source_event_time"],
            incident["detected_at"],
        )

        stage = "investigation"

        region = os.environ["EXPECTED_REGION"]

        incident.update(collect_evidence(
            boto3.client("ec2", region_name=region),
            boto3.client("config", region_name=region),
            incident["resource_id"],
            os.environ["EXPECTED_VPC_ID"],
        ))

        incident["event_to_classification_seconds"] = elapsed(
            incident["source_event_time"],
            incident["investigation_completed_at"],
        )

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

        timeline = [
            {
                "time": incident["source_event_time"],
                "event": "source_authorization",
            },
            {"time": received_at, "event": "handler_received"},
            {
                "time": incident["detected_at"],
                "event": "source_event_accepted",
            },
            {
                "time": incident["current_configuration_observed_at"],
                "event": "current_configuration_observed",
            },
            {
                "time": incident["investigation_completed_at"],
                "event": "investigation_completed",
            },
            {
                "time": persisted_at,
                "event": "incident_persisted",
            },
        ]

        config_evidence = incident["config_evidence"]

        if config_evidence["status"] == "available":
            timeline.append({
                "time": config_evidence["capture_time"],
                "event": "aws_config_capture",
            })

        notification = {"status": "not_requested"}
        topic = os.environ.get("ALERT_TOPIC_ARN", "")

        if topic and incident["severity"] == "HIGH":
            stage = "notification"
            publish_started = utc_now()

            alert = {
                "type": "LAB_CONFIGURATION_ALERT",
                "incident_id": incident["incident_id"],
                "classification": incident["classification"],
                "severity": incident["severity"],
                "account_id": incident["account_id"],
                "region": incident["region"],
                "resource_id": incident["resource_id"],
                "source_event_time": incident["source_event_time"],
                "detected_at": incident["detected_at"],
                "attachment_count_observed":
                    incident["attachment_count_observed"],
                "rule_ids": [
                    rule["SecurityGroupRuleId"]
                    for rule in incident["public_ssh_rules"]
                ],
                "evidence_uri":
                    f"s3://{bucket}/{prefix}/incident.json",
                "response_state": "no_response_executed",
                "next_step":
                    "Follow the triage runbook and verify lab cleanup.",
            }

            response = boto3.client(
                "sns", region_name=region
            ).publish(
                TopicArn=topic,
                Subject="P3 LAB: Public SSH configuration observed",
                Message=json.dumps(alert, indent=2),
            )

            published_at = utc_now()

            notification = {
                "status": "published",
                "message_id": response["MessageId"],
                "publish_started_at": publish_started,
                "published_at": published_at,
                "persistence_to_publish_seconds":
                    elapsed(persisted_at, published_at),
                "detection_to_publish_seconds":
                    elapsed(incident["detected_at"], published_at),
            }

            timeline.append({
                "time": published_at,
                "event": "sns_publish_succeeded",
            })

        timeline.sort(key=lambda entry: parse_time(entry["time"]))
        timeline_bytes = encode(timeline)

        stage = "completion_storage"

        put_json(
            client, bucket, f"{prefix}/timeline.json", timeline_bytes
        )

        completion = {
            "incident_id": incident["incident_id"],
            "request_id": context.aws_request_id,
            "persisted_at": persisted_at,
            "completed_at": utc_now(),
            "event_sha256": hashlib.sha256(event_bytes).hexdigest(),
            "incident_sha256": hashlib.sha256(incident_bytes).hexdigest(),
            "timeline_sha256": hashlib.sha256(timeline_bytes).hexdigest(),
            "notification": notification,
        }

        put_json(
            client, bucket, f"{prefix}/complete.json", encode(completion)
        )

        print(json.dumps({
            "event": "incident_processed",
            "incident_id": incident["incident_id"],
            "request_id": context.aws_request_id,
            "severity": incident["severity"],
            "classification": incident["classification"],
            "event_to_classification_seconds":
                incident["event_to_classification_seconds"],
            "notification": notification,
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