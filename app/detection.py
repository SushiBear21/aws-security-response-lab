from datetime import datetime
from uuid import UUID


def parse_time(value):
    if not isinstance(value, str):
        raise ValueError("Missing event timestamp.")

    result = datetime.fromisoformat(value.replace("Z", "+00:00"))

    if result.tzinfo is None:
        raise ValueError("Event timestamp must include timezone.")

    return result


def normalize_event(event, account_id, region, group_id):
    if not isinstance(event, dict):
        raise ValueError("Event must be an object.")

    if (
        event.get("account") != account_id
        or event.get("region") != region
        or event.get("source") != "aws.ec2"
        or event.get("detail-type") != "AWS API Call via CloudTrail"
    ):
        return None

    detail = event.get("detail")

    if not isinstance(detail, dict):
        raise ValueError("Missing event detail.")

    if (
        detail.get("eventSource") != "ec2.amazonaws.com"
        or detail.get("eventName") != "AuthorizeSecurityGroupIngress"
        or detail.get("errorCode")
    ):
        return None

    parameters = detail.get("requestParameters")

    if not isinstance(parameters, dict):
        raise ValueError("Missing request parameters.")

    if parameters.get("groupId") != group_id:
        return None

    incident_id = str(UUID(detail["eventID"]))
    event_time = parse_time(detail.get("eventTime"))
    identity = detail.get("userIdentity") or {}

    if not isinstance(identity, dict):
        raise ValueError("Invalid user identity.")

    return {
        "schema_version": "1",
        "incident_id": incident_id,
        "source": "cloudtrail",
        "source_event_id": incident_id,
        "source_event_time": event_time.isoformat(),
        "eventbridge_event_id": event.get("id"),
        "account_id": account_id,
        "region": region,
        "resource_id": group_id,
        "event_name": detail["eventName"],
        "actor_reference": identity.get("arn"),
        "classification": "authorization_event_observed",
        "severity": "INFO",
        "status": "needs_investigation",
    }