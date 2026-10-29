import argparse
import hashlib
import json
import os
import time
import uuid
from datetime import datetime, timezone

import boto3
from botocore.config import Config


ACCOUNT = "359769212511"
REGION = "us-east-1"
TABLE = "p3-response-approvals"


def timestamp():
    return datetime.now(timezone.utc).isoformat()


def canonical(value):
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def clients(local=False):
    session = boto3.Session(
        profile_name="portfolio-sandbox" if local else None,
        region_name=REGION,
    )
    identity = session.client("sts").get_caller_identity()

    if identity["Account"] != ACCOUNT:
        raise ValueError("Wrong AWS account.")

    return (
        session,
        session.resource("dynamodb").Table(TABLE),
        identity["Arn"],
    )


def outputs():
    import subprocess

    result = subprocess.run(
        [
            "terraform",
            "-chdir=infra/terraform",
            "output",
            "-json",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    values = json.loads(result.stdout)
    return {key: value["value"] for key, value in values.items()}


def inspect_interface(ec2, eni_id, vpc_id):
    interface = ec2.describe_network_interfaces(
        NetworkInterfaceIds=[eni_id]
    )["NetworkInterfaces"][0]

    tags = {
        tag["Key"]: tag["Value"]
        for tag in interface.get("TagSet", [])
    }

    if (
        interface["VpcId"] != vpc_id
        or interface["Status"] != "available"
        or interface.get("Attachment")
        or tags.get("ResponseLab") != "true"
    ):
        raise ValueError("Interface is outside the response lab boundary.")

    return sorted(group["GroupId"] for group in interface["Groups"])


def load_proposal(table, run_id):
    item = table.get_item(
        Key={"run_id": run_id},
        ConsistentRead=True,
    ).get("Item")

    if not item:
        raise ValueError("Proposal not found.")

    payload = json.loads(item["payload_json"])

    if digest(payload) != item["payload_sha256"]:
        raise ValueError("Proposal digest mismatch.")

    return item, payload


def lambda_handler(event, context):
    run_id = event.get("run_id") if isinstance(event, dict) else None

    if not isinstance(run_id, str) or len(run_id) != 32:
        raise ValueError("Invalid run ID.")

    session, table, _ = clients()
    item, payload = load_proposal(table, run_id)

    allowed = {
        "account_id": ACCOUNT,
        "region": REGION,
        "interface_id": os.environ["LAB_INTERFACE_ID"],
        "vpc_id": os.environ["LAB_VPC_ID"],
    }

    for key, expected in allowed.items():
        if payload.get(key) != expected:
            raise ValueError("Proposal target mismatch.")

    baseline = os.environ["BASELINE_GROUP_ID"]
    quarantine = os.environ["QUARANTINE_GROUP_ID"]

    expected_pairs = {
        "quarantine": ([baseline], [quarantine]),
        "rollback": ([quarantine], [baseline]),
    }

    action = payload.get("action")

    if action not in expected_pairs:
        raise ValueError("Unsupported action.")

    before, after = expected_pairs[action]

    if (
        payload.get("expected_groups") != before
        or payload.get("desired_groups") != after
    ):
        raise ValueError("Unsupported group change.")

    ec2 = session.client(
        "ec2",
        config=Config(retries={"total_max_attempts": 1}),
    )

    current = inspect_interface(
        ec2, payload["interface_id"], payload["vpc_id"]
    )

    if item["state"] == "EXECUTED":
        return {
            "status": "already_executed",
            "run_id": run_id,
            "current_groups": current,
            "desired_state_still_present": current == after,
        }

    now = int(time.time())

    if (
        item["state"] != "APPROVED"
        or item.get("approved_sha256") != item["payload_sha256"]
        or int(item["expires_at"]) <= now
        or current != before
    ):
        raise ValueError("Approval invalid, expired, or resource changed.")

    # Only one invocation can claim this approval.
    table.update_item(
        Key={"run_id": run_id},
        UpdateExpression=(
            "SET #state = :running, execution_request_id = :request, "
            "execution_started_at = :started"
        ),
        ConditionExpression=(
            "#state = :approved AND payload_sha256 = :hash "
            "AND approved_sha256 = :hash AND expires_at > :now"
        ),
        ExpressionAttributeNames={"#state": "state"},
        ExpressionAttributeValues={
            ":running": "EXECUTING",
            ":approved": "APPROVED",
            ":hash": item["payload_sha256"],
            ":now": now,
            ":request": context.aws_request_id,
            ":started": timestamp(),
        },
    )

    try:
        # Recheck immediately before the AWS change.
        if int(item["expires_at"]) <= int(time.time()):
            raise ValueError("Approval expired before AWS change.")

        if inspect_interface(
            ec2, payload["interface_id"], payload["vpc_id"]
        ) != before:
            raise ValueError("Resource changed before execution.")

        ec2.modify_network_interface_attribute(
            NetworkInterfaceId=payload["interface_id"],
            Groups=after,
        )

        observed = None

        for _ in range(10):
            observed = inspect_interface(
                ec2, payload["interface_id"], payload["vpc_id"]
            )
            if observed == after:
                break
            time.sleep(1)

        if observed != after:
            raise RuntimeError("AWS change could not be verified.")

        completed = timestamp()
        approval_latency = round(
            time.time() - float(item["approved_epoch"]), 3
        )

        table.update_item(
            Key={"run_id": run_id},
            UpdateExpression=(
                "SET #state = :done, completed_at = :completed, "
                "observed_groups_json = :groups, "
                "approval_to_verified_seconds = :latency"
            ),
            ConditionExpression=(
                "#state = :running AND execution_request_id = :request"
            ),
            ExpressionAttributeNames={"#state": "state"},
            ExpressionAttributeValues={
                ":done": "EXECUTED",
                ":running": "EXECUTING",
                ":request": context.aws_request_id,
                ":completed": completed,
                ":groups": canonical(observed),
                ":latency": str(approval_latency),
            },
        )

        result = {
            "status": "executed",
            "action": action,
            "run_id": run_id,
            "observed_groups": observed,
            "approval_to_verified_seconds": approval_latency,
        }
        print(canonical(result))
        return result

    except Exception:
        # No automatic second modification after an uncertain outcome.
        # If this write fails, EXECUTING also blocks automatic replay.
        table.update_item(
            Key={"run_id": run_id},
            UpdateExpression="SET #state = :review",
            ConditionExpression=(
                "#state = :running AND execution_request_id = :request"
            ),
            ExpressionAttributeNames={"#state": "state"},
            ExpressionAttributeValues={
                ":review": "NEEDS_REVIEW",
                ":running": "EXECUTING",
                ":request": context.aws_request_id,
            },
        )
        raise RuntimeError(
            "Response needs manual reconciliation; do not reset its state."
        ) from None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "command",
        choices=["propose", "inspect", "approve", "reject", "execute"],
    )
    parser.add_argument("--run")
    parser.add_argument("--action", choices=["quarantine", "rollback"])
    parser.add_argument("--incident")
    args = parser.parse_args()

    session, table, actor = clients(local=True)

    if args.command == "propose":
        if not args.action or not args.incident:
            raise ValueError("Provide --action and --incident.")

        config = outputs()
        baseline = config["response_baseline_group_id"]
        quarantine = config["response_quarantine_group_id"]

        before, after = (
            ([baseline], [quarantine])
            if args.action == "quarantine"
            else ([quarantine], [baseline])
        )

        interface_id = config["response_interface_id"]
        vpc_id = config["vpc_id"]

        current = inspect_interface(
            session.client("ec2"), interface_id, vpc_id
        )

        if current != before:
            raise ValueError("Current groups do not match expected state.")

        payload = {
            "action": args.action,
            "account_id": ACCOUNT,
            "region": REGION,
            "interface_id": interface_id,
            "vpc_id": vpc_id,
            "expected_groups": before,
            "desired_groups": after,
            "incident_reference": args.incident,
        }

        run_id = uuid.uuid4().hex
        table.put_item(
            Item={
                "run_id": run_id,
                "state": "PENDING",
                "payload_json": canonical(payload),
                "payload_sha256": digest(payload),
                "created_at": timestamp(),
                "created_by": actor,
            },
            ConditionExpression="attribute_not_exists(run_id)",
        )
        print("Run ID:", run_id)
        print("State: PENDING. No AWS resource change made.")
        return

    if not args.run:
        raise ValueError("Provide --run.")

    item, payload = load_proposal(table, args.run)

    if args.command == "inspect":
        print(json.dumps(item, indent=2, default=str))
        return

    if args.command == "approve":
        print(json.dumps(payload, indent=2))
        phrase = "APPROVE " + item["payload_sha256"][:12]
        answer = input(f"To approve this exact payload, type:\n{phrase}\n> ")

        if answer != phrase:
            raise ValueError("Approval not granted.")

        approved_epoch = time.time()

        table.update_item(
            Key={"run_id": args.run},
            UpdateExpression=(
                "SET #state = :approved, approved_sha256 = :hash, "
                "approved_by = :actor, approved_at = :time, "
                "approved_epoch = :epoch, expires_at = :expires"
            ),
            ConditionExpression=(
                "#state = :pending AND payload_sha256 = :hash "
                "AND payload_json = :payload"
            ),
            ExpressionAttributeNames={"#state": "state"},
            ExpressionAttributeValues={
                ":approved": "APPROVED",
                ":pending": "PENDING",
                ":hash": item["payload_sha256"],
                ":payload": item["payload_json"],
                ":actor": actor,
                ":time": timestamp(),
                ":epoch": str(approved_epoch),
                ":expires": int(approved_epoch) + 600,
            },
        )
        print("APPROVED for ten minutes.")
        return

    if args.command == "reject":
        table.update_item(
            Key={"run_id": args.run},
            UpdateExpression=(
                "SET #state = :rejected, rejected_by = :actor, "
                "rejected_at = :time"
            ),
            ConditionExpression="#state = :pending",
            ExpressionAttributeNames={"#state": "state"},
            ExpressionAttributeValues={
                ":rejected": "REJECTED",
                ":pending": "PENDING",
                ":actor": actor,
                ":time": timestamp(),
            },
        )
        print("REJECTED.")
        return

    response = session.client("lambda").invoke(
        FunctionName="p3-security-response",
        InvocationType="RequestResponse",
        Payload=canonical({"run_id": args.run}).encode(),
    )

    print(response["Payload"].read().decode())

    if response.get("FunctionError"):
        raise RuntimeError("Execution denied or failed; inspect the proposal.")


if __name__ == "__main__":
    main()