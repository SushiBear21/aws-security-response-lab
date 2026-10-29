import json
import time
from pathlib import Path

import boto3


ROOT = Path(__file__).resolve().parents[1]
REPORTS = ROOT / "reports"


def main():
    marker = REPORTS / "recovery-success.json"

    if marker.exists():
        raise ValueError(
            "Recovery already recorded. Inspect it; do not invoke again."
        )

    test_id = (REPORTS / "recovery-test-id.txt").read_text().strip()

    session = boto3.Session(
        profile_name="portfolio-sandbox",
        region_name="us-east-1",
    )

    account = session.client("sts").get_caller_identity()["Account"]

    if account != "359769212511":
        raise ValueError("Wrong AWS account.")

    sqs = session.client("sqs")

    queue = sqs.get_queue_url(
        QueueName="p3-finding-processing-failures"
    )["QueueUrl"]

    messages = sqs.receive_message(
        QueueUrl=queue,
        MaxNumberOfMessages=10,
        WaitTimeSeconds=10,
        VisibilityTimeout=120,
    ).get("Messages", [])

    selected = None
    record = None

    for message in messages:
        candidate = json.loads(message["Body"])
        request = candidate.get("requestPayload", {})

        if (
            isinstance(request, dict)
            and request.get("id") == test_id
            and request.get("test_case") == "session8-recovery"
            and request.get("diagnostic_replay") is True
            and request.get("detail") is None
        ):
            selected = message
            record = candidate
            break

    if selected is None:
        print("Matching failure not received. No recovery invoked.")
        return

    (REPORTS / "recovery-failure-record.json").write_text(
        json.dumps(record, indent=2),
        encoding="utf-8",
    )

    print("Selected failure test ID:", test_id)

    answer = input(
        "Type RECOVER TEST to repair this synthetic fixture:\n> "
    )

    if answer != "RECOVER TEST":
        print("No recovery invoked. Message will become visible again.")
        return

    event = dict(record["requestPayload"])

    event["detail"] = {
        "accountId": "359769212511",
        "region": "us-east-1",
        "id": "synthetic-recovery-" + test_id,
        "title": "SYNTHETIC recovery exercise",
        "type": "Synthetic:Lab/Recovery",
        "severity": 1,
        "service": {"additionalInfo": {"sample": True}},
        "resource": {},
    }

    started = time.perf_counter()

    response = session.client("lambda").invoke(
        FunctionName="p3-finding-router",
        InvocationType="RequestResponse",
        Payload=json.dumps(event).encode(),
    )

    result = json.loads(response["Payload"].read())

    if response.get("FunctionError") or result.get("status") != "complete":
        (REPORTS / "recovery-attempt-error.json").write_text(
            json.dumps(result, indent=2),
            encoding="utf-8",
        )

        raise RuntimeError(
            "Recovery unsuccessful. Inspect side effects before retrying."
        )

    saved = {
        "test_id": test_id,
        "recovery_call_seconds": round(
            time.perf_counter() - started, 3
        ),
        "result": result,
        "queue_message_id": selected["MessageId"],
    }

    marker.write_text(
        json.dumps(saved, indent=2),
        encoding="utf-8",
    )

    sqs.delete_message(
        QueueUrl=queue,
        ReceiptHandle=selected["ReceiptHandle"],
    )

    print("PASS: Corrected fixture processed; queue message deleted.")
    print(json.dumps(saved, indent=2))


if __name__ == "__main__":
    main()