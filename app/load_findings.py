import json
import statistics
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

import boto3
from botocore.config import Config


ROOT = Path(__file__).resolve().parents[1]


def now():
    return datetime.now(timezone.utc).isoformat()


def main():
    session = boto3.Session(
        profile_name="portfolio-sandbox",
        region_name="us-east-1",
    )

    account = session.client("sts").get_caller_identity()["Account"]

    if account != "359769212511":
        raise ValueError("Wrong AWS account.")

    run_id = uuid.uuid4().hex
    cases = []

    # Create clients sequentially before starting worker threads.
    # Each submitted case gets its own client.
    for index in range(12):
        routed = index < 4

        event = {
            "id": str(uuid.uuid4()),
            "account": "359769212511",
            "region": "us-east-1",
            "source": (
                "aws.guardduty" if routed else "lab.out-of-scope"
            ),
            "detail-type": "GuardDuty Finding",
            "diagnostic_replay": True,
            "test_case": "session8-load",
            "detail": {
                "accountId": "359769212511",
                "region": "us-east-1",
                "id": f"synthetic-load-{run_id}-{index}",
                "title": f"SYNTHETIC load test {index}",
                "type": "Synthetic:Lab/Load",
                "severity": 1,
                "resource": {},
                "service": {
                    "additionalInfo": {"sample": True}
                },
            },
        }

        client = session.client(
            "lambda",
            config=Config(
                retries={"total_max_attempts": 1},
                connect_timeout=5,
                read_timeout=60,
            ),
        )

        cases.append({
            "index": index,
            "event": event,
            "expected": "complete" if routed else "ignored",
            "client": client,
        })

    def invoke(case):
        started = time.perf_counter()

        try:
            response = case["client"].invoke(
                FunctionName="p3-finding-router",
                InvocationType="RequestResponse",
                Payload=json.dumps(case["event"]).encode(),
            )

            result = json.loads(response["Payload"].read())

            status = (
                "function_error"
                if response.get("FunctionError")
                else result.get("status", "unexpected")
            )

            return {
                "case": case["index"],
                "event_id": case["event"]["id"],
                "expected": case["expected"],
                "actual": status,
                "passed": status == case["expected"],
                "client_latency_seconds": round(
                    time.perf_counter() - started, 3
                ),
                "result": result,
            }

        except Exception as error:
            return {
                "case": case["index"],
                "event_id": case["event"]["id"],
                "expected": case["expected"],
                "actual": "client_error",
                "passed": False,
                "client_latency_seconds": round(
                    time.perf_counter() - started, 3
                ),
                "error_type": type(error).__name__,
                "outcome_requires_reconciliation": True,
            }

    print("Submitting 12 requests with concurrency limited to 3.")
    print("Four synthetic finding notifications are expected.")

    started_at = now()
    wall_start = time.perf_counter()

    with ThreadPoolExecutor(max_workers=3) as pool:
        results = list(pool.map(invoke, cases))

    wall_seconds = time.perf_counter() - wall_start

    timing = {}

    for path in ("complete", "ignored"):
        values = [
            result["client_latency_seconds"]
            for result in results
            if result["expected"] == path and result["passed"]
        ]

        timing[path] = {
            "successful_sample_count": len(values),
            "median_seconds": (
                round(statistics.median(values), 3)
                if values else None
            ),
            "max_seconds": max(values) if values else None,
        }

    outcomes = {}

    for result in results:
        status = result["actual"]
        outcomes[status] = outcomes.get(status, 0) + 1

    report = {
        "run_id": run_id,
        "started_at": started_at,
        "finished_at": now(),
        "submitted": len(cases),
        "concurrency_limit": 3,
        "passed": sum(result["passed"] for result in results),
        "outcomes": outcomes,
        "wall_seconds": round(wall_seconds, 3),
        "observed_requests_per_second": round(
            len(cases) / wall_seconds, 3
        ),
        "latency_by_expected_path": timing,
        "results": results,
        "scope": (
            "Direct synchronous Lambda invocation. "
            "Excludes client setup, GuardDuty detection, "
            "EventBridge delivery, and email arrival latency. "
            "No quarantine invoked. SDK automatic retries disabled."
        ),
    }

    destination = ROOT / "reports" / f"load-{run_id}.json"
    destination.parent.mkdir(exist_ok=True)

    destination.write_text(
        json.dumps(report, indent=2),
        encoding="utf-8",
    )

    print("Run ID:", run_id)
    print("Passed:", report["passed"], "/", report["submitted"])
    print("Outcomes:", json.dumps(outcomes))
    print("Wall seconds:", report["wall_seconds"])
    print("Requests per second:", report["observed_requests_per_second"])
    print(json.dumps(timing, indent=2))
    print("Saved to:", destination)

    if report["passed"] != report["submitted"]:
        raise RuntimeError(
            "Some requests failed. Inspect the report before another run."
        )


if __name__ == "__main__":
    main()