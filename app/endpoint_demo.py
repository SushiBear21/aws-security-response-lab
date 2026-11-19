"""Rehearse the endpoint workflow on disposable, synthetic state."""
import argparse
import json
from pathlib import Path
from tempfile import TemporaryDirectory

from app.endpoint_workbench import Workbench, read_policy
from app.sysmon import load_sysmon


FIXTURES = Path(__file__).resolve().parents[1] / "tests" / "fixtures"


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def deny_execution(lab, run_id):
    try:
        lab.execute(run_id)
    except ValueError as error:
        require(str(error) == "Approval invalid, expired, or resource changed.", str(error))
        return str(error)
    raise RuntimeError("Execution unexpectedly accepted an unapproved action")


def rehearse(path):
    lab = Workbench(path)
    events = load_sysmon(FIXTURES / "sysmon-endpoint.xml")
    policy = read_policy(FIXTURES / "sysmon-policy.json")
    initial = lab.ingest(events, policy)
    require(initial["inserted"] == 7, "Fixture should produce seven normalized events")
    require(len(initial["new_cases"]) == 1, "Expected one case")
    require(len(initial["suppressed_network_events"]) == 1, "Expected one exact suppression")
    case_id = initial["new_cases"][0]

    duplicate = lab.ingest(events, policy)
    require(duplicate["duplicate_events"] == 7 and duplicate["inserted"] == 0
            and not duplicate["new_cases"], "Duplicate delivery changed event or case count")

    isolation = lab.propose(case_id, "isolate")
    denied_isolation = deny_execution(lab, isolation["run_id"])
    require(lab.report()["cases"][0]["simulated_state"] == "connected", "Denial changed simulated state")
    lab.approve(isolation["run_id"], isolation["payload_sha256"])
    isolated = lab.execute(isolation["run_id"])
    replay = lab.execute(isolation["run_id"])
    require(isolated["state"] == "isolated", "Approved isolation failed")
    require(replay == {"status": "already_executed", "desired_state_present": True}, "Replay changed state")

    rollback = lab.propose(case_id, "rollback")
    denied_rollback = deny_execution(lab, rollback["run_id"])
    require(lab.report()["cases"][0]["simulated_state"] == "isolated", "Denial changed simulated state")
    lab.approve(rollback["run_id"], rollback["payload_sha256"])
    restored = lab.execute(rollback["run_id"])
    report = lab.report()
    case = report["cases"][0]
    require(restored["state"] == "connected" and case["simulated_state"] == "connected"
            and case["isolation_owner"] is None, "Rollback failed to restore baseline")
    require(len(case["timeline"]) == 3 and len(report["cases"]) == 1, "Case evidence changed unexpectedly")

    return {
        "fixture_scope": "synthetic_sysmon_xml",
        "approval_source": "automated_demo",
        "initial": initial,
        "duplicate_delivery": duplicate,
        "unapproved_isolation_denied": denied_isolation,
        "isolation": isolated,
        "isolation_replay": replay,
        "unapproved_rollback_denied": denied_rollback,
        "rollback": restored,
        "report": report,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, help="Write the evidence report to this file")
    args = parser.parse_args()
    with TemporaryDirectory(prefix="endpoint-lab-") as tmp:
        evidence = rehearse(Path(tmp) / "demo.sqlite")
    body = json.dumps(evidence, indent=2) + "\n"
    if args.output:
        args.output.write_text(body, encoding="utf-8")
        print(f"Endpoint workbench demo passed. Evidence at {args.output}")
    else:
        print(body, end="")


if __name__ == "__main__":
    main()
