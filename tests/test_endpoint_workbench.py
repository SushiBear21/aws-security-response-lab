from datetime import datetime, timedelta
import json
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
import unittest
from xml.etree import ElementTree

from app.endpoint_demo import FIXTURES, rehearse
from app.endpoint_siem import IMAGE
from app.endpoint_workbench import TTL_SECONDS, Workbench, read_policy
from app.response import canonical, digest
from app.sysmon import load_sysmon


class EndpointWorkbenchTests(unittest.TestCase):
    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.db = self.root / "lab.sqlite"
        self.now = 1000
        self.lab = Workbench(self.db, clock=lambda: self.now)
        self.samples = load_sysmon(FIXTURES / "sysmon-endpoint.xml")
        self.policy = read_policy(FIXTURES / "sysmon-policy.json")
        self.process = next(event for event in self.samples if event["record"] == 101)
        self.network = next(event for event in self.samples if event["record"] == 102)

    def change_event(self, event, **fields):
        updated = {**event, **fields}
        updated["id"] = digest({key: updated[key] for key in ("host", "channel", "record", "time")})
        return updated

    def case(self):
        return self.lab.ingest(self.samples, self.policy)["new_cases"][0]

    def approve(self, proposal):
        return self.lab.approve(proposal["run_id"], proposal["payload_sha256"])

    def test_parser_and_timeline_evidence(self):
        self.assertEqual(7, len(self.samples))
        self.assertEqual("ws-alert.lab", self.network["host"])
        self.assertEqual(IMAGE, self.process["image"])
        self.assertEqual(self.process["process_guid"], self.network["process_guid"])
        self.assertEqual("2026-11-19T10:00:30.123456+00:00", self.network["time"])
        self.assertEqual(("tcp", "192.0.2.44", 443, True), (
            self.network["protocol"], self.network["destination"], self.network["port"], self.network["initiated"],
        ))
        case_id = self.case()
        report = self.lab.report()
        self.assertEqual(7, sum(item["events"] for item in report["siem_event_counts"]))
        case, = report["cases"]
        self.assertEqual(case_id, case["case_id"])
        self.assertEqual(self.policy["assets"]["ws-alert.lab"], case["asset"])
        self.assertEqual([101, 102, 103], [item["record"] for item in case["timeline"]])
        for key in ("timeline", "trigger", "finding"):
            self.assertEqual(digest(case[key]), case[key + "_sha256"])
        self.assertEqual(digest(self.policy), case["policy_sha256"])

    def test_parser_single_event_ignores_other_ids_and_rejects_dtd(self):
        xml = self.root / "events.xml"
        entry = ElementTree.parse(FIXTURES / "sysmon-endpoint.xml").getroot()[0]
        ElementTree.ElementTree(entry).write(xml, encoding="utf-8")
        self.assertEqual([self.network], load_sysmon(xml))
        entry.find(".//{*}EventID").text = "5"
        ElementTree.ElementTree(entry).write(xml, encoding="utf-8")
        self.assertEqual([], load_sysmon(xml))
        xml.write_text('<!DOCTYPE Events [<!ENTITY x "x">]><Events/>', encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "DTD"):
            load_sysmon(xml)

    def test_negative_and_inclusive_window(self):
        t = datetime.fromisoformat(self.process["time"])
        within = (t + timedelta(seconds=120)).isoformat()
        beyond = (t + timedelta(seconds=120, microseconds=1)).isoformat()
        before = (t - timedelta(microseconds=1)).isoformat()
        rows = [
            self.change_event(self.network, record=110, time=beyond),
            self.change_event(self.network, record=111, image=r"c:\lab\other.exe"),
            self.change_event(self.network, record=112, initiated=False),
            self.change_event(self.network, record=113, time=before),
            self.change_event(self.network, record=114, host="different.lab"),
            self.change_event(self.network, record=115, process_guid="00000000-0000-0000-0000-000000000009"),
        ]
        self.assertEqual([], self.lab.ingest([self.process, *rows], self.policy)["new_cases"])
        edge = self.change_event(self.network, record=116, time=within)
        self.assertEqual(1, len(self.lab.ingest([edge], self.policy)["new_cases"]))

    def test_late_process_and_duplicate_deliveries_create_one_case(self):
        self.assertEqual([], self.lab.ingest([self.network], self.policy)["new_cases"])
        self.assertEqual(1, len(self.lab.ingest([self.process, self.process], self.policy)["new_cases"]))
        result = Workbench(self.db).ingest(self.samples, self.policy)
        self.assertEqual(5, result["inserted"])
        self.assertEqual(2, result["duplicate_events"])
        self.assertEqual([], result["new_cases"])
        self.assertEqual(1, len(self.lab.report()["cases"]))

    def test_exact_suppression_does_not_mask_other_destination_port_or_host(self):
        process = next(event for event in self.samples if event["record"] == 201)
        connection = next(event for event in self.samples if event["record"] == 202)
        initial = self.lab.ingest([process, connection], self.policy)
        self.assertEqual([], initial["new_cases"])
        self.assertIn(connection["id"], initial["suppressed_network_events"])
        for index, changes in enumerate([
            {"port": 8443}, {"destination": "192.0.2.11"}, {"host": "unregistered.lab"},
        ], 1):
            with self.subTest(changes=changes):
                host = changes.get("host", process["host"])
                guid = f"00000000-0000-0000-0000-{index + 100:012d}"
                start = self.change_event(process, record=220 + index, host=host, process_guid=guid)
                flow = self.change_event(connection, record=230 + index, process_guid=guid, **changes)
                result = self.lab.ingest([start, flow], self.policy)
                case_id, = result["new_cases"]
                self.assertNotIn(flow["id"], result["suppressed_network_events"])
                if host == "unregistered.lab":
                    with self.assertRaisesRegex(ValueError, "outside"):
                        self.lab.propose(case_id, "isolate")

    def test_conflicting_duplicate_and_policy_change_reject_batch(self):
        self.lab.ingest([self.process], self.policy)
        with self.assertRaisesRegex(ValueError, "Conflicting delivery"):
            self.lab.ingest([self.network, {**self.process, "image": "different"}], self.policy)
        self.assertEqual(1, sum(item["events"] for item in self.lab.report()["siem_event_counts"]))
        with self.assertRaisesRegex(ValueError, "changed inventory or tuning"):
            self.lab.ingest([self.network], {**self.policy, "suppressions": []})
        self.assertEqual([], self.lab.report()["cases"])

    def test_pending_and_expired_approval_and_wrong_digest_are_blocked(self):
        proposal = self.lab.propose(self.case(), "isolate")
        run_id = proposal["run_id"]
        with self.assertRaisesRegex(ValueError, "invalid"):
            self.lab.execute(run_id)
        with self.assertRaisesRegex(ValueError, "exact payload digest"):
            self.lab.approve(run_id, "wrong")
        self.approve(proposal)
        self.now += TTL_SECONDS
        with self.assertRaisesRegex(ValueError, "expired"):
            self.lab.execute(run_id)
        report = self.lab.report()
        self.assertEqual("connected", report["cases"][0]["simulated_state"])
        self.assertEqual(2, sum(row["event"] == "execution_denied" for row in report["decisions"]))

    def test_approved_payload_tampering_denied(self):
        proposal = self.lab.propose(self.case(), "isolate")
        approved = self.approve(proposal)
        payload = json.loads(approved["payload_json"])
        payload["host"] = "unregistered.lab"
        approved["payload_json"] = canonical(payload)
        with sqlite3.connect(self.db) as db:
            db.execute("UPDATE proposals SET body=?", (canonical(approved),))
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            self.lab.execute(proposal["run_id"])
        self.assertEqual("connected", self.lab.report()["cases"][0]["simulated_state"])

    def test_stale_approval_blocked_after_state_is_restored(self):
        case_id = self.case()
        stale = self.approve(self.lab.propose(case_id, "isolate"))
        current = self.approve(self.lab.propose(case_id, "isolate"))
        self.lab.execute(current["run_id"])
        rollback = self.approve(self.lab.propose(case_id, "rollback"))
        self.lab.execute(rollback["run_id"])
        with self.assertRaisesRegex(ValueError, "resource changed"):
            self.lab.execute(stale["run_id"])

    def test_demo_requires_separate_approval_for_rollback_and_records_replay(self):
        evidence = rehearse(self.root / "demo.sqlite")
        self.assertEqual(7, evidence["duplicate_delivery"]["duplicate_events"])
        self.assertTrue(evidence["isolation_replay"]["desired_state_present"])
        self.assertEqual("connected", evidence["rollback"]["state"])
        decisions = evidence["report"]["decisions"]
        self.assertEqual(["proposed", "execution_denied", "approved", "executed"] * 2,
                         [decision["event"] for decision in decisions])
        self.assertEqual(2, len({decision["payload_sha256"] for decision in decisions}))


if __name__ == "__main__":
    unittest.main()
