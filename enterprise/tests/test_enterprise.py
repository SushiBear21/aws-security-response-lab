import sys
import unittest
from copy import deepcopy
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from lab import (GateDenied, apply, approve, check_architecture, demo, digest,
                 initial_state, load, make_plan)
from recovery import RecoveryError, checksum, recover, demo as dr_demo
from scan_iac import scan


class ArchitectureTests(unittest.TestCase):
    def setUp(self):
        self.model = load(ROOT / "architecture.json")

    def test_synthetic_account_architecture_passes(self):
        self.assertEqual([], check_architecture(self.model))

    def test_denied_architecture_fails(self):
        bad = load(ROOT / "fixtures" / "architecture-denied.json")
        self.assertGreaterEqual(len(check_architecture(bad)), 4)

    def test_identity_and_log_integrity_fail_closed(self):
        modified = deepcopy(self.model)
        modified["accounts"]["workload"] = modified["accounts"]["management"]
        modified["logging"]["log_file_validation"] = False
        self.assertGreaterEqual(len(check_architecture(modified)), 2)

    def test_iac_guardrails(self):
        self.assertEqual([], scan())


class GitOpsTests(unittest.TestCase):
    def setUp(self):
        self.desired = load(ROOT / "terraform" / "baseline.tfvars.json")
        self.state = initial_state()
        self.plan = make_plan(self.desired, self.state, "rev-a", "alice", "PR-10")

    def test_signed_digest_and_approval_gate(self):
        with self.assertRaises(GateDenied):
            apply(self.plan, None, self.state, digest(self.plan), "rev-a")
        with self.assertRaises(GateDenied):
            approve(self.plan, "alice")
        self.assertEqual(1, apply(self.plan, approve(self.plan, "bob"),
                                  self.state, digest(self.plan), "rev-a")["generation"])

    def test_tampering_denied(self):
        modified = deepcopy(self.plan)
        modified["desired"]["security_baseline"]["version"] = "tampered"
        with self.assertRaises(GateDenied):
            apply(modified, approve(self.plan, "bob"), self.state, digest(self.plan), "rev-a")

    def test_wrong_revision_denied(self):
        with self.assertRaises(GateDenied):
            apply(self.plan, approve(self.plan, "bob"), self.state, digest(self.plan), "rev-b")

    def test_rejected_approval_denied(self):
        with self.assertRaises(GateDenied):
            apply(self.plan, approve(self.plan, "bob", "REJECTED"), self.state, digest(self.plan), "rev-a")

    def test_plan_replay_denied(self):
        updated = apply(self.plan, approve(self.plan, "bob"),
                        self.state, digest(self.plan), "rev-a")
        with self.assertRaises(GateDenied):
            apply(self.plan, approve(self.plan, "bob"), updated, digest(self.plan), "rev-a")

    def test_end_to_end_rollback_with_fresh_review(self):
        result = demo()
        for key in ("denied_unapproved_apply", "denied_noncompliant_policy", "denied_replay",
                    "post_apply_verified", "rollback_verified"):
            self.assertTrue(result[key], key)
        self.assertEqual(0, result["cloud_api_calls"])


class DisasterRecoveryTests(unittest.TestCase):
    def test_restore_objectives_and_data_loss_are_reported(self):
        result = dr_demo()
        self.assertTrue(result["integrity_verified"])
        self.assertTrue(result["rto_target_met"])
        self.assertTrue(result["rpo_target_met"])
        self.assertEqual(1, result["lost_event_count"])
        self.assertEqual(1, result["observed_rpo_seconds"])

    def test_corrupt_event_sequence_is_rejected(self):
        journal = [{"sequence": 1, "logical_second": 0},
                   {"sequence": 5, "logical_second": 1}]
        with self.assertRaises(RecoveryError):
            recover(journal)


if __name__ == "__main__":
    unittest.main()
