import json
import unittest

from app.response import digest, load_proposal


class FakeTable:
    def __init__(self, item):
        self.item = item

    def get_item(self, **kwargs):
        if kwargs.get("ConsistentRead") is not True:
            raise AssertionError("Proposal reads must be consistent.")

        return {"Item": self.item} if self.item else {}


class ResponseIntegrityTests(unittest.TestCase):
    def payload(self):
        return {
            "action": "quarantine",
            "interface_id": "eni-synthetic",
            "expected_groups": ["sg-baseline"],
            "desired_groups": ["sg-quarantine"],
        }

    def item(self):
        payload = self.payload()

        return {
            "payload_json": json.dumps(payload),
            "payload_sha256": digest(payload),
        }

    def test_valid_payload_loads(self):
        item = self.item()
        _, payload = load_proposal(FakeTable(item), "synthetic-run")
        self.assertEqual(payload, self.payload())

    def test_changed_target_is_rejected(self):
        item = self.item()
        payload = json.loads(item["payload_json"])
        payload["interface_id"] = "eni-other"
        item["payload_json"] = json.dumps(payload)

        with self.assertRaises(ValueError):
            load_proposal(FakeTable(item), "synthetic-run")

    def test_changed_destination_is_rejected(self):
        item = self.item()
        payload = json.loads(item["payload_json"])
        payload["desired_groups"] = ["sg-other"]
        item["payload_json"] = json.dumps(payload)

        with self.assertRaises(ValueError):
            load_proposal(FakeTable(item), "synthetic-run")

    def test_missing_proposal_is_rejected(self):
        with self.assertRaises(ValueError):
            load_proposal(FakeTable(None), "synthetic-run")


if __name__ == "__main__":
    unittest.main()