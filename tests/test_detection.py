import copy
import unittest

from app.detection import normalize_event


ACCOUNT = "359769212511"
REGION = "us-east-1"
GROUP = "sg-0c0d98ed7d3c83e75"


def fixture():
    return {
        "account": ACCOUNT,
        "region": REGION,
        "source": "aws.ec2",
        "detail-type": "AWS API Call via CloudTrail",
        "id": "8cb01b43-e240-4aa1-a08d-dfa16730b91b",
        "detail": {
            "eventSource": "ec2.amazonaws.com",
            "eventName": "AuthorizeSecurityGroupIngress",
            "eventID": "fcfbd7f5-b560-463d-b74b-462448df757d",
            "eventTime": "2026-10-29T12:00:00Z",
            "requestParameters": {"groupId": GROUP},
            "userIdentity": {"arn": "synthetic-test-actor"},
        },
    }


class DetectionTests(unittest.TestCase):
    def normalize(self, event):
        return normalize_event(event, ACCOUNT, REGION, GROUP)

    def test_target_event_is_accepted(self):
        result = self.normalize(fixture())
        self.assertEqual(result["severity"], "INFO")
        self.assertEqual(result["resource_id"], GROUP)

    def test_wrong_account_is_ignored(self):
        event = fixture()
        event["account"] = "000000000000"
        self.assertIsNone(self.normalize(event))

    def test_wrong_region_is_ignored(self):
        event = fixture()
        event["region"] = "us-west-2"
        self.assertIsNone(self.normalize(event))

    def test_wrong_group_is_ignored(self):
        event = fixture()
        event["detail"]["requestParameters"]["groupId"] = "sg-other"
        self.assertIsNone(self.normalize(event))

    def test_failed_operation_is_ignored(self):
        event = fixture()
        event["detail"]["errorCode"] = "UnauthorizedOperation"
        self.assertIsNone(self.normalize(event))

    def test_unrelated_operation_is_ignored(self):
        event = fixture()
        event["detail"]["eventName"] = "DeleteTags"
        self.assertIsNone(self.normalize(event))

    def test_invalid_timestamp_is_rejected(self):
        event = fixture()
        event["detail"]["eventTime"] = "invalid"
        with self.assertRaises(ValueError):
            self.normalize(event)

    def test_repeated_event_keeps_incident_identity(self):
        event = fixture()
        repeated = copy.deepcopy(event)
        repeated["id"] = "different-delivery"
        self.assertEqual(
            self.normalize(event)["incident_id"],
            self.normalize(repeated)["incident_id"],
        )


if __name__ == "__main__":
    unittest.main()