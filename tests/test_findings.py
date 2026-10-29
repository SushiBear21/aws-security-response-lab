import unittest

from app.findings import normalize_findings, GUARDDUTY_PRODUCT


def guardduty_event():
    return {
        "account": "359769212511",
        "region": "us-east-1",
        "source": "aws.guardduty",
        "detail-type": "GuardDuty Finding",
        "detail": {
            "accountId": "359769212511",
            "region": "us-east-1",
            "id": "synthetic-finding-001",
            "title": "Synthetic test",
            "severity": 8,
            "service": {
                "additionalInfo": {"sample": True}
            },
        },
    }


def securityhub_event():
    return {
        "account": "359769212511",
        "region": "us-east-1",
        "source": "aws.securityhub",
        "detail-type": "Security Hub Findings - Imported",
        "detail": {
            "findings": [{
                "AwsAccountId": "359769212511",
                "ProductArn": GUARDDUTY_PRODUCT,
                "Id": "synthetic-import-001",
                "Title": "Synthetic imported test",
                "Severity": {"Label": "HIGH", "Normalized": 80},
            }],
        },
    }


class FindingTests(unittest.TestCase):
    def test_guardduty_sample_is_identified(self):
        result = normalize_findings(guardduty_event())[0]
        self.assertEqual(result["sample_status"], "confirmed_sample")
        self.assertEqual(result["response_state"], "no_response_requested")

    def test_wrong_account_is_ignored(self):
        event = guardduty_event()
        event["account"] = "000000000000"
        self.assertEqual(normalize_findings(event), [])

    def test_wrong_region_is_ignored(self):
        event = guardduty_event()
        event["region"] = "us-west-2"
        self.assertEqual(normalize_findings(event), [])

    def test_securityhub_guardduty_import_is_accepted(self):
        result = normalize_findings(securityhub_event())[0]
        self.assertEqual(result["source"], "securityhub_cspm")
        self.assertEqual(result["sample_status"], "not_confirmed")

    def test_other_securityhub_product_is_ignored(self):
        event = securityhub_event()
        event["detail"]["findings"][0]["ProductArn"] = "other-product"
        self.assertEqual(normalize_findings(event), [])

    def test_missing_finding_id_is_rejected(self):
        event = guardduty_event()
        del event["detail"]["id"]
        with self.assertRaises(ValueError):
            normalize_findings(event)

    def test_securityhub_v2_is_not_misinterpreted(self):
        event = securityhub_event()
        event["detail-type"] = "Findings Imported V2"
        self.assertEqual(normalize_findings(event), [])


if __name__ == "__main__":
    unittest.main()