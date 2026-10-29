ACCOUNT = "359769212511"
REGION = "us-east-1"
GUARDDUTY_PRODUCT = (
    "arn:aws:securityhub:us-east-1::product/aws/guardduty"
)


def normalize_findings(event):
    if not isinstance(event, dict):
        raise ValueError("Event must be an object.")

    if (
        event.get("account") != ACCOUNT
        or event.get("region") != REGION
    ):
        return []

    source = event.get("source")
    event_type = event.get("detail-type")
    detail = event.get("detail")

    if not isinstance(detail, dict):
        raise ValueError("Missing event detail.")

    if source == "aws.guardduty" and event_type == "GuardDuty Finding":
        if (
            detail.get("accountId") != ACCOUNT
            or detail.get("region") != REGION
        ):
            return []

        finding_id = detail.get("id")

        if not isinstance(finding_id, str) or not finding_id:
            raise ValueError("Missing GuardDuty finding ID.")

        extra = (
            detail.get("service", {}).get("additionalInfo", {})
        )
        sample = extra.get("sample") if isinstance(extra, dict) else None

        return [{
            "schema_version": "1",
            "source": "guardduty",
            "finding_id": finding_id,
            "finding_arn": detail.get("arn"),
            "title": detail.get("title"),
            "finding_type": detail.get("type"),
            "severity_original": detail.get("severity"),
            "source_created_at": detail.get("createdAt"),
            "source_updated_at": detail.get("updatedAt"),
            "sample_status": (
                "confirmed_sample"
                if sample is True or sample == "true"
                else "not_confirmed"
            ),
            "resources": detail.get("resource", {}),
            "response_state": "no_response_requested",
        }]

    if (
        source == "aws.securityhub"
        and event_type == "Security Hub Findings - Imported"
    ):
        findings = detail.get("findings")

        if not isinstance(findings, list):
            raise ValueError("Missing Security Hub findings list.")

        results = []

        for finding in findings:
            if not isinstance(finding, dict):
                raise ValueError("Invalid Security Hub finding.")

            if (
                finding.get("AwsAccountId") != ACCOUNT
                or finding.get("ProductArn") != GUARDDUTY_PRODUCT
            ):
                continue

            finding_id = finding.get("Id")

            if not isinstance(finding_id, str) or not finding_id:
                raise ValueError("Missing Security Hub finding ID.")

            results.append({
                "schema_version": "1",
                "source": "securityhub_cspm",
                "finding_id": finding_id,
                "product_arn": finding["ProductArn"],
                "title": finding.get("Title"),
                "finding_types": finding.get("Types", []),
                "severity_original": finding.get("Severity", {}),
                "source_created_at": finding.get("CreatedAt"),
                "source_updated_at": finding.get("UpdatedAt"),
                "sample_status": "not_confirmed",
                "resources": finding.get("Resources", []),
                "response_state": "no_response_requested",
            })

        return results

    return []