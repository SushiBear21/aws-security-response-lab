import json
from datetime import datetime, timezone

from botocore.exceptions import ClientError


def now():
    return datetime.now(timezone.utc).isoformat()


def public_ssh_rules(rules):
    matches = []

    for rule in rules:
        if rule.get("IsEgress"):
            continue

        public = (
            rule.get("CidrIpv4") == "0.0.0.0/0"
            or rule.get("CidrIpv6") == "::/0"
        )

        protocol = str(rule.get("IpProtocol"))
        start = rule.get("FromPort")
        end = rule.get("ToPort")

        includes_ssh = protocol == "-1" or (
            protocol in ("tcp", "6")
            and type(start) is int
            and type(end) is int
            and start <= 22 <= end
        )

        if public and includes_ssh:
            matches.append(rule)

    return matches


def collect_evidence(ec2, config, group_id, expected_vpc):
    started_at = now()

    group = ec2.describe_security_groups(
        GroupIds=[group_id]
    )["SecurityGroups"][0]

    if group["GroupId"] != group_id or group["VpcId"] != expected_vpc:
        raise ValueError("Resource boundary mismatch.")

    rules = []
    paginator = ec2.get_paginator("describe_security_group_rules")

    for page in paginator.paginate(
        Filters=[{"Name": "group-id", "Values": [group_id]}]
    ):
        rules.extend(page["SecurityGroupRules"])

        if len(rules) > 1000:
            raise ValueError("Rule collection limit exceeded.")

    interfaces = ec2.describe_network_interfaces(
        Filters=[{"Name": "group-id", "Values": [group_id]}],
        MaxResults=10,
    )

    risky = public_ssh_rules(rules)

    result = {
        "investigation_started_at": started_at,
        "current_configuration_observed_at": now(),
        "vpc_id": group["VpcId"],
        "group_name": group["GroupName"],
        "security_group_rules": rules,
        "public_ssh_rules": risky,
        "attachment_count_observed":
            len(interfaces["NetworkInterfaces"]),
        "attachment_listing_truncated":
            bool(interfaces.get("NextToken")),
        "classification": (
            "public_ssh_configuration_observed"
            if risky
            else "authorization_event_no_current_public_ssh"
        ),
        "severity": "HIGH" if risky else "INFO",
        "status": "needs_operator_review",
        "interpretation": (
            "Current configuration observed after the source event. "
            "Public rules do not establish compromise or reachability."
        ),
    }

    # Config is supporting evidence with its own capture time.
    # It may lag behind the current EC2 configuration.
    try:
        response = config.get_resource_config_history(
            resourceType="AWS::EC2::SecurityGroup",
            resourceId=group_id,
            chronologicalOrder="Reverse",
            limit=1,
        )

        items = response.get("configurationItems", [])

        if items:
            item = items[0]
            configuration = item.get("configuration")

            if isinstance(configuration, str):
                configuration = json.loads(configuration)

            result["config_evidence"] = {
                "status": "available",
                "capture_time":
                    item["configurationItemCaptureTime"].isoformat(),
                "configuration_item_status":
                    item.get("configurationItemStatus"),
                "configuration": configuration,
            }
        else:
            result["config_evidence"] = {
                "status": "not_yet_available"
            }

    except ClientError as error:
        result["config_evidence"] = {
            "status": "unavailable",
            "error_code": error.response["Error"]["Code"],
        }

    result["investigation_completed_at"] = now()
    return result