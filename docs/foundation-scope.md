# Foundation recording scope

Account: 359769212511
Region: us-east-1
Profile: portfolio-sandbox

The supplied inventory returned no CloudTrail trails, Config configuration recorders, or Config delivery channels. This configuration creates a new customer-managed recorder and delivery channel on that basis. Repeat the inventory before applying; if either Config resource now exists, stop and assess ownership and reuse rather than applying this configuration unchanged.

AWS Config continuously records AWS::EC2::SecurityGroup and AWS::EC2::VPC. Selection is by resource type across the Region, not by lab tag or VPC. Other matching resources in us-east-1, including default security groups and VPCs, can be recorded and incur charges. No Config rules or conformance packs are created.

CloudTrail records regional write-management events across the account in us-east-1, with log validation. Read events, data events, other Regions, and global-service events are outside this trail's scope.

The dedicated VPC has no subnets, gateways, peering, or workloads. The exercise security group has no inbound or outbound rules.

The evidence bucket uses SSE-S3 encryption, versioning, public-access blocking, bucket-owner-enforced ownership, and a policy requiring TLS. CloudTrail and Config use separate prefixes. The bucket cannot be force-deleted while it contains evidence; versioned objects require intentional cleanup. No automatic evidence expiration is configured.

Config uses a dedicated IAM role with the AWS-managed AWS_ConfigRole read policy and bucket-scoped delivery permissions. Recording scope is narrow, but the managed read policy supports broader resource discovery.

## Review and validation

Run terraform fmt, init, validate, and plan from the project instructions. This generated configuration has not been validated with the provider or deployed. The local Terraform executable could not be started because Windows returned Access is denied.

Review the plan before any apply. AWS Config recording and S3 storage/requests can incur charges; this file does not estimate prices or establish a budget. Commit .terraform.lock.hcl after initialization; keep state and saved plans ignored.
