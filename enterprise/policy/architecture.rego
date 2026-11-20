package main

deny contains msg if {
  input.mode != "synthetic_blueprint"
  msg := "Only synthetic architecture manifests are allowed in CI"
}

deny contains msg if {
  not input.logging.organization_trail
  msg := "Organization-wide CloudTrail is required"
}

deny contains msg if {
  not input.logging.multi_region
  msg := "Multi-Region CloudTrail is required"
}

deny contains msg if {
  not input.logging.log_file_validation
  msg := "CloudTrail log-file integrity validation is required"
}

deny contains msg if {
  not input.logging.bucket.public_access_blocked
  msg := "Central log bucket must block public access"
}

deny contains msg if {
  not input.logging.bucket.tls_required
  msg := "Central log bucket must require TLS"
}

deny contains msg if {
  not input.logging.bucket.object_lock
  msg := "Log retention must include Object Lock design"
}

deny contains msg if {
  input.logging.bucket.encryption != "aws:kms"
  msg := "Centralized logs must use KMS encryption"
}

deny contains msg if {
  not input.logging.bucket.source_arn_condition
  msg := "CloudTrail destination must restrict SourceArn"
}

deny contains msg if {
  input.guardduty.delegated_admin != "security_tooling"
  msg := "GuardDuty delegated administrator must be the security account"
}

deny contains msg if {
  input.security_hub_cspm.delegated_admin != "security_tooling"
  msg := "Security Hub CSPM administrator must be security tooling"
}

deny contains msg if {
  input.aws_config.organization_aggregator_account != "security_tooling"
  msg := "Config organization aggregator must live in security tooling"
}

deny contains msg if {
  some action in input.iam.cross_account_audit_role.allowed_actions
  endswith(action, ":*")
  msg := sprintf("Wildcard IAM action is forbidden: %s", [action])
}

deny contains msg if {
  not input.response.human_approval_required
  msg := "Automated response must require human approval"
}

deny contains msg if {
  not input.response.approval_exact_plan_digest
  msg := "Approval must be bound to the exact plan digest"
}

deny contains msg if {
  input.safeguards.aws_deployment_enabled
  msg := "Cloud provisioning must not be enabled in this simulation"
}

deny contains msg if {
  input.safeguards.azure_in_scope
  msg := "Azure is parked outside this lab"
}
