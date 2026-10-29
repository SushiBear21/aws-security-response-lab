resource "aws_guardduty_detector_feature" "optional" {
  for_each = toset([
    "S3_DATA_EVENTS",
    "EKS_AUDIT_LOGS",
    "EBS_MALWARE_PROTECTION",
    "RDS_LOGIN_EVENTS",
    "LAMBDA_NETWORK_LOGS"
  ])

  detector_id = aws_guardduty_detector.lab.id
  name        = each.value
  status      = "DISABLED"
}