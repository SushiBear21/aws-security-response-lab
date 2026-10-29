resource "aws_sns_topic" "triage" {
  name = "p3-security-triage"
}

resource "aws_iam_role_policy" "notifications" {
  name = "p3-publish-triage-alerts"
  role = aws_iam_role.detector.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "PublishLabAlerts"
      Effect   = "Allow"
      Action   = "sns:Publish"
      Resource = aws_sns_topic.triage.arn
    }]
  })
}

output "triage_topic_arn" {
  value = aws_sns_topic.triage.arn
}