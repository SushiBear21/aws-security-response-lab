resource "aws_guardduty_detector" "lab" {
  enable = true
}

resource "aws_securityhub_account" "lab" {
  enable_default_standards = false
}

resource "aws_securityhub_product_subscription" "guardduty" {
  product_arn = "arn:aws:securityhub:us-east-1::product/aws/guardduty"

  depends_on = [aws_securityhub_account.lab]
}

output "guardduty_detector_id" {
  value = aws_guardduty_detector.lab.id
}