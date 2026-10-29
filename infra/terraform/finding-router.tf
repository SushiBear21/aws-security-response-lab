resource "aws_cloudwatch_log_group" "finding_router" {
  name              = "/aws/lambda/p3-finding-router"
  retention_in_days = 14
}

resource "aws_iam_role" "finding_router" {
  name = "p3-finding-router"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "finding_router" {
  name = "p3-store-and-notify-findings"
  role = aws_iam_role.finding_router.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.evidence.arn}/findings/*"
      },
      {
        Effect   = "Allow"
        Action   = "sns:Publish"
        Resource = aws_sns_topic.triage.arn
      },
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "${aws_cloudwatch_log_group.finding_router.arn}:*"
      }
    ]
  })
}

resource "aws_lambda_function" "finding_router" {
  function_name = "p3-finding-router"
  role          = aws_iam_role.finding_router.arn
  runtime       = "python3.13"
  handler       = "app.finding_router.lambda_handler"

  filename         = "${path.module}/../../.build/finding-router.zip"
  source_code_hash = filebase64sha256("${path.module}/../../.build/finding-router.zip")

  timeout     = 30
  memory_size = 256

  environment {
    variables = {
      EVIDENCE_BUCKET = aws_s3_bucket.evidence.id
      ALERT_TOPIC_ARN = aws_sns_topic.triage.arn
    }
  }

  depends_on = [
    aws_iam_role_policy.finding_router,
    aws_cloudwatch_log_group.finding_router
  ]
}

locals {
  finding_event_patterns = {
    guardduty = jsonencode({
      source        = ["aws.guardduty"]
      "detail-type" = ["GuardDuty Finding"]
      account       = ["359769212511"]
      region        = ["us-east-1"]
    })

    securityhub = jsonencode({
      source        = ["aws.securityhub"]
      "detail-type" = ["Security Hub Findings - Imported"]
      account       = ["359769212511"]
      region        = ["us-east-1"]
      detail = {
        findings = {
          ProductArn = [
            "arn:aws:securityhub:us-east-1::product/aws/guardduty"
          ]
        }
      }
    })
  }
}

resource "aws_cloudwatch_event_rule" "finding_router" {
  for_each = local.finding_event_patterns

  name          = "p3-${each.key}-findings"
  event_pattern = each.value
}

resource "aws_lambda_permission" "finding_router" {
  for_each = local.finding_event_patterns

  statement_id   = "AllowFindingEvents-${each.key}"
  action         = "lambda:InvokeFunction"
  function_name  = aws_lambda_function.finding_router.function_name
  principal      = "events.amazonaws.com"
  source_arn     = aws_cloudwatch_event_rule.finding_router[each.key].arn
  source_account = "359769212511"
}

resource "aws_cloudwatch_event_target" "finding_router" {
  for_each = local.finding_event_patterns

  rule      = aws_cloudwatch_event_rule.finding_router[each.key].name
  target_id = "finding-router"
  arn       = aws_lambda_function.finding_router.arn

  depends_on = [aws_lambda_permission.finding_router]
}