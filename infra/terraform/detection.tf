resource "aws_cloudwatch_log_group" "detector" {
  name              = "/aws/lambda/p3-security-detector"
  retention_in_days = 14
}

resource "aws_iam_role" "detector" {
  name = "p3-security-detector"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "detector" {
  name = "p3-detector-evidence-and-logs"
  role = aws_iam_role.detector.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "WriteIncidentEvidence"
        Effect   = "Allow"
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.evidence.arn}/incidents/*"
      },
      {
        Sid    = "WriteDetectorLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "${aws_cloudwatch_log_group.detector.arn}:*"
      }
    ]
  })
}

resource "aws_lambda_function" "detector" {
  function_name = "p3-security-detector"
  role          = aws_iam_role.detector.arn
  runtime       = "python3.13"
  handler       = "app.detector.lambda_handler"

  filename         = "${path.module}/../../.build/detector.zip"
  source_code_hash = filebase64sha256("${path.module}/../../.build/detector.zip")

  timeout     = 60
  memory_size = 256

  environment {
    variables = {
      EXPECTED_ACCOUNT = "359769212511"
      EXPECTED_REGION  = "us-east-1"
      EVIDENCE_BUCKET  = aws_s3_bucket.evidence.id
      TARGET_GROUP_ID  = aws_security_group.target.id
    }
  }

  depends_on = [
    aws_iam_role_policy.detector,
    aws_cloudwatch_log_group.detector
  ]
}

resource "aws_cloudwatch_event_rule" "ingress_change" {
  name = "p3-lab-ingress-change"

  event_pattern = jsonencode({
    source        = ["aws.ec2"]
    "detail-type" = ["AWS API Call via CloudTrail"]
    account       = ["359769212511"]
    region        = ["us-east-1"]
    detail = {
      eventSource = ["ec2.amazonaws.com"]
      eventName   = ["AuthorizeSecurityGroupIngress"]
      errorCode   = [{ exists = false }]
      requestParameters = {
        groupId = [aws_security_group.target.id]
      }
    }
  })
}

resource "aws_lambda_permission" "eventbridge" {
  statement_id   = "AllowLabIngressEvents"
  action         = "lambda:InvokeFunction"
  function_name  = aws_lambda_function.detector.function_name
  principal      = "events.amazonaws.com"
  source_arn     = aws_cloudwatch_event_rule.ingress_change.arn
  source_account = "359769212511"
}

resource "aws_cloudwatch_event_target" "detector" {
  rule      = aws_cloudwatch_event_rule.ingress_change.name
  target_id = "security-detector"
  arn       = aws_lambda_function.detector.arn

  depends_on = [aws_lambda_permission.eventbridge]
}

output "detector_function_name" {
  value = aws_lambda_function.detector.function_name
}