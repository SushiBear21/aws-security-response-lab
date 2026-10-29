resource "aws_sqs_queue" "finding_delivery_failures" {
  name                       = "p3-finding-delivery-failures"
  message_retention_seconds  = 1209600
  visibility_timeout_seconds = 120
  sqs_managed_sse_enabled    = true
}

resource "aws_sqs_queue" "finding_processing_failures" {
  name                       = "p3-finding-processing-failures"
  message_retention_seconds  = 1209600
  visibility_timeout_seconds = 120
  sqs_managed_sse_enabled    = true
}

resource "aws_sqs_queue_policy" "finding_delivery_failures" {
  queue_url = aws_sqs_queue.finding_delivery_failures.url

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sqs:SendMessage"
      Resource  = aws_sqs_queue.finding_delivery_failures.arn
      Condition = {
        ArnEquals = {
          "aws:SourceArn" = [
            for rule in aws_cloudwatch_event_rule.finding_router :
            rule.arn
          ]
        }
      }
    }]
  })
}

resource "aws_iam_role_policy" "finding_failure_destination" {
  name = "p3-write-processing-failures"
  role = aws_iam_role.finding_router.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "sqs:SendMessage"
      Resource = aws_sqs_queue.finding_processing_failures.arn
    }]
  })
}

resource "aws_lambda_function_event_invoke_config" "finding_router" {
  function_name                = aws_lambda_function.finding_router.function_name
  maximum_event_age_in_seconds = 300
  maximum_retry_attempts       = 0

  destination_config {
    on_failure {
      destination = aws_sqs_queue.finding_processing_failures.arn
    }
  }

  depends_on = [aws_iam_role_policy.finding_failure_destination]
}

resource "aws_cloudwatch_metric_alarm" "lambda_errors" {
  for_each = toset([
    "p3-security-detector",
    "p3-security-response",
    "p3-finding-router"
  ])

  alarm_name          = "${each.value}-errors"
  namespace           = "AWS/Lambda"
  metric_name         = "Errors"
  statistic           = "Sum"
  period              = 60
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"

  dimensions = {
    FunctionName = each.value
  }

  alarm_actions = [aws_sns_topic.triage.arn]
}

resource "aws_cloudwatch_metric_alarm" "finding_queue_depth" {
  for_each = {
    delivery   = aws_sqs_queue.finding_delivery_failures.name
    processing = aws_sqs_queue.finding_processing_failures.name
  }

  alarm_name          = "p3-finding-${each.key}-queue-not-empty"
  namespace           = "AWS/SQS"
  metric_name         = "ApproximateNumberOfMessagesVisible"
  statistic           = "Maximum"
  period              = 60
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"

  dimensions = {
    QueueName = each.value
  }

  alarm_actions = [aws_sns_topic.triage.arn]
}

resource "aws_cloudwatch_metric_alarm" "finding_throttles" {
  alarm_name          = "p3-finding-router-throttles"
  namespace           = "AWS/Lambda"
  metric_name         = "Throttles"
  statistic           = "Sum"
  period              = 60
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"

  dimensions = {
    FunctionName = aws_lambda_function.finding_router.function_name
  }

  alarm_actions = [aws_sns_topic.triage.arn]
}

resource "aws_cloudwatch_metric_alarm" "finding_destination_errors" {
  alarm_name          = "p3-finding-destination-delivery-errors"
  namespace           = "AWS/Lambda"
  metric_name         = "DestinationDeliveryFailures"
  statistic           = "Sum"
  period              = 60
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"

  dimensions = {
    FunctionName = aws_lambda_function.finding_router.function_name
  }

  alarm_actions = [aws_sns_topic.triage.arn]
}

resource "aws_cloudwatch_dashboard" "operations" {
  dashboard_name = "p3-security-operations"

  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "metric"
        x      = 0
        y      = 0
        width  = 12
        height = 6
        properties = {
          title  = "Lambda invocations"
          region = "us-east-1"
          period = 60
          stat   = "Sum"
          metrics = [
            ["AWS/Lambda", "Invocations", "FunctionName", "p3-security-detector"],
            ["AWS/Lambda", "Invocations", "FunctionName", "p3-security-response"],
            ["AWS/Lambda", "Invocations", "FunctionName", "p3-finding-router"]
          ]
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 0
        width  = 12
        height = 6
        properties = {
          title  = "Lambda errors and router throttles"
          region = "us-east-1"
          period = 60
          stat   = "Sum"
          metrics = [
            ["AWS/Lambda", "Errors", "FunctionName", "p3-security-detector"],
            ["AWS/Lambda", "Errors", "FunctionName", "p3-security-response"],
            ["AWS/Lambda", "Errors", "FunctionName", "p3-finding-router"],
            ["AWS/Lambda", "Throttles", "FunctionName", "p3-finding-router"]
          ]
        }
      },
      {
        type   = "metric"
        x      = 0
        y      = 6
        width  = 12
        height = 6
        properties = {
          title  = "Finding router duration"
          region = "us-east-1"
          period = 60
          stat   = "Average"
          metrics = [
            ["AWS/Lambda", "Duration", "FunctionName", "p3-finding-router"]
          ]
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 6
        width  = 12
        height = 6
        properties = {
          title  = "Visible failed events"
          region = "us-east-1"
          period = 60
          stat   = "Maximum"
          metrics = [
            ["AWS/SQS", "ApproximateNumberOfMessagesVisible",
            "QueueName", aws_sqs_queue.finding_delivery_failures.name],
            ["AWS/SQS", "ApproximateNumberOfMessagesVisible",
            "QueueName", aws_sqs_queue.finding_processing_failures.name]
          ]
        }
      }
    ]
  })
}

output "finding_processing_failure_queue_url" {
  value = aws_sqs_queue.finding_processing_failures.url
}

output "finding_delivery_failure_queue_url" {
  value = aws_sqs_queue.finding_delivery_failures.url
}