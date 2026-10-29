resource "aws_iam_role_policy" "github_plan_refresh" {
  name = "p3-read-refresh-metadata"
  role = aws_iam_role.github_plan.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ReadLabLambdaVersions"
        Effect = "Allow"
        Action = [
          "lambda:ListVersionsByFunction",
          "lambda:GetFunctionCodeSigningConfig"
        ]
        Resource = [
          "arn:aws:lambda:us-east-1:359769212511:function:p3-security-detector",
          "arn:aws:lambda:us-east-1:359769212511:function:p3-finding-router",
          "arn:aws:lambda:us-east-1:359769212511:function:p3-security-response"
        ]
      },
      {
        Sid      = "DescribeRegionalTrails"
        Effect   = "Allow"
        Action   = "cloudtrail:DescribeTrails"
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:RequestedRegion" = "us-east-1"
          }
        }
      },
      {
        Sid      = "ReadApprovalTableTTL"
        Effect   = "Allow"
        Action   = "dynamodb:DescribeTimeToLive"
        Resource = "arn:aws:dynamodb:us-east-1:359769212511:table/p3-response-approvals"
      },
      {
        Sid    = "CheckEvidenceBucket"
        Effect = "Allow"
        Action = [
          "s3:ListBucket",
          "s3:GetAccelerateConfiguration",
          "s3:GetReplicationConfiguration"
        ]
        Resource = "arn:aws:s3:::security-lab-evidence-359769212511-47e2f18084087725c0094ba897"
      }
    ]
  })
}