resource "aws_iam_role_policy" "github_plan" {
  name = "p3-read-lab-and-lock-state"
  role = aws_iam_role.github_plan.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "LocateState"
        Effect   = "Allow"
        Action   = "s3:ListBucket"
        Resource = aws_s3_bucket.state.arn
        Condition = {
          StringLike = {
            "s3:prefix" = [
              "aws-security-response-lab/sandbox/*",
              "env:/*"
            ]
          }
        }
      },
      {
        Sid      = "ReadState"
        Effect   = "Allow"
        Action   = "s3:GetObject"
        Resource = "${aws_s3_bucket.state.arn}/aws-security-response-lab/sandbox/terraform.tfstate"
      },
      {
        Sid    = "ManageStateLock"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject"
        ]
        Resource = "${aws_s3_bucket.state.arn}/aws-security-response-lab/sandbox/terraform.tfstate.tflock"
      },
      {
        Sid    = "ReadBucketConfiguration"
        Effect = "Allow"
        Action = [
          "s3:GetBucket*",
          "s3:GetEncryptionConfiguration",
          "s3:GetLifecycleConfiguration"
        ]
        Resource = [
          aws_s3_bucket.state.arn,
          "arn:aws:s3:::security-lab-evidence-359769212511-47e2f18084087725c0094ba897"
        ]
      },
      {
        Sid    = "ReadRegionalInfrastructure"
        Effect = "Allow"
        Action = [
          "ec2:Describe*",
          "lambda:GetFunction",
          "lambda:GetFunctionConfiguration",
          "lambda:GetFunctionEventInvokeConfig",
          "lambda:GetPolicy",
          "lambda:ListTags",
          "logs:DescribeLogGroups",
          "logs:ListTagsLogGroup",
          "logs:ListTagsForResource",
          "cloudwatch:DescribeAlarms",
          "cloudwatch:GetDashboard",
          "cloudwatch:ListTagsForResource",
          "events:DescribeRule",
          "events:ListTargetsByRule",
          "events:ListTagsForResource",
          "cloudtrail:GetTrail",
          "cloudtrail:GetEventSelectors",
          "cloudtrail:ListTags",
          "config:DescribeConfigurationRecorders",
          "config:DescribeConfigurationRecorderStatus",
          "config:DescribeDeliveryChannels",
          "config:ListTagsForResource",
          "dynamodb:DescribeTable",
          "dynamodb:DescribeContinuousBackups",
          "dynamodb:ListTagsOfResource",
          "guardduty:GetDetector",
          "guardduty:ListTagsForResource",
          "securityhub:DescribeHub",
          "securityhub:ListEnabledProductsForImport",
          "securityhub:ListTagsForResource",
          "sns:GetTopicAttributes",
          "sns:ListTagsForResource",
          "sqs:GetQueueAttributes",
          "sqs:ListQueueTags"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:RequestedRegion" = "us-east-1"
          }
        }
      },
      {
        Sid    = "ReadLabRoles"
        Effect = "Allow"
        Action = [
          "iam:GetRole",
          "iam:GetRolePolicy",
          "iam:ListRolePolicies",
          "iam:ListAttachedRolePolicies",
          "iam:ListInstanceProfilesForRole",
          "iam:ListRoleTags"
        ]
        Resource = [
          "arn:aws:iam::359769212511:role/p3-*",
          "arn:aws:iam::359769212511:role/aws-security-response-lab-config"
        ]
      },
      {
        Sid    = "ReadConfigManagedPolicy"
        Effect = "Allow"
        Action = [
          "iam:GetPolicy",
          "iam:GetPolicyVersion"
        ]
        Resource = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
      }
    ]
  })
}