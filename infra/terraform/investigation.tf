resource "aws_iam_role_policy" "investigation" {
  name = "p3-read-investigation-evidence"
  role = aws_iam_role.detector.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "InspectNetworkConfiguration"
        Effect = "Allow"
        Action = [
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeSecurityGroupRules",
          "ec2:DescribeNetworkInterfaces"
        ]
        Resource = "*"
      },
      {
        Sid      = "ReadConfigHistory"
        Effect   = "Allow"
        Action   = "config:GetResourceConfigHistory"
        Resource = "*"
      }
    ]
  })
}