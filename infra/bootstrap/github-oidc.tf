resource "aws_iam_openid_connect_provider" "github" {
  url = "https://token.actions.githubusercontent.com"

  client_id_list = ["sts.amazonaws.com"]
}

resource "aws_iam_role" "github_plan" {
  name                 = "p3-github-plan"
  max_session_duration = 3600

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = "sts:AssumeRoleWithWebIdentity"

      Principal = {
        Federated = aws_iam_openid_connect_provider.github.arn
      }

      Condition = {
        StringEquals = {
          "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
          "token.actions.githubusercontent.com:sub" = "repo:SushiBear21/aws-security-response-lab:ref:refs/heads/main"
        }
      }
    }]
  })
}

output "github_plan_role_arn" {
  value = aws_iam_role.github_plan.arn
}