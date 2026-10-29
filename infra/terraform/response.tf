resource "aws_subnet" "response" {
  vpc_id                  = aws_vpc.lab.id
  cidr_block              = "10.77.0.0/28"
  map_public_ip_on_launch = false

  tags = {
    Name        = "p3-response-subnet"
    ResponseLab = "true"
  }
}

resource "aws_security_group" "response_baseline" {
  name        = "p3-response-baseline"
  description = "Baseline group for unattached response lab interface"
  vpc_id      = aws_vpc.lab.id

  ingress {
    protocol    = "tcp"
    from_port   = 443
    to_port     = 443
    cidr_blocks = ["10.77.0.0/24"]
  }

  egress = []

  tags = {
    ResponseLab = "true"
  }
}

resource "aws_security_group" "response_quarantine" {
  name        = "p3-response-quarantine"
  description = "Empty isolation group for response exercise"
  vpc_id      = aws_vpc.lab.id
  ingress     = []
  egress      = []

  tags = {
    ResponseLab = "true"
  }
}

resource "aws_network_interface" "response" {
  subnet_id       = aws_subnet.response.id
  security_groups = [aws_security_group.response_baseline.id]

  tags = {
    Name        = "p3-unattached-response-interface"
    ResponseLab = "true"
  }
}

resource "aws_dynamodb_table" "approvals" {
  name         = "p3-response-approvals"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "run_id"

  attribute {
    name = "run_id"
    type = "S"
  }

  point_in_time_recovery {
    enabled = true
  }
}

resource "aws_cloudwatch_log_group" "response" {
  name              = "/aws/lambda/p3-security-response"
  retention_in_days = 14
}

resource "aws_iam_role" "response" {
  name = "p3-security-response"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "response" {
  name = "p3-execute-approved-response"
  role = aws_iam_role.response.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ReadAndTransitionProposals"
        Effect   = "Allow"
        Action   = ["dynamodb:GetItem", "dynamodb:UpdateItem"]
        Resource = aws_dynamodb_table.approvals.arn
      },
      {
        Sid      = "InspectInterface"
        Effect   = "Allow"
        Action   = "ec2:DescribeNetworkInterfaces"
        Resource = "*"
      },
      {
        Sid    = "ModifyDedicatedInterface"
        Effect = "Allow"
        Action = "ec2:ModifyNetworkInterfaceAttribute"
        Resource = [
          aws_network_interface.response.arn,
          aws_security_group.response_baseline.arn,
          aws_security_group.response_quarantine.arn
        ]
      },
      {
        Sid      = "WriteResponseLogs"
        Effect   = "Allow"
        Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "${aws_cloudwatch_log_group.response.arn}:*"
      }
    ]
  })
}

resource "aws_lambda_function" "response" {
  function_name = "p3-security-response"
  role          = aws_iam_role.response.arn
  runtime       = "python3.13"
  handler       = "app.response.lambda_handler"

  filename         = "${path.module}/../../.build/response.zip"
  source_code_hash = filebase64sha256("${path.module}/../../.build/response.zip")

  timeout     = 30
  memory_size = 256

  environment {
    variables = {
      LAB_INTERFACE_ID    = aws_network_interface.response.id
      LAB_VPC_ID          = aws_vpc.lab.id
      BASELINE_GROUP_ID   = aws_security_group.response_baseline.id
      QUARANTINE_GROUP_ID = aws_security_group.response_quarantine.id
    }
  }

  depends_on = [
    aws_iam_role_policy.response,
    aws_cloudwatch_log_group.response
  ]
}

output "response_interface_id" {
  value = aws_network_interface.response.id
}

output "response_baseline_group_id" {
  value = aws_security_group.response_baseline.id
}

output "response_quarantine_group_id" {
  value = aws_security_group.response_quarantine.id
}