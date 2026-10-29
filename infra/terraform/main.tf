terraform {
  required_version = ">= 1.5.0, < 2.0.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

provider "aws" {
  region              = "us-east-1"
  allowed_account_ids = ["359769212511"]
  default_tags {
    tags = {
      Project     = "aws-security-response-lab"
      Environment = "sandbox"
      ManagedBy   = "Terraform"
    }
  }
}

locals {
  name       = "aws-security-response-lab"
  account_id = "359769212511"
  region     = "us-east-1"
  trail_arn  = "arn:aws:cloudtrail:${local.region}:${local.account_id}:trail/${local.name}"
  config_arn = "arn:aws:config:${local.region}:${local.account_id}:*"
}

resource "aws_vpc" "lab" {
  cidr_block           = "10.77.0.0/24"
  enable_dns_support   = true
  enable_dns_hostnames = false
  tags                 = { Name = local.name }
}

# No subnets, internet gateway, NAT gateway, peering, or workloads are created.
resource "aws_security_group" "target" {
  name        = "${local.name}-target"
  description = "Dedicated exercise target; no inbound or outbound rules"
  vpc_id      = aws_vpc.lab.id
  ingress     = []
  egress      = []
  tags        = { Name = "${local.name}-target" }
}

resource "aws_s3_bucket" "evidence" {
  bucket_prefix = "security-lab-evidence-359769212511-"
  force_destroy = false
}

resource "aws_s3_bucket_public_access_block" "evidence" {
  bucket                  = aws_s3_bucket.evidence.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_versioning" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_policy" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "RequireTLS"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = [aws_s3_bucket.evidence.arn, "${aws_s3_bucket.evidence.arn}/*"]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      },
      {
        Sid       = "CloudTrailCheck"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.evidence.arn
        Condition = { StringEquals = { "aws:SourceArn" = local.trail_arn } }
      },
      {
        Sid       = "CloudTrailDelivery"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.evidence.arn}/cloudtrail/AWSLogs/${local.account_id}/*"
        Condition = { StringEquals = {
          "aws:SourceArn" = local.trail_arn
          "s3:x-amz-acl"  = "bucket-owner-full-control"
        } }
      },
      {
        Sid       = "ConfigBucketChecks"
        Effect    = "Allow"
        Principal = { Service = "config.amazonaws.com" }
        Action    = ["s3:GetBucketAcl", "s3:ListBucket"]
        Resource  = aws_s3_bucket.evidence.arn
        Condition = {
          StringEquals = { "aws:SourceAccount" = local.account_id }
          ArnLike      = { "aws:SourceArn" = local.config_arn }
        }
      },
      {
        Sid       = "ConfigDelivery"
        Effect    = "Allow"
        Principal = { Service = "config.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.evidence.arn}/config/AWSLogs/${local.account_id}/Config/*"
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = local.account_id
            "s3:x-amz-acl"      = "bucket-owner-full-control"
          }
          ArnLike = { "aws:SourceArn" = local.config_arn }
        }
      }
    ]
  })
}

resource "aws_cloudtrail" "lab" {
  name                          = local.name
  s3_bucket_name                = aws_s3_bucket.evidence.id
  s3_key_prefix                 = "cloudtrail"
  is_multi_region_trail         = false
  include_global_service_events = false
  enable_log_file_validation    = true
  enable_logging                = true
  event_selector {
    read_write_type           = "WriteOnly"
    include_management_events = true
  }
  depends_on = [
    aws_s3_bucket_policy.evidence,
    aws_s3_bucket_public_access_block.evidence,
    aws_s3_bucket_ownership_controls.evidence,
    aws_s3_bucket_versioning.evidence,
    aws_s3_bucket_server_side_encryption_configuration.evidence
  ]
}

resource "aws_iam_role" "config" {
  name = "${local.name}-config"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "config.amazonaws.com" }
      Action    = "sts:AssumeRole"
      Condition = { StringEquals = { "aws:SourceAccount" = local.account_id } }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "config" {
  role       = aws_iam_role.config.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
}

resource "aws_iam_role_policy" "config_delivery" {
  name = "evidence-delivery"
  role = aws_iam_role.config.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:GetBucketAcl", "s3:ListBucket"]
        Resource = aws_s3_bucket.evidence.arn
      },
      {
        Effect    = "Allow"
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.evidence.arn}/config/AWSLogs/${local.account_id}/Config/*"
        Condition = { StringEquals = { "s3:x-amz-acl" = "bucket-owner-full-control" } }
      }
    ]
  })
}

# Only create this recorder because the supplied inventory returned none.
resource "aws_config_configuration_recorder" "lab" {
  name     = local.name
  role_arn = aws_iam_role.config.arn
  recording_group {
    all_supported                 = false
    include_global_resource_types = false
    resource_types                = ["AWS::EC2::SecurityGroup", "AWS::EC2::VPC"]
    recording_strategy {
      use_only = "INCLUSION_BY_RESOURCE_TYPES"
    }
  }
  recording_mode {
    recording_frequency = "CONTINUOUS"
  }
  depends_on = [aws_iam_role_policy_attachment.config, aws_iam_role_policy.config_delivery]
}

resource "aws_config_delivery_channel" "lab" {
  name           = local.name
  s3_bucket_name = aws_s3_bucket.evidence.id
  s3_key_prefix  = "config"
  snapshot_delivery_properties {
    delivery_frequency = "TwentyFour_Hours"
  }
  depends_on = [
    aws_config_configuration_recorder.lab,
    aws_s3_bucket_policy.evidence,
    aws_s3_bucket_public_access_block.evidence,
    aws_s3_bucket_ownership_controls.evidence,
    aws_s3_bucket_versioning.evidence,
    aws_s3_bucket_server_side_encryption_configuration.evidence
  ]
}

resource "aws_config_configuration_recorder_status" "lab" {
  name       = aws_config_configuration_recorder.lab.name
  is_enabled = true
  depends_on = [aws_config_delivery_channel.lab]
}

output "evidence_bucket_name" { value = aws_s3_bucket.evidence.id }
output "evidence_bucket_arn" { value = aws_s3_bucket.evidence.arn }
output "vpc_id" { value = aws_vpc.lab.id }
output "target_security_group_id" { value = aws_security_group.target.id }
output "trail_name" { value = aws_cloudtrail.lab.name }
output "trail_arn" { value = aws_cloudtrail.lab.arn }
output "config_recorder_name" { value = aws_config_configuration_recorder.lab.name }
output "config_delivery_channel_name" { value = aws_config_delivery_channel.lab.name }
