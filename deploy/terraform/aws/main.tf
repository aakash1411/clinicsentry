## ClinicSentry — AWS reference deployment.
##
## Provisions:
##   - VPC (private subnets + NAT)
##   - RDS Postgres for audit storage
##   - S3 bucket with Object Lock (compliance mode) for cold archive
##   - KMS key for envelope encryption
##   - IAM role with least-privilege policy
##   - CloudWatch alarms on chain-verification failure
##
## Intended as a starting point; production deployments will tailor it.

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.region
}

variable "name_prefix" {
  type        = string
  description = "Prefix applied to every resource name."
  default     = "clinicsentry"
}

variable "region" {
  type        = string
  description = "AWS region."
  default     = "us-east-1"
}

variable "vpc_cidr" {
  type    = string
  default = "10.42.0.0/16"
}

variable "object_lock_retention_days" {
  type        = number
  description = "Object Lock retention in days for the audit archive bucket."
  default     = 2555
}

# -------------------------------------------------------------------- VPC ----

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.5"

  name = "${var.name_prefix}-vpc"
  cidr = var.vpc_cidr

  azs             = ["${var.region}a", "${var.region}b"]
  private_subnets = [cidrsubnet(var.vpc_cidr, 4, 0), cidrsubnet(var.vpc_cidr, 4, 1)]
  public_subnets  = [cidrsubnet(var.vpc_cidr, 4, 2), cidrsubnet(var.vpc_cidr, 4, 3)]

  enable_nat_gateway = true
  single_nat_gateway = true
  enable_dns_hostnames = true

  tags = local.tags
}

# --------------------------------------------------------------------- KMS ---

resource "aws_kms_key" "audit" {
  description             = "ClinicSentry audit encryption key"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  tags                    = local.tags
}

resource "aws_kms_alias" "audit" {
  name          = "alias/${var.name_prefix}-audit"
  target_key_id = aws_kms_key.audit.key_id
}

# ---------------------------------------------------------------------- RDS --

resource "random_password" "rds" {
  length  = 32
  special = false
}

resource "aws_db_subnet_group" "audit" {
  name       = "${var.name_prefix}-rds"
  subnet_ids = module.vpc.private_subnets
  tags       = local.tags
}

resource "aws_security_group" "rds" {
  name        = "${var.name_prefix}-rds-sg"
  description = "ClinicSentry RDS access"
  vpc_id      = module.vpc.vpc_id

  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = local.tags
}

resource "aws_db_instance" "audit" {
  identifier              = "${var.name_prefix}-audit"
  engine                  = "postgres"
  engine_version          = "16"
  instance_class          = "db.t4g.small"
  allocated_storage       = 50
  storage_encrypted       = true
  kms_key_id              = aws_kms_key.audit.arn
  db_name                 = "clinicsentry"
  username                = "cg"
  password                = random_password.rds.result
  db_subnet_group_name    = aws_db_subnet_group.audit.name
  vpc_security_group_ids  = [aws_security_group.rds.id]
  skip_final_snapshot     = false
  final_snapshot_identifier = "${var.name_prefix}-final"
  backup_retention_period = 30
  deletion_protection     = true
  tags                    = local.tags
}

# ---------------------------------------------------------------------- S3 ---

resource "aws_s3_bucket" "archive" {
  bucket = "${var.name_prefix}-archive-${data.aws_caller_identity.me.account_id}"
  object_lock_enabled = true
  tags = local.tags
}

resource "aws_s3_bucket_versioning" "archive" {
  bucket = aws_s3_bucket.archive.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "archive" {
  bucket = aws_s3_bucket.archive.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.audit.arn
    }
  }
}

resource "aws_s3_bucket_object_lock_configuration" "archive" {
  bucket = aws_s3_bucket.archive.id
  rule {
    default_retention {
      mode = "COMPLIANCE"
      days = var.object_lock_retention_days
    }
  }
}

resource "aws_s3_bucket_public_access_block" "archive" {
  bucket                  = aws_s3_bucket.archive.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# -------------------------------------------------------------------- IAM ---

data "aws_caller_identity" "me" {}

resource "aws_iam_role" "service" {
  name = "${var.name_prefix}-service"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action = "sts:AssumeRole"
    }]
  })
  tags = local.tags
}

resource "aws_iam_role_policy" "service" {
  name = "${var.name_prefix}-service"
  role = aws_iam_role.service.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = ["s3:PutObject", "s3:GetObject", "s3:ListBucket"]
        Resource = [
          aws_s3_bucket.archive.arn,
          "${aws_s3_bucket.archive.arn}/*"
        ]
      },
      {
        Effect = "Allow"
        Action = ["kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey"]
        Resource = [aws_kms_key.audit.arn]
      }
    ]
  })
}

# ----------------------------------------------------------------- CloudWatch

resource "aws_cloudwatch_metric_alarm" "chain_failure" {
  alarm_name          = "${var.name_prefix}-chain-verify-failures"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "ChainVerifyFailures"
  namespace           = "ClinicSentry"
  period              = 300
  statistic           = "Sum"
  threshold           = 0
  alarm_description   = "Any audit-chain verify failure triggers paging."
  treat_missing_data  = "notBreaching"
  tags                = local.tags
}

# ----------------------------------------------------------------- locals ----

locals {
  tags = {
    project   = "clinicsentry"
    component = "infra"
  }
}

output "rds_endpoint" {
  value     = aws_db_instance.audit.endpoint
  sensitive = false
}

output "archive_bucket" {
  value = aws_s3_bucket.archive.bucket
}

output "rds_password" {
  value     = random_password.rds.result
  sensitive = true
}
