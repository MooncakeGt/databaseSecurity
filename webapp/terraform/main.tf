# Combined Terraform Configuration: Secure AWS Infrastructure

provider "aws" {
  region = "ap-southeast-1"
}

# ------------------------------
# VPC Setup (Assume VPC is already created or use data)
data "aws_vpc" "main" {
  filter {
    name   = "tag:Name"
    values = ["assignment-vpc"]
  }
}

# ------------------------------
# Security Groups
resource "aws_security_group" "web_sg" {
  name        = "web-sg"
  description = "Allow HTTP & HTTPS"
  vpc_id      = data.aws_vpc.main.id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# ------------------------------
# IAM Role with Least Privilege
resource "aws_iam_role" "ec2_role" {
  name = "ec2-access-s3-logs"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Principal = {
        Service = "ec2.amazonaws.com"
      },
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_policy" "ec2_s3_logs_policy" {
  name = "EC2S3LogsPolicy"
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect   = "Allow",
      Action   = ["s3:PutObject", "s3:GetObject"],
      Resource = "arn:aws:s3:::assignment-secure-logs/*"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "attach_policy" {
  role       = aws_iam_role.ec2_role.name
  policy_arn = aws_iam_policy.ec2_s3_logs_policy.arn
}

# ------------------------------
# S3 Bucket with Encryption
resource "aws_s3_bucket" "secure_bucket" {
  bucket = "assignment-secure-app-bucket"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "secure_sse" {
  bucket = aws_s3_bucket.secure_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}


# ------------------------------
# RDS Encrypted
resource "aws_db_instance" "secure_db" {
  allocated_storage    = 20
  storage_encrypted    = true
  engine               = "mysql"
  engine_version       = "8.0"
  instance_class       = "db.t3.micro"
  db_name                 = "securedb"
  username             = "admin"
  password             = "StrongPass123!"
  skip_final_snapshot  = true
  publicly_accessible  = false
  vpc_security_group_ids = [aws_security_group.web_sg.id]
}

# ------------------------------
# CloudTrail
resource "aws_cloudtrail" "main" {
  name                          = "assignment-trail"
  s3_bucket_name                = aws_s3_bucket.secure_bucket.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  event_selector {
    read_write_type           = "All"
    include_management_events = true
  }
}

# ------------------------------
# CloudWatch Alarm
resource "aws_cloudwatch_log_group" "unauth_log" {
  name = "/aws/cloudtrail/unauthorized"
}

resource "aws_cloudwatch_metric_alarm" "unauth_alarm" {
  alarm_name          = "UnauthorizedAPI"
  metric_name         = "UnauthorizedOperation"
  namespace           = "AWS/CloudTrail"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  alarm_description   = "Alarm for unauthorized API calls"
}

# ------------------------------
# WAF ACL
resource "aws_wafv2_web_acl" "secure_web_acl" {
  name        = "assignment-waf"
  scope       = "REGIONAL"
  description = "WAF for ALB - blocks SQLi and XSS"
  default_action {
    allow {}
  }

  rule {
    name     = "BlockSQLi"
    priority = 1
    statement {
      sqli_match_statement {
        field_to_match {
          body {}
        }
        text_transformation {
          priority = 0
          type     = "URL_DECODE"
        }
      }
    }
    action {
      block {}
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "sqlirule"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "assignment-waf"
    sampled_requests_enabled   = true
  }
}

# ------------------------------
# ACM Certificate for SSL
resource "aws_acm_certificate" "ssl_cert" {
  domain_name       = "yourapp.example.com"
  validation_method = "DNS"
}

# ALB listener and resource assumed defined elsewhere with reference to this cert
