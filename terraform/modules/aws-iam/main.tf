# Security Auditor Role
resource "aws_iam_role" "security_auditor" {
  name = "${var.project_name}-security-auditor"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Condition = {
          Bool = {
            "aws:MultiFactorAuthPresent" = "true"
          }
        }
      }
    ]
  })

  tags = var.tags
}

# Security Auditor Policy
resource "aws_iam_policy" "security_audit" {
  name        = "${var.project_name}-security-audit"
  description = "Permissions for security auditing and scanning"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "iam:GenerateCredentialReport",
          "iam:GetCredentialReport",
          "iam:List*",
          "iam:Get*",
          "cloudtrail:LookupEvents",
          "cloudtrail:GetTrailStatus",
          "cloudtrail:GetEventSelectors",
          "cloudtrail:DescribeTrails",
          "s3:GetBucketPolicy",
          "s3:GetBucketAcl",
          "s3:GetBucketLocation",
          "s3:GetBucketLogging",
          "s3:GetBucketVersioning",
          "s3:ListAllMyBuckets",
          "config:Describe*",
          "config:Get*",
          "config:List*",
          "guardduty:Get*",
          "guardduty:List*",
          "securityhub:Get*",
          "securityhub:List*"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.cloudtrail_bucket.arn,
          "${aws_s3_bucket.cloudtrail_bucket.arn}/*"
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "security_audit" {
  role       = aws_iam_role.security_auditor.name
  policy_arn = aws_iam_policy.security_audit.arn
}

# ReadOnly Access for scanners
resource "aws_iam_role_policy_attachment" "read_only" {
  role       = aws_iam_role.security_auditor.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

data "aws_caller_identity" "current" {}