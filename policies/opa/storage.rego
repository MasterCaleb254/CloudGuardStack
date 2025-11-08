package storage

# Deny public access to storage buckets
deny[msg] {
    input.kind == "aws_s3_bucket"
    input.spec.public_access_block == false
    msg := "S3 bucket must have public access block enabled"
}

# Require encryption at rest
deny[msg] {
    input.kind == "aws_s3_bucket"
    not input.spec.server_side_encryption_configuration
    msg := "S3 bucket must have server-side encryption enabled"
}

# Enforce secure transport
deny[msg] {
    input.kind == "aws_s3_bucket_policy"
    not input.spec.policy.Statement[_].Condition.Bool."aws:SecureTransport" == "true"
    msg := "S3 bucket policy must require secure transport (HTTPS)"
}

# Require versioning
deny[msg] {
    input.kind == "aws_s3_bucket"
    input.spec.versioning.enabled != true
    msg := "S3 bucket must have versioning enabled"
}