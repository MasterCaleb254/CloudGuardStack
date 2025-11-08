#!/bin/bash
set -e

echo "🗑️ Tearing down AWS ephemeral account..."

ACCOUNT_ID=$(aws sts get-caller-identity --query "Account" --output text)
CREATION_TIME=$(aws iam get-account-summary --query "Summary.AccountCreationTime" --output text)

echo "🔍 Account ID: $ACCOUNT_ID"
echo "📅 Created: $CREATION_TIME"

# List all resources and attempt cleanup
echo "🧹 Cleaning up resources..."

# Delete S3 buckets
aws s3api list-buckets --query "Buckets[].Name" --output text | tr '\t' '\n' | while read bucket; do
    echo "🗑️ Deleting bucket: $bucket"
    aws s3 rb "s3://$bucket" --force || true
done

# Terminate EC2 instances
aws ec2 describe-instances --query "Reservations[].Instances[].InstanceId" --output text | tr '\t' '\n' | while read instance; do
    echo "🗑️ Terminating instance: $instance"
    aws ec2 terminate-instances --instance-ids "$instance" || true
done

echo "✅ AWS account teardown initiated"