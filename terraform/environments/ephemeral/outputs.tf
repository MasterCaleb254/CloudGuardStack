# AWS Outputs
output "aws_vpc_id" {
  description = "ID of the created AWS VPC"
  value       = module.aws_baseline.vpc_id
}

output "aws_public_subnet_ids" {
  description = "IDs of the AWS public subnets"
  value       = module.aws_baseline.public_subnet_ids
}

output "aws_private_subnet_ids" {
  description = "IDs of the AWS private subnets"
  value       = module.aws_baseline.private_subnet_ids
}

output "aws_cloudtrail_bucket" {
  description = "Name of the S3 bucket for CloudTrail logs"
  value       = module.aws_logging.cloudtrail_bucket_name
}

output "aws_cloudtrail_arn" {
  description = "ARN of the CloudTrail trail"
  value       = module.aws_logging.cloudtrail_arn
}

output "aws_security_auditor_role_arn" {
  description = "ARN of the security auditor IAM role"
  value       = module.aws_iam.security_auditor_role_arn
}

# Azure Outputs
output "azure_resource_group_name" {
  description = "Name of the Azure resource group"
  value       = module.azure_baseline.resource_group_name
}

output "azure_vnet_id" {
  description = "ID of the Azure Virtual Network"
  value       = module.azure_baseline.vnet_id
}

output "azure_public_subnet_ids" {
  description = "IDs of the Azure public subnets"
  value       = module.azure_baseline.public_subnet_ids
}

output "azure_private_subnet_ids" {
  description = "IDs of the Azure private subnets"
  value       = module.azure_baseline.private_subnet_ids
}

output "azure_log_analytics_workspace_id" {
  description = "ID of the Log Analytics Workspace"
  value       = module.azure_logging.log_analytics_workspace_id
}

output "azure_storage_account_name" {
  description = "Name of the storage account for logs"
  value       = module.azure_logging.storage_account_name
}

# Cross-cloud outputs
output "cloudwatch_log_group" {
  description = "Name of the CloudWatch log group for security events"
  value       = "/cloudguardstack/security"
}

output "siem_integration_info" {
  description = "Information for SIEM integration"
  value = {
    aws_cloudtrail_bucket    = module.aws_logging.cloudtrail_bucket_name
    aws_cloudwatch_log_group = "/cloudguardstack/security"
    azure_log_analytics_id   = module.azure_logging.log_analytics_workspace_id
    azure_storage_account    = module.azure_logging.storage_account_name
  }
}

output "deployment_summary" {
  description = "Summary of the deployed infrastructure"
  value = {
    environment          = var.environment
    project_name         = var.project_name
    aws_region           = var.aws_region
    azure_location       = var.azure_location
    deployed_at          = timestamp()
    vpc_cidr             = var.vpc_cidr
    vnet_cidr            = var.vnet_cidr
    log_retention_days   = var.log_retention_days
  }
}