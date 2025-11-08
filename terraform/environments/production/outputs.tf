# AWS Production Outputs
output "aws_vpc_id" {
  description = "ID of the production AWS VPC"
  value       = module.aws_baseline.vpc_id
}

output "aws_public_subnet_ids" {
  description = "IDs of the production AWS public subnets"
  value       = module.aws_baseline.public_subnet_ids
}

output "aws_private_subnet_ids" {
  description = "IDs of the production AWS private subnets"
  value       = module.aws_baseline.private_subnet_ids
}

output "aws_cloudtrail_bucket" {
  description = "Name of the production S3 bucket for CloudTrail logs"
  value       = module.aws_logging.cloudtrail_bucket_name
}

output "aws_cloudtrail_arn" {
  description = "ARN of the production CloudTrail trail"
  value       = module.aws_logging.cloudtrail_arn
}

output "aws_security_auditor_role_arn" {
  description = "ARN of the production security auditor IAM role"
  value       = module.aws_iam.security_auditor_role_arn
}

# Azure Production Outputs
output "azure_resource_group_name" {
  description = "Name of the production Azure resource group"
  value       = module.azure_baseline.resource_group_name
}

output "azure_vnet_id" {
  description = "ID of the production Azure Virtual Network"
  value       = module.azure_baseline.vnet_id
}

output "azure_public_subnet_ids" {
  description = "IDs of the production Azure public subnets"
  value       = module.azure_baseline.public_subnet_ids
}

output "azure_private_subnet_ids" {
  description = "IDs of the production Azure private subnets"
  value       = module.azure_baseline.private_subnet_ids
}

output "azure_log_analytics_workspace_id" {
  description = "ID of the production Log Analytics Workspace"
  value       = module.azure_logging.log_analytics_workspace_id
}

output "azure_storage_account_name" {
  description = "Name of the production storage account for logs"
  value       = module.azure_logging.storage_account_name
}

# Production-specific outputs
output "cloudwatch_alarm_arns" {
  description = "ARNs of CloudWatch alarms for monitoring"
  value       = [aws_cloudwatch_metric_alarm.security_alarm.arn]
}

output "production_deployment_info" {
  description = "Production deployment information"
  value = {
    environment        = var.environment
    project_name       = var.project_name
    aws_region         = var.aws_region
    azure_location     = var.azure_location
    deployed_at        = timestamp()
    vpc_cidr           = var.vpc_cidr
    vnet_cidr          = var.vnet_cidr
    log_retention_days = var.log_retention_days
    monitoring_enabled = var.enable_monitoring
  }
}

output "security_contact" {
  description = "Security team contact information"
  value       = var.alert_email
  sensitive   = true
}