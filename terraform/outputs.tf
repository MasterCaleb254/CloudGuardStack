output "project_name" {
  description = "Name of the deployed project"
  value       = var.project_name
}

output "environment" {
  description = "Deployed environment"
  value       = var.environment
}

output "deployment_timestamp" {
  description = "Timestamp of the deployment"
  value       = timestamp()
}

output "aws_enabled" {
  description = "Whether AWS resources are enabled"
  value       = var.enable_aws
}

output "azure_enabled" {
  description = "Whether Azure resources are enabled"
  value       = var.enable_azure
}

output "gcp_enabled" {
  description = "Whether GCP resources are enabled"
  value       = var.enable_gcp
}

output "cloud_regions" {
  description = "Configured cloud regions"
  value = {
    aws_region    = var.aws_region
    azure_location = var.azure_location
    gcp_region    = var.gcp_region
  }
}

output "log_retention" {
  description = "Configured log retention period"
  value       = "${var.log_retention_days} days"
}

output "security_contact" {
  description = "Security team contact email"
  value       = var.contact_email
}

output "resource_cleanup_policy" {
  description = "Resource cleanup policy"
  value       = var.auto_delete_resources ? "AUTO_DELETE" : "MANUAL_CLEANUP"
}

output "common_tags" {
  description = "Common tags applied to all resources"
  value       = merge(local.common_tags, var.additional_tags)
}

output "next_steps" {
  description = "Next steps after deployment"
  value = <<EOT
CloudGuardStack infrastructure deployed successfully!

Next steps:
1. Run security scans: python scanners/iam-entitlement/scanner.py
2. Setup SIEM: ./scripts/demo/setup-siem-demo.sh
3. Configure monitoring: Check CloudWatch and Azure Monitor
4. Review IAM roles and security policies

For ephemeral environments, remember to run cleanup:
  ./scripts/utilities/teardown-ephemeral-accounts.sh
EOT
}