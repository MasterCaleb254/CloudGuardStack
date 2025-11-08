# This is the root module that defines the overall structure
# Each environment should be deployed separately using terraform workspaces
# or by targeting specific environment directories

# Local values for common configuration
locals {
  common_tags = {
    Project     = "CloudGuardStack"
    ManagedBy   = "terraform"
    Repository  = "https://github.com/MasterCaleb254/cloud-guard-stack"
    Purpose     = "Cloud Security Baseline"
  }
}

# Data sources for account information
data "aws_caller_identity" "current" {}

data "azurerm_subscription" "current" {}

# Output account information for reference
output "account_info" {
  description = "Current cloud account information"
  value = {
    aws_account_id    = data.aws_caller_identity.current.account_id
    aws_user_id       = data.aws_caller_identity.current.user_id
    aws_arn           = data.aws_caller_identity.current.arn
    azure_subscription_id = data.azurerm_subscription.current.subscription_id
    azure_display_name    = data.azurerm_subscription.current.display_name
  }
}