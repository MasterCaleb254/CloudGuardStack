output "log_analytics_workspace_id" {
  description = "ID of the Log Analytics Workspace"
  value       = azurerm_log_analytics_workspace.security.id
}

output "log_analytics_workspace_name" {
  description = "Name of the Log Analytics Workspace"
  value       = azurerm_log_analytics_workspace.security.name
}

output "log_analytics_workspace_primary_shared_key" {
  description = "Primary shared key for the Log Analytics Workspace"
  value       = azurerm_log_analytics_workspace.security.primary_shared_key
  sensitive   = true
}

output "storage_account_id" {
  description = "ID of the storage account for logs"
  value       = azurerm_storage_account.logs.id
}

output "storage_account_name" {
  description = "Name of the storage account for logs"
  value       = azurerm_storage_account.logs.name
}

output "storage_account_primary_access_key" {
  description = "Primary access key for the storage account"
  value       = azurerm_storage_account.logs.primary_access_key
  sensitive   = true
}