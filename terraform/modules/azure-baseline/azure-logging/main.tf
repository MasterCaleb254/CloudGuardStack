# Log Analytics Workspace
resource "azurerm_log_analytics_workspace" "security" {
  name                = "law-${var.project_name}-${var.environment}"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  sku                 = "PerGB2018"
  retention_in_days   = var.log_retention_days

  tags = var.tags
}

# Storage Account for logs
resource "azurerm_storage_account" "logs" {
  name                     = replace("${var.project_name}logs${var.environment}", "-", "")
  resource_group_name      = azurerm_resource_group.main.name
  location                 = azurerm_resource_group.main.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
  min_tls_version          = "TLS1_2"

  network_rules {
    default_action = "Deny"
    ip_rules       = var.allowed_ips
  }

  tags = var.tags
}

# Activity Log Diagnostic Setting
resource "azurerm_monitor_diagnostic_setting" "activity_logs" {
  name               = "activity-logs-to-loganalytics"
  target_resource_id = "/subscriptions/${data.azurerm_subscription.current.subscription_id}"
  storage_account_id = azurerm_storage_account.logs.id

  log {
    category = "Administrative"
    enabled  = true
  }

  log {
    category = "Security"
    enabled  = true
  }

  log {
    category = "Alert"
    enabled  = true
  }

  log {
    category = "Recommendation"
    enabled  = true
  }

  log {
    category = "Policy"
    enabled  = true
  }

  metric {
    category = "AllMetrics"
    enabled  = true
  }
}

data "azurerm_subscription" "current" {}