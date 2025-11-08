variable "project_name" {
  description = "Name of the project for resource naming"
  type        = string
  default     = "cloudguardstack"
}

variable "environment" {
  description = "Environment name (ephemeral, staging, production)"
  type        = string
  default     = "ephemeral"
}

variable "location" {
  description = "Azure region where resources will be created"
  type        = string
  default     = "East US"
}

variable "log_retention_days" {
  description = "Number of days to retain logs"
  type        = number
  default     = 90
}

variable "allowed_ips" {
  description = "List of IP addresses allowed to access storage account"
  type        = list(string)
  default     = []
}

variable "tags" {
  description = "Additional tags for all resources"
  type        = map(string)
  default = {
    Environment = "ephemeral"
    Project     = "CloudGuardStack"
    ManagedBy   = "terraform"
    AutoDelete  = "true"
  }
}