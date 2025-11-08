variable "project_name" {
  description = "Name of the project for resource naming"
  type        = string
  default     = "cloudguardstack"
}

variable "environment" {
  description = "Environment to deploy (ephemeral, staging, production)"
  type        = string
  default     = "ephemeral"
  
  validation {
    condition     = contains(["ephemeral", "staging", "production"], var.environment)
    error_message = "Environment must be one of: ephemeral, staging, production."
  }
}

variable "enable_aws" {
  description = "Enable AWS resources deployment"
  type        = bool
  default     = true
}

variable "enable_azure" {
  description = "Enable Azure resources deployment"
  type        = bool
  default     = true
}

variable "enable_gcp" {
  description = "Enable GCP resources deployment (future use)"
  type        = bool
  default     = false
}

variable "aws_region" {
  description = "Default AWS region"
  type        = string
  default     = "us-east-1"
}

variable "azure_location" {
  description = "Default Azure region"
  type        = string
  default     = "East US"
}

variable "gcp_region" {
  description = "Default GCP region (future use)"
  type        = string
  default     = "us-central1"
}

variable "log_retention_days" {
  description = "Default log retention in days"
  type        = number
  default     = 90
  
  validation {
    condition     = var.log_retention_days >= 7 && var.log_retention_days <= 3653
    error_message = "Log retention must be between 7 and 3653 days."
  }
}

variable "auto_delete_resources" {
  description = "Automatically delete resources (use with caution)"
  type        = bool
  default     = false
}

variable "contact_email" {
  description = "Contact email for security notifications"
  type        = string
  default     = "security@example.com"
}

variable "additional_tags" {
  description = "Additional tags to apply to all resources"
  type        = map(string)
  default     = {}
}