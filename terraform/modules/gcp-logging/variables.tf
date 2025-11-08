variable "project_id" {
  description = "The GCP project ID"
  type        = string
}

variable "project_name" {
  description = "Name of the project for resource naming"
  type        = string
  default     = "cloudguardstack"
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "ephemeral"
}

variable "region" {
  description = "The GCP region for resources"
  type        = string
  default     = "us-central1"
}

variable "log_retention_days" {
  description = "Number of days to retain logs"
  type        = number
  default     = 30
}

variable "enable_audit_logs" {
  description = "Enable audit logging for all services"
  type        = bool
  default     = true
}

variable "audit_logs_filter" {
  description = "Filter for audit logs"
  type        = string
  default     = "logName:\"cloudguardstack\" OR severity>=ERROR"
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