variable "aws_region" {
  description = "AWS region for production resources"
  type        = string
  default     = "us-east-1"
}

variable "azure_location" {
  description = "Azure region for production resources"
  type        = string
  default     = "East US"
}

variable "project_name" {
  description = "Name of the project for resource naming"
  type        = string
  default     = "cloudguardstack"
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "production"
  validation {
    condition     = contains(["production", "staging"], var.environment)
    error_message = "Environment must be either 'production' or 'staging'."
  }
}

variable "vpc_cidr" {
  description = "CIDR block for AWS VPC"
  type        = string
  default     = "10.100.0.0/16"
}

variable "aws_public_subnets" {
  description = "List of public subnet CIDR blocks for AWS"
  type        = list(string)
  default     = ["10.100.1.0/24", "10.100.2.0/24", "10.100.3.0/24"]
}

variable "aws_private_subnets" {
  description = "List of private subnet CIDR blocks for AWS"
  type        = list(string)
  default     = ["10.100.10.0/24", "10.100.20.0/24", "10.100.30.0/24"]
}

variable "aws_availability_zones" {
  description = "List of availability zones for AWS"
  type        = list(string)
  default     = ["us-east-1a", "us-east-1b", "us-east-1c"]
}

variable "vnet_cidr" {
  description = "CIDR block for Azure Virtual Network"
  type        = string
  default     = "10.200.0.0/16"
}

variable "azure_public_subnets" {
  description = "List of public subnet CIDR blocks for Azure"
  type        = list(string)
  default     = ["10.200.1.0/24", "10.200.2.0/24"]
}

variable "azure_private_subnets" {
  description = "List of private subnet CIDR blocks for Azure"
  type        = list(string)
  default     = ["10.200.10.0/24", "10.200.20.0/24"]
}

variable "log_retention_days" {
  description = "Number of days to retain logs in CloudWatch and Log Analytics"
  type        = number
  default     = 365  # Longer retention for production
}

variable "allowed_ips" {
  description = "List of IP addresses allowed to access Azure storage account"
  type        = list(string)
  default     = []
}

variable "common_tags" {
  description = "Common tags for all production resources"
  type        = map(string)
  default = {
    Environment = "production"
    Project     = "CloudGuardStack"
    ManagedBy   = "terraform"
    AutoDelete  = "false"
    Critical    = "true"
  }
}

variable "enable_monitoring" {
  description = "Enable additional monitoring and alerting"
  type        = bool
  default     = true
}

variable "alert_email" {
  description = "Email address for production alerts"
  type        = string
  default     = "security-team@example.com"
}