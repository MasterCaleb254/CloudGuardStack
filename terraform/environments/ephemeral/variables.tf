variable "aws_region" {
  description = "AWS region for resources"
  type        = string
  default     = "us-east-1"
}

variable "azure_location" {
  description = "Azure region for resources"
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
  default     = "ephemeral"
}

variable "vpc_cidr" {
  description = "CIDR block for AWS VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "aws_public_subnets" {
  description = "List of public subnet CIDR blocks for AWS"
  type        = list(string)
  default     = ["10.0.1.0/24", "10.0.2.0/24"]
}

variable "aws_private_subnets" {
  description = "List of private subnet CIDR blocks for AWS"
  type        = list(string)
  default     = ["10.0.10.0/24", "10.0.20.0/24"]
}

variable "vnet_cidr" {
  description = "CIDR block for Azure Virtual Network"
  type        = string
  default     = "10.1.0.0/16"
}

variable "azure_public_subnets" {
  description = "List of public subnet CIDR blocks for Azure"
  type        = list(string)
  default     = ["10.1.1.0/24", "10.1.2.0/24"]
}

variable "azure_private_subnets" {
  description = "List of private subnet CIDR blocks for Azure"
  type        = list(string)
  default     = ["10.1.10.0/24", "10.1.20.0/24"]
}

variable "log_retention_days" {
  description = "Number of days to retain logs in CloudWatch and Log Analytics"
  type        = number
  default     = 90
}

variable "force_destroy" {
  description = "Force destroy S3 buckets even if not empty (for ephemeral environments)"
  type        = bool
  default     = true
}

variable "allowed_ips" {
  description = "List of IP addresses allowed to access Azure storage account"
  type        = list(string)
  default     = []
}

variable "common_tags" {
  description = "Common tags for all resources"
  type        = map(string)
  default = {
    Environment = "ephemeral"
    Project     = "CloudGuardStack"
    ManagedBy   = "terraform"
    AutoDelete  = "true"
    Ephemeral   = "true"
  }
}