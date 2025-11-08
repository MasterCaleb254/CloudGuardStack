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

variable "vnet_cidr" {
  description = "CIDR block for the Virtual Network"
  type        = string
  default     = "10.1.0.0/16"
}

variable "public_subnet_cidrs" {
  description = "List of public subnet CIDR blocks"
  type        = list(string)
  default     = ["10.1.1.0/24", "10.1.2.0/24"]
}

variable "private_subnet_cidrs" {
  description = "List of private subnet CIDR blocks"
  type        = list(string)
  default     = ["10.1.10.0/24", "10.1.20.0/24"]
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