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

variable "project_id" {
  description = "The GCP project ID. If not provided, a random ID will be generated"
  type        = string
  default     = null
}

variable "billing_account" {
  description = "The ID of the billing account to associate with the project"
  type        = string
  default     = null
}

variable "org_id" {
  description = "The organization ID for the project"
  type        = string
  default     = null
}

variable "region" {
  description = "The GCP region for resources"
  type        = string
  default     = "us-central1"
}

variable "zone" {
  description = "The GCP zone for resources"
  type        = string
  default     = "us-central1-a"
}

variable "network_name" {
  description = "Name of the VPC network"
  type        = string
  default     = "cloudguardstack-vpc"
}

variable "routing_mode" {
  description = "The network routing mode (REGIONAL or GLOBAL)"
  type        = string
  default     = "REGIONAL"

  validation {
    condition     = contains(["REGIONAL", "GLOBAL"], var.routing_mode)
    error_message = "Routing mode must be either REGIONAL or GLOBAL."
  }
}

variable "auto_create_subnetworks" {
  description = "When set to true, the network is created in 'auto subnet mode'"
  type        = bool
  default     = false
}

variable "subnet_cidr" {
  description = "CIDR range for the primary subnet"
  type        = string
  default     = "10.2.0.0/16"
}

variable "subnet_secondary_ranges" {
  description = "Secondary IP ranges for the subnet"
  type        = map(list(object({
    range_name    = string
    ip_cidr_range = string
  })))
  default = {
    "cloudguardstack-subnet" = [
      {
        range_name    = "pods"
        ip_cidr_range = "10.2.1.0/24"
      },
      {
        range_name    = "services"
        ip_cidr_range = "10.2.2.0/24"
      }
    ]
  }
}

variable "enable_flow_logs" {
  description = "Enable VPC Flow Logs for the network"
  type        = bool
  default     = true
}

variable "flow_logs_aggregation_interval" {
  description = "Aggregation interval for flow logs"
  type        = string
  default     = "INTERVAL_5_SEC"

  validation {
    condition     = contains(["INTERVAL_5_SEC", "INTERVAL_30_SEC", "INTERVAL_1_MIN", "INTERVAL_5_MIN", "INTERVAL_10_MIN", "INTERVAL_15_MIN"], var.flow_logs_aggregation_interval)
    error_message = "Aggregation interval must be one of the predefined values."
  }
}

variable "firewall_rules" {
  description = "List of firewall rules to create"
  type = list(object({
    name                    = string
    description             = string
    direction               = string
    priority                = number
    ranges                  = list(string)
    source_tags             = list(string)
    target_tags             = list(string)
    allow = list(object({
      protocol = string
      ports    = list(string)
    }))
    deny = list(object({
      protocol = string
      ports    = list(string)
    }))
    log_config = object({
      metadata = string
    })
  }))
  default = [
    {
      name        = "allow-ssh"
      description = "Allow SSH from anywhere"
      direction   = "INGRESS"
      priority    = 1000
      ranges      = ["0.0.0.0/0"]
      source_tags = null
      target_tags = null
      allow = [
        {
          protocol = "tcp"
          ports    = ["22"]
        }
      ]
      deny       = []
      log_config = null
    },
    {
      name        = "allow-http"
      description = "Allow HTTP from anywhere"
      direction   = "INGRESS"
      priority    = 1000
      ranges      = ["0.0.0.0/0"]
      source_tags = null
      target_tags = null
      allow = [
        {
          protocol = "tcp"
          ports    = ["80"]
        }
      ]
      deny       = []
      log_config = null
    },
    {
      name        = "allow-https"
      description = "Allow HTTPS from anywhere"
      direction   = "INGRESS"
      priority    = 1000
      ranges      = ["0.0.0.0/0"]
      source_tags = null
      target_tags = null
      allow = [
        {
          protocol = "tcp"
          ports    = ["443"]
        }
      ]
      deny       = []
      log_config = null
    },
    {
      name        = "deny-all-ingress"
      description = "Deny all other ingress traffic"
      direction   = "INGRESS"
      priority    = 65534
      ranges      = ["0.0.0.0/0"]
      source_tags = null
      target_tags = null
      allow       = []
      deny = [
        {
          protocol = "all"
          ports    = null
        }
      ]
      log_config = null
    }
  ]
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