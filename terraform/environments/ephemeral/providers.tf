# AWS Provider
provider "aws" {
  region = "us-east-1"

  default_tags {
    tags = {
      Environment = "ephemeral"
      Project     = "CloudGuardStack"
      ManagedBy   = "terraform"
      AutoDelete  = "true"
    }
  }
}

# Azure Provider
provider "azurerm" {
  features {}
}

# GCP Provider (placeholder for future expansion)
# provider "google" {
#   project = var.gcp_project_id
#   region  = "us-central1"
# }