terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0.0"
    }

    azurerm = {
      source  = "hashicorp/azurerm"
      version = ">= 3.70.0"
    }

    # GCP provider for future expansion
    # google = {
    #   source  = "hashicorp/google"
    #   version = ">= 4.0.0"
    # }
  }

  # Backend configuration - uncomment and configure for team use
  # backend "s3" {
  #   bucket = "cloudguardstack-tfstate"
  #   key    = "terraform.tfstate"
  #   region = "us-east-1"
  #   encrypt = true
  # }
}

# Configure AWS Provider
provider "aws" {
  region = var.aws_region

  default_tags {
    tags = merge(local.common_tags, var.additional_tags, {
      Environment = var.environment
    })
  }
}

# Configure Azure Provider
provider "azurerm" {
  features {}

  subscription_id = var.enable_azure ? null : "00000000-0000-0000-0000-000000000000"
}

# GCP Provider for future expansion
# provider "google" {
#   project = var.gcp_project_id
#   region  = var.gcp_region
# }