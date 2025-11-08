# AWS Infrastructure
module "aws_baseline" {
  source = "../../modules/aws-baseline"
  
  project_name          = "cloudguardstack"
  vpc_cidr             = "10.0.0.0/16"
  public_subnet_cidrs  = ["10.0.1.0/24", "10.0.2.0/24"]
  private_subnet_cidrs = ["10.0.10.0/24", "10.0.20.0/24"]
  availability_zones   = ["us-east-1a", "us-east-1b"]
  
  tags = {
    Environment = "ephemeral"
    Project     = "CloudGuardStack"
    AutoDelete  = "true"
  }
}

module "aws_logging" {
  source = "../../modules/aws-logging"
  
  project_name       = "cloudguardstack"
  log_retention_days = 90
  force_destroy      = true
  
  tags = {
    Environment = "ephemeral"
    Project     = "CloudGuardStack"
    AutoDelete  = "true"
  }
}

module "aws_iam" {
  source = "../../modules/aws-iam"
  
  project_name = "cloudguardstack"
  
  tags = {
    Environment = "ephemeral"
    Project     = "CloudGuardStack"
    AutoDelete  = "true"
  }
}

# Azure Infrastructure
module "azure_baseline" {
  source = "../../modules/azure-baseline"
  
  project_name    = "cloudguardstack"
  environment     = "ephemeral"
  location        = "East US"
  vnet_cidr       = "10.1.0.0/16"
  public_subnet_cidrs  = ["10.1.1.0/24", "10.1.2.0/24"]
  private_subnet_cidrs = ["10.1.10.0/24", "10.1.20.0/24"]
  
  tags = {
    Environment = "ephemeral"
    Project     = "CloudGuardStack"
    AutoDelete  = "true"
  }
}

module "azure_logging" {
  source = "../../modules/azure-logging"
  
  project_name       = "cloudguardstack"
  environment        = "ephemeral"
  location           = "East US"
  log_retention_days = 90
  allowed_ips        = [] # Add specific IPs if needed
  
  tags = {
    Environment = "ephemeral"
    Project     = "CloudGuardStack"
    AutoDelete  = "true"
  }
}

# GCP Infrastructure - Ephemeral
module "gcp_baseline" {
  source = "../../modules/gcp-baseline"
  
  project_name    = var.project_name
  environment     = var.environment
  region          = "us-central1"
  zone            = "us-central1-a"
  network_name    = "${var.project_name}-vpc"
  subnet_cidr     = "10.2.0.0/16"
  enable_flow_logs = true
  
  tags = merge(var.common_tags, {
    Environment = var.environment
    AutoDelete  = "true"
  })
}

module "gcp_logging" {
  source = "../../modules/gcp-logging"
  
  project_id     = module.gcp_baseline.project_id
  project_name   = var.project_name
  environment    = var.environment
  region         = "us-central1"
  log_retention_days = var.log_retention_days
  
  tags = merge(var.common_tags, {
    Environment = var.environment
    AutoDelete  = "true"
  })
}