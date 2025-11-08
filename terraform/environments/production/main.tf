# AWS Infrastructure - Production
module "aws_baseline" {
  source = "../../modules/aws-baseline"
  
  project_name          = var.project_name
  vpc_cidr             = var.vpc_cidr
  public_subnet_cidrs  = var.aws_public_subnets
  private_subnet_cidrs = var.aws_private_subnets
  availability_zones   = var.aws_availability_zones
  
  tags = merge(var.common_tags, {
    Environment = "production"
    AutoDelete  = "false"
  })
}

module "aws_logging" {
  source = "../../modules/aws-logging"
  
  project_name       = var.project_name
  log_retention_days = var.log_retention_days
  force_destroy      = false  # Never force destroy in production
  
  tags = merge(var.common_tags, {
    Environment = "production"
    AutoDelete  = "false"
  })
}

module "aws_iam" {
  source = "../../modules/aws-iam"
  
  project_name = var.project_name
  
  tags = merge(var.common_tags, {
    Environment = "production"
    AutoDelete  = "false"
  })
}

# Azure Infrastructure - Production
module "azure_baseline" {
  source = "../../modules/azure-baseline"
  
  project_name    = var.project_name
  environment     = "production"
  location        = var.azure_location
  vnet_cidr       = var.vnet_cidr
  public_subnet_cidrs  = var.azure_public_subnets
  private_subnet_cidrs = var.azure_private_subnets
  
  tags = merge(var.common_tags, {
    Environment = "production"
    AutoDelete  = "false"
  })
}

module "azure_logging" {
  source = "../../modules/azure-logging"
  
  project_name       = var.project_name
  environment        = "production"
  location           = var.azure_location
  log_retention_days = var.log_retention_days
  allowed_ips        = var.allowed_ips
  
  tags = merge(var.common_tags, {
    Environment = "production"
    AutoDelete  = "false"
  })
}

# Additional Production-specific resources
resource "aws_cloudwatch_log_metric_filter" "security_events" {
  name           = "SecurityEventsFilter"
  pattern        = "ERROR"
  log_group_name = "/cloudguardstack/security"

  metric_transformation {
    name      = "SecurityErrorCount"
    namespace = "CloudGuardStack"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "security_alarm" {
  alarm_name          = "security-events-alarm"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "SecurityErrorCount"
  namespace           = "CloudGuardStack"
  period              = "300"
  statistic           = "Sum"
  threshold           = "5"
  alarm_description   = "This metric monitors for security events"
  alarm_actions       = []  # Add SNS topic ARN for notifications

  tags = merge(var.common_tags, {
    Environment = "production"
  })
}

# GCP Infrastructure - Production
module "gcp_baseline" {
  source = "../../modules/gcp-baseline"
  
  project_name    = var.project_name
  environment     = var.environment
  region          = "us-central1"
  zone            = "us-central1-a"
  network_name    = "${var.project_name}-vpc"
  subnet_cidr     = "10.200.0.0/16"
  enable_flow_logs = true
  
  tags = merge(var.common_tags, {
    Environment = var.environment
    AutoDelete  = "false"
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
    AutoDelete  = "false"
  })
}