output "project_id" {
  description = "The GCP project ID"
  value       = google_project.main.project_id
}

output "project_number" {
  description = "The GCP project number"
  value       = google_project.main.number
}

output "project_name" {
  description = "The GCP project name"
  value       = google_project.main.name
}

output "network_name" {
  description = "Name of the created VPC network"
  value       = google_compute_network.main.name
}

output "network_id" {
  description = "ID of the created VPC network"
  value       = google_compute_network.main.id
}

output "network_self_link" {
  description = "Self link of the created VPC network"
  value       = google_compute_network.main.self_link
}

output "subnet_name" {
  description = "Name of the primary subnet"
  value       = google_compute_subnetwork.main.name
}

output "subnet_id" {
  description = "ID of the primary subnet"
  value       = google_compute_subnetwork.main.id
}

output "subnet_self_link" {
  description = "Self link of the primary subnet"
  value       = google_compute_subnetwork.main.self_link
}

output "subnet_ip_cidr_range" {
  description = "IP CIDR range of the primary subnet"
  value       = google_compute_subnetwork.main.ip_cidr_range
}

output "subnet_secondary_ranges" {
  description = "Secondary IP ranges of the subnet"
  value       = google_compute_subnetwork.main.secondary_ip_range
}

output "firewall_rules" {
  description = "Map of created firewall rules"
  value = {
    for rule in google_compute_firewall.rules :
    rule.name => {
      name        = rule.name
      direction   = rule.direction
      priority    = rule.priority
      source_ranges = rule.source_ranges
      target_tags = rule.target_tags
    }
  }
}

output "service_account_email" {
  description = "Email of the security scanner service account"
  value       = google_service_account.security_scanner.email
}

output "service_account_name" {
  description = "Name of the security scanner service account"
  value       = google_service_account.security_scanner.name
}

output "kms_key_ring_name" {
  description = "Name of the KMS key ring"
  value       = google_kms_key_ring.main.name
}

output "kms_key_ring_id" {
  description = "ID of the KMS key ring"
  value       = google_kms_key_ring.main.id
}

output "kms_crypto_key_name" {
  description = "Name of the general encryption crypto key"
  value       = google_kms_crypto_key.general.name
}

output "kms_crypto_key_id" {
  description = "ID of the general encryption crypto key"
  value       = google_kms_crypto_key.general.id
}

output "enabled_services" {
  description = "List of enabled GCP services"
  value       = keys(google_project_service.services)
}

output "flow_logs_enabled" {
  description = "Whether VPC Flow Logs are enabled"
  value       = var.enable_flow_logs
}

output "deployment_region" {
  description = "The deployment region"
  value       = var.region
}

output "deployment_zone" {
  description = "The deployment zone"
  value       = var.zone
}

output "environment_info" {
  description = "Information about the GCP environment"
  value = {
    project_id    = google_project.main.project_id
    project_name  = google_project.main.name
    environment   = var.environment
    region        = var.region
    zone          = var.zone
    network_name  = google_compute_network.main.name
    subnet_name   = google_compute_subnetwork.main.name
    deployed_at   = timestamp()
  }
}