# Generate a random project ID if not provided
resource "random_id" "project" {
  count       = var.project_id == null ? 1 : 0
  byte_length = 8
  prefix      = "${var.project_name}-${var.environment}-"
}

# GCP Project
resource "google_project" "main" {
  name            = "${var.project_name} ${title(var.environment)}"
  project_id      = var.project_id != null ? var.project_id : random_id.project[0].hex
  billing_account = var.billing_account
  org_id          = var.org_id

  labels = merge(var.tags, {
    environment = var.environment
    project     = var.project_name
    autodelete  = var.environment == "ephemeral" ? "true" : "false"
  })

  # Required services will be enabled in a separate resource
  auto_create_network = false
}

# Enable essential services
resource "google_project_service" "services" {
  for_each = toset([
    "compute.googleapis.com",
    "container.googleapis.com",
    "logging.googleapis.com",
    "monitoring.googleapis.com",
    "iam.googleapis.com",
    "cloudresourcemanager.googleapis.com",
    "serviceusage.googleapis.com",
    "storage.googleapis.com",
    "cloudkms.googleapis.com"
  ])

  project = google_project.main.project_id
  service = each.key

  # Do not disable the service on destroy
  disable_on_destroy = false

  depends_on = [google_project.main]
}

# VPC Network
resource "google_compute_network" "main" {
  name                    = var.network_name
  project                 = google_project.main.project_id
  auto_create_subnetworks = var.auto_create_subnetworks
  routing_mode            = var.routing_mode

  description = "VPC network for CloudGuardStack ${var.environment} environment"

  depends_on = [google_project_service.services]
}

# Subnet
resource "google_compute_subnetwork" "main" {
  name          = "${var.project_name}-subnet"
  project       = google_project.main.project_id
  ip_cidr_range = var.subnet_cidr
  region        = var.region
  network       = google_compute_network.main.id

  dynamic "secondary_ip_range" {
    for_each = var.subnet_secondary_ranges[google_compute_subnetwork.main.name]
    content {
      range_name    = secondary_ip_range.value.range_name
      ip_cidr_range = secondary_ip_range.value.ip_cidr_range
    }
  }

  description = "Primary subnet for CloudGuardStack ${var.environment}"

  depends_on = [google_compute_network.main]
}

# Firewall Rules
resource "google_compute_firewall" "rules" {
  for_each = { for rule in var.firewall_rules : rule.name => rule }

  name        = each.value.name
  project     = google_project.main.project_id
  network     = google_compute_network.main.name
  description = each.value.description
  direction   = each.value.direction
  priority    = each.value.priority

  source_ranges = each.value.direction == "INGRESS" ? each.value.ranges : null
  target_tags   = each.value.target_tags

  dynamic "allow" {
    for_each = each.value.allow
    content {
      protocol = allow.value.protocol
      ports    = allow.value.ports
    }
  }

  dynamic "deny" {
    for_each = each.value.deny
    content {
      protocol = deny.value.protocol
      ports    = deny.value.ports
    }
  }

  dynamic "log_config" {
    for_each = each.value.log_config != null ? [each.value.log_config] : []
    content {
      metadata = log_config.value.metadata
    }
  }

  depends_on = [google_compute_network.main]
}

# VPC Flow Logs
resource "google_compute_subnetwork" "flow_logs" {
  count = var.enable_flow_logs ? 1 : 0

  name                     = google_compute_subnetwork.main.name
  project                  = google_project.main.project_id
  ip_cidr_range            = google_compute_subnetwork.main.ip_cidr_range
  region                   = google_compute_subnetwork.main.region
  network                  = google_compute_network.main.id
  private_ip_google_access = true

  log_config {
    aggregation_interval = var.flow_logs_aggregation_interval
    flow_sampling        = 0.5
    metadata             = "INCLUDE_ALL_METADATA"
  }

  depends_on = [google_compute_subnetwork.main]
}

# Service Account for security scanning
resource "google_service_account" "security_scanner" {
  account_id   = "${var.project_name}-security-scanner"
  project      = google_project.main.project_id
  display_name = "CloudGuardStack Security Scanner Service Account"
  description  = "Service account for security scanning and auditing"

  depends_on = [google_project_service.services]
}

# IAM roles for security scanner
resource "google_project_iam_member" "security_scanner_roles" {
  for_each = toset([
    "roles/viewer",
    "roles/logging.viewer",
    "roles/monitoring.viewer",
    "roles/iam.securityReviewer",
    "roles/storage.objectViewer"
  ])

  project = google_project.main.project_id
  role    = each.key
  member  = "serviceAccount:${google_service_account.security_scanner.email}"

  depends_on = [google_service_account.security_scanner]
}

# Cloud KMS Key Ring for encryption
resource "google_kms_key_ring" "main" {
  name     = "${var.project_name}-keyring"
  project  = google_project.main.project_id
  location = var.region

  depends_on = [google_project_service.services]
}

# Cloud KMS Crypto Key for general encryption
resource "google_kms_crypto_key" "general" {
  name            = "general-encryption"
  key_ring        = google_kms_key_ring.main.id
  rotation_period = "7776000s" # 90 days

  version_template {
    algorithm        = "GOOGLE_SYMMETRIC_ENCRYPTION"
    protection_level = "SOFTWARE"
  }

  depends_on = [google_kms_key_ring.main]
}