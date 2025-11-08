# Log Bucket for audit logs
resource "google_storage_bucket" "audit_logs" {
  name                        = "${var.project_name}-audit-logs-${var.project_id}"
  project                     = var.project_id
  location                    = var.region
  force_destroy               = var.environment == "ephemeral"
  uniform_bucket_level_access = true

  versioning {
    enabled = true
  }

  encryption {
    default_kms_key_name = var.kms_key_id
  }

  labels = merge(var.tags, {
    purpose = "audit-logs"
  })
}

# Log Sink for audit logs
resource "google_logging_project_sink" "audit_logs" {
  name        = "${var.project_name}-audit-sink"
  project     = var.project_id
  destination = "storage.googleapis.com/${google_storage_bucket.audit_logs.name}"
  filter      = var.audit_logs_filter

  unique_writer_identity = true
}

# IAM binding for log sink
resource "google_storage_bucket_iam_member" "log_sink_writer" {
  bucket = google_storage_bucket.audit_logs.name
  role   = "roles/storage.objectCreator"
  member = google_logging_project_sink.audit_logs.writer_identity
}

# Audit logging configuration
resource "google_project_iam_audit_config" "audit_logging" {
  count   = var.enable_audit_logs ? 1 : 0
  project = var.project_id

  service = "allServices"
  audit_log_config {
    log_type = "ADMIN_READ"
  }
  audit_log_config {
    log_type = "DATA_READ"
  }
  audit_log_config {
    log_type = "DATA_WRITE"
  }
}