# 1. ADK Agent Engine Staging Bucket
resource "google_storage_bucket" "adk_staging" {
  project                     = var.project_id
  name                        = "cymbal_cyber_adk_staging_bucket_${var.project_id}"
  location                    = var.region
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  force_destroy               = true

  versioning {
    enabled = true
  }

  depends_on = [google_project_service.required]
}

# 2. SOC Escalations Bucket (Message Queue for Human Handoff)
resource "google_storage_bucket" "escalations" {
  project                     = var.project_id
  name                        = "cymbal-cyber-adk-escalations-bucket_${var.project_id}"
  location                    = var.region
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  force_destroy               = true

  cors {
    origin          = ["*"]
    method          = ["GET", "HEAD"]
    response_header = ["*"]
    max_age_seconds = 3600
  }

  depends_on = [google_project_service.required]
}

# 3. Screenshots Bucket for Multi-Modal Visual Analysis
resource "google_storage_bucket" "screenshots" {
  project                     = var.project_id
  name                        = "cymbal-cyber-screenshots_${var.project_id}"
  location                    = var.region
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  force_destroy               = true

  cors {
    origin          = ["*"]
    method          = ["GET", "HEAD"]
    response_header = ["*"]
    max_age_seconds = 3600
  }

  depends_on = [google_project_service.required]
}

# 4. Raw Synthetic Logs Bucket
resource "google_storage_bucket" "raw_logs" {
  project                     = var.project_id
  name                        = "cymbal-cyber-raw-logs_${var.project_id}"
  location                    = var.region
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  force_destroy               = true

  lifecycle_rule {
    action {
      type = "Delete"
    }
    condition {
      age = 30
    }
  }

  depends_on = [google_project_service.required]
}
