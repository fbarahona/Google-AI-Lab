# ==============================================================================
# LEAST-PRIVILEGE WORKLOAD IDENTITY ARCHITECTURE (3 SCOPED IDENTITIES)
# ==============================================================================

# 1. Continuous Query Workload Service Account
# Role: Runs BigQuery Continuous Query stream processing and publishes alerts.
resource "google_service_account" "continuous_query_sa" {
  project      = var.project_id
  account_id   = var.service_account_id
  display_name = "Cymbal Cyber Continuous Query SA"
  description  = "Headless identity running BigQuery continuous streaming queries."

  depends_on = [google_project_service.required]
}

# Project-level least-privilege roles for Continuous Query SA
locals {
  cq_project_roles = toset([
    "roles/bigquery.jobUser",
    "roles/logging.logWriter",
    "roles/serviceusage.serviceUsageConsumer",
  ])
}

resource "google_project_iam_member" "cq_project_bindings" {
  for_each = local.cq_project_roles

  project = var.project_id
  role    = each.value
  member  = "serviceAccount:${google_service_account.continuous_query_sa.email}"
}

# Resource-level Pub/Sub publisher scoped strictly to alerts topic
resource "google_pubsub_topic_iam_member" "cq_alerts_publisher" {
  project = var.project_id
  topic   = google_pubsub_topic.alerts_topic.name
  role    = "roles/pubsub.publisher"
  member  = "serviceAccount:${google_service_account.continuous_query_sa.email}"
}

# Resource-level BigQuery dataset READER access
resource "google_bigquery_dataset_access" "cq_dataset_reader" {
  project       = var.project_id
  dataset_id    = google_bigquery_dataset.cyber_dataset.dataset_id
  role          = "READER"
  user_by_email = google_service_account.continuous_query_sa.email
}


# 2. ADK Multi-Agent Runtime Service Account
# Role: Runs multi-agent investigations, background anomaly scanner, and SOC ticket dispatch.
resource "google_service_account" "agent_sa" {
  project      = var.project_id
  account_id   = var.agent_service_account_id
  display_name = "Cymbal Cyber ADK Multi-Agent Runtime SA"
  description  = "Executes multi-agent forensic investigations, threat scanner, and SOC ticket dispatch."

  depends_on = [google_project_service.required]
}

# Project-level least-privilege roles for Agent Runtime SA
locals {
  agent_project_roles = toset([
    "roles/bigquery.jobUser",
    "roles/bigquery.connectionUser",
    "roles/aiplatform.user",
    "roles/logging.logWriter",
    "roles/serviceusage.serviceUsageConsumer",
  ])
}

resource "google_project_iam_member" "agent_project_bindings" {
  for_each = local.agent_project_roles

  project = var.project_id
  role    = each.value
  member  = "serviceAccount:${google_service_account.agent_sa.email}"
}

# Resource-level BigQuery dataset WRITER access (inserts into soc_tickets & adk_threat_assessment)
resource "google_bigquery_dataset_access" "agent_dataset_writer" {
  project       = var.project_id
  dataset_id    = google_bigquery_dataset.cyber_dataset.dataset_id
  role          = "WRITER"
  user_by_email = google_service_account.agent_sa.email
}

# Resource-level GCS bucket bindings:
# 1) Screenshots bucket: READ-ONLY (objectViewer)
resource "google_storage_bucket_iam_member" "agent_screenshots_reader" {
  bucket = google_storage_bucket.screenshots.name
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:${google_service_account.agent_sa.email}"
}

# 2) Escalations bucket: WRITE/READ (objectUser)
resource "google_storage_bucket_iam_member" "agent_escalations_writer" {
  bucket = google_storage_bucket.escalations.name
  role   = "roles/storage.objectUser"
  member = "serviceAccount:${google_service_account.agent_sa.email}"
}

# 3) Staging bucket: WRITE/READ (objectUser)
resource "google_storage_bucket_iam_member" "agent_staging_writer" {
  bucket = google_storage_bucket.adk_staging.name
  role   = "roles/storage.objectUser"
  member = "serviceAccount:${google_service_account.agent_sa.email}"
}

# Self-token-creation scoped strictly to itself for keyless V4 signed URLs
resource "google_service_account_iam_member" "agent_self_impersonation" {
  service_account_id = google_service_account.agent_sa.name
  role               = "roles/iam.serviceAccountTokenCreator"
  member             = "serviceAccount:${google_service_account.agent_sa.email}"
}


# 3. Pub/Sub Push Subscription Invoker Service Account
# Role: Dedicated identity used by Pub/Sub push subscription to authenticate to Agent Runtime endpoint.
resource "google_service_account" "invoker_sa" {
  project      = var.project_id
  account_id   = var.invoker_service_account_id
  display_name = "Cymbal Cyber Pub/Sub Invoker SA"
  description  = "Dedicated identity used by Pub/Sub push subscription to authenticate to Agent Runtime endpoint."

  depends_on = [google_project_service.required]
}
