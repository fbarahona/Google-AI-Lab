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

# Resource-level BigQuery dataset READER access (queries tables & UDFs)
resource "google_bigquery_dataset_access" "agent_dataset_reader" {
  project       = var.project_id
  dataset_id    = google_bigquery_dataset.cyber_dataset.dataset_id
  role          = "READER"
  user_by_email = google_service_account.agent_sa.email
}

# Table-level least-privilege dataEditor scoped strictly to soc_tickets
resource "google_bigquery_table_iam_member" "agent_soc_tickets_editor" {
  project    = var.project_id
  dataset_id = google_bigquery_dataset.cyber_dataset.dataset_id
  table_id   = google_bigquery_table.soc_tickets.table_id
  role       = "roles/bigquery.dataEditor"
  member     = "serviceAccount:${google_service_account.agent_sa.email}"
}

# Table-level least-privilege dataEditor scoped strictly to adk_threat_assessment
resource "google_bigquery_table_iam_member" "agent_adk_threat_assessment_editor" {
  project    = var.project_id
  dataset_id = google_bigquery_dataset.cyber_dataset.dataset_id
  table_id   = google_bigquery_table.adk_threat_assessment.table_id
  role       = "roles/bigquery.dataEditor"
  member     = "serviceAccount:${google_service_account.agent_sa.email}"
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


# 4. Dataflow Pipeline Workload Service Account
# Role: Executes Dataflow streaming ingestion from Pub/Sub raw logs to BigQuery.
resource "google_service_account" "dataflow_sa" {
  project      = var.project_id
  account_id   = var.dataflow_service_account_id
  display_name = "Cymbal Cyber Dataflow Pipeline SA"
  description  = "Dedicated least-privilege identity running Dataflow streaming log ingestion."

  depends_on = [google_project_service.required]
}

locals {
  dataflow_project_roles = toset([
    "roles/dataflow.worker",
    "roles/bigquery.jobUser",
    "roles/logging.logWriter",
    "roles/serviceusage.serviceUsageConsumer",
  ])
}

resource "google_project_iam_member" "dataflow_project_bindings" {
  for_each = local.dataflow_project_roles

  project = var.project_id
  role    = each.value
  member  = "serviceAccount:${google_service_account.dataflow_sa.email}"
}

# Subscriber role on raw logs subscription
resource "google_pubsub_subscription_iam_member" "dataflow_raw_sub_subscriber" {
  project      = var.project_id
  subscription = google_pubsub_subscription.raw_logs_to_bq_sub.name
  role         = "roles/pubsub.subscriber"
  member       = "serviceAccount:${google_service_account.dataflow_sa.email}"
}

# BigQuery dataset READER access (metadata and schema resolution)
resource "google_bigquery_dataset_access" "dataflow_dataset_reader" {
  project       = var.project_id
  dataset_id    = google_bigquery_dataset.cyber_dataset.dataset_id
  role          = "READER"
  user_by_email = google_service_account.dataflow_sa.email
}

# Table-level least-privilege dataEditor scoped strictly to user_access_events
resource "google_bigquery_table_iam_member" "dataflow_user_access_editor" {
  project    = var.project_id
  dataset_id = google_bigquery_dataset.cyber_dataset.dataset_id
  table_id   = google_bigquery_table.user_access_events.table_id
  role       = "roles/bigquery.dataEditor"
  member     = "serviceAccount:${google_service_account.dataflow_sa.email}"
}

# Table-level least-privilege dataEditor scoped strictly to network_events
resource "google_bigquery_table_iam_member" "dataflow_network_events_editor" {
  project    = var.project_id
  dataset_id = google_bigquery_dataset.cyber_dataset.dataset_id
  table_id   = google_bigquery_table.network_events.table_id
  role       = "roles/bigquery.dataEditor"
  member     = "serviceAccount:${google_service_account.dataflow_sa.email}"
}

# Staging bucket objectAdmin access for Dataflow pipeline binaries and temporary files
resource "google_storage_bucket_iam_member" "dataflow_staging_admin" {
  bucket = google_storage_bucket.adk_staging.name
  role   = "roles/storage.objectAdmin"
  member = "serviceAccount:${google_service_account.dataflow_sa.email}"
}
