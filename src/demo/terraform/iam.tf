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

# Table-level least-privilege dataEditor scoped strictly to alerts (status updates)
resource "google_bigquery_table_iam_member" "agent_alerts_editor" {
  project    = var.project_id
  dataset_id = google_bigquery_dataset.cyber_dataset.dataset_id
  table_id   = google_bigquery_table.alerts.table_id
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


# 4. Dataflow Pipeline Workload Service Account (Optional on-demand)
# Role: Executes Dataflow streaming ingestion from Pub/Sub raw logs to BigQuery.
resource "google_service_account" "dataflow_sa" {
  count        = var.enable_dataflow_streaming ? 1 : 0
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
  for_each = var.enable_dataflow_streaming ? local.dataflow_project_roles : toset([])

  project = var.project_id
  role    = each.value
  member  = "serviceAccount:${google_service_account.dataflow_sa[0].email}"
}

# BigQuery dataset READER access (metadata and schema resolution)
resource "google_bigquery_dataset_access" "dataflow_dataset_reader" {
  count         = var.enable_dataflow_streaming ? 1 : 0
  project       = var.project_id
  dataset_id    = google_bigquery_dataset.cyber_dataset.dataset_id
  role          = "READER"
  user_by_email = google_service_account.dataflow_sa[0].email
}

# Table-level least-privilege dataEditor scoped strictly to user_access_events
resource "google_bigquery_table_iam_member" "dataflow_user_access_editor" {
  count      = var.enable_dataflow_streaming ? 1 : 0
  project    = var.project_id
  dataset_id = google_bigquery_dataset.cyber_dataset.dataset_id
  table_id   = google_bigquery_table.user_access_events.table_id
  role       = "roles/bigquery.dataEditor"
  member     = "serviceAccount:${google_service_account.dataflow_sa[0].email}"
}

# Table-level least-privilege dataEditor scoped strictly to network_events
resource "google_bigquery_table_iam_member" "dataflow_network_events_editor" {
  count      = var.enable_dataflow_streaming ? 1 : 0
  project    = var.project_id
  dataset_id = google_bigquery_dataset.cyber_dataset.dataset_id
  table_id   = google_bigquery_table.network_events.table_id
  role       = "roles/bigquery.dataEditor"
  member     = "serviceAccount:${google_service_account.dataflow_sa[0].email}"
}

# Staging bucket objectAdmin access for Dataflow pipeline binaries and temporary files
resource "google_storage_bucket_iam_member" "dataflow_staging_admin" {
  count  = var.enable_dataflow_streaming ? 1 : 0
  bucket = google_storage_bucket.adk_staging.name
  role   = "roles/storage.objectAdmin"
  member = "serviceAccount:${google_service_account.dataflow_sa[0].email}"
}

# 4. Pub/Sub Google-Managed Service Agent IAM
# Required for Pub/Sub BigQuery subscriptions and DLQ dead-letter publisher
data "google_project" "project" {
  project_id = var.project_id
}

resource "google_project_service_identity" "pubsub_sa" {
  provider = google-beta
  project  = var.project_id
  service  = "pubsub.googleapis.com"
}

# Pub/Sub SA needs publisher on the DLQ topic
resource "google_pubsub_topic_iam_member" "pubsub_sa_dlq_publisher" {
  project    = var.project_id
  topic      = google_pubsub_topic.alerts_dlq_topic.name
  role       = "roles/pubsub.publisher"
  member     = "serviceAccount:${google_project_service_identity.pubsub_sa.email}"
  depends_on = [google_project_service_identity.pubsub_sa]
}

# Pub/Sub SA needs publisher on the raw events DLQ topic
resource "google_pubsub_topic_iam_member" "pubsub_agent_raw_dlq_publisher" {
  project    = var.project_id
  topic      = google_pubsub_topic.raw_events_dlq.name
  role       = "roles/pubsub.publisher"
  member     = "serviceAccount:${google_project_service_identity.pubsub_sa.email}"
  depends_on = [google_project_service_identity.pubsub_sa]
}

# Pub/Sub SA needs subscriber on the alerts push subscription
resource "google_pubsub_subscription_iam_member" "pubsub_sa_alerts_subscriber" {
  project      = var.project_id
  subscription = google_pubsub_subscription.adk_agent_trigger.name
  role         = "roles/pubsub.subscriber"
  member       = "serviceAccount:${google_project_service_identity.pubsub_sa.email}"
  depends_on   = [google_project_service_identity.pubsub_sa]
}

# Pub/Sub SA needs subscriber on raw access events BQ subscription for dead-letter forwarding
resource "google_pubsub_subscription_iam_member" "pubsub_sa_raw_access_subscriber" {
  project      = var.project_id
  subscription = google_pubsub_subscription.raw_access_to_bq.name
  role         = "roles/pubsub.subscriber"
  member       = "serviceAccount:${google_project_service_identity.pubsub_sa.email}"
  depends_on   = [google_project_service_identity.pubsub_sa]
}

# Pub/Sub SA needs subscriber on raw network events BQ subscription for dead-letter forwarding
resource "google_pubsub_subscription_iam_member" "pubsub_sa_raw_network_subscriber" {
  project      = var.project_id
  subscription = google_pubsub_subscription.raw_network_to_bq.name
  role         = "roles/pubsub.subscriber"
  member       = "serviceAccount:${google_project_service_identity.pubsub_sa.email}"
  depends_on   = [google_project_service_identity.pubsub_sa]
}

# Least-privilege table-level dataEditor scoped strictly to the three tables written by Pub/Sub subscriptions
resource "google_bigquery_table_iam_member" "pubsub_sa_access_events_editor" {
  project    = var.project_id
  dataset_id = google_bigquery_dataset.cyber_dataset.dataset_id
  table_id   = google_bigquery_table.user_access_events.table_id
  role       = "roles/bigquery.dataEditor"
  member     = "serviceAccount:${google_project_service_identity.pubsub_sa.email}"
  depends_on = [google_project_service_identity.pubsub_sa]
}

resource "google_bigquery_table_iam_member" "pubsub_sa_network_events_editor" {
  project    = var.project_id
  dataset_id = google_bigquery_dataset.cyber_dataset.dataset_id
  table_id   = google_bigquery_table.network_events.table_id
  role       = "roles/bigquery.dataEditor"
  member     = "serviceAccount:${google_project_service_identity.pubsub_sa.email}"
  depends_on = [google_project_service_identity.pubsub_sa]
}

resource "google_bigquery_table_iam_member" "pubsub_sa_dlq_editor" {
  project    = var.project_id
  dataset_id = google_bigquery_dataset.cyber_dataset.dataset_id
  table_id   = google_bigquery_table.alerts_dead_letter.table_id
  role       = "roles/bigquery.dataEditor"
  member     = "serviceAccount:${google_project_service_identity.pubsub_sa.email}"
  depends_on = [google_project_service_identity.pubsub_sa]
}

# 5. Dedicated Threat Detector Workload Service Account (Cloud Run Job)
resource "google_service_account" "detector_sa" {
  project      = var.project_id
  account_id   = "threat-detector-job-sa"
  display_name = "Cymbal Cyber Scheduled Threat Detector Job SA"
  description  = "Executes scheduled micro-batch queries and publishes detected alerts to cymbal_cyber_alerts."

  depends_on = [google_project_service.required]
}

resource "google_project_iam_member" "detector_job_user" {
  project = var.project_id
  role    = "roles/bigquery.jobUser"
  member  = "serviceAccount:${google_service_account.detector_sa.email}"
}

resource "google_bigquery_dataset_access" "detector_dataset_reader" {
  project       = var.project_id
  dataset_id    = google_bigquery_dataset.cyber_dataset.dataset_id
  role          = "READER"
  user_by_email = google_service_account.detector_sa.email
}

resource "google_bigquery_table_iam_member" "detector_alerts_editor" {
  project    = var.project_id
  dataset_id = google_bigquery_dataset.cyber_dataset.dataset_id
  table_id   = google_bigquery_table.alerts.table_id
  role       = "roles/bigquery.dataEditor"
  member     = "serviceAccount:${google_service_account.detector_sa.email}"
}

resource "google_bigquery_table_iam_member" "detector_dlq_editor" {
  project    = var.project_id
  dataset_id = google_bigquery_dataset.cyber_dataset.dataset_id
  table_id   = google_bigquery_table.alerts_dead_letter.table_id
  role       = "roles/bigquery.dataEditor"
  member     = "serviceAccount:${google_service_account.detector_sa.email}"
}

resource "google_bigquery_table_iam_member" "detector_soc_tickets_editor" {
  project    = var.project_id
  dataset_id = google_bigquery_dataset.cyber_dataset.dataset_id
  table_id   = google_bigquery_table.soc_tickets.table_id
  role       = "roles/bigquery.dataEditor"
  member     = "serviceAccount:${google_service_account.detector_sa.email}"
}

resource "google_pubsub_topic_iam_member" "detector_alerts_publisher" {
  project = var.project_id
  topic   = google_pubsub_topic.alerts_topic.name
  role    = "roles/pubsub.publisher"
  member  = "serviceAccount:${google_service_account.detector_sa.email}"
}

