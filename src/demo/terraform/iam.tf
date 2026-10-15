# ==============================================================================
# LEAST-PRIVILEGE WORKLOAD IDENTITY ARCHITECTURE (ONE IDENTITY PER WORKLOAD)
# ==============================================================================

# 1. Continuous Query Workload Service Account
# Role: Runs BigQuery Continuous Query stream processing and publishes alerts.
# Only exists with enable_continuous_query: an unused identity is still a credential.
resource "google_service_account" "continuous_query_sa" {
  count        = var.enable_continuous_query ? 1 : 0
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
  for_each = var.enable_continuous_query ? local.cq_project_roles : toset([])

  project = var.project_id
  role    = each.value
  member  = "serviceAccount:${google_service_account.continuous_query_sa[0].email}"
}

# Resource-level Pub/Sub publisher scoped strictly to alerts topic
resource "google_pubsub_topic_iam_member" "cq_alerts_publisher" {
  count   = var.enable_continuous_query ? 1 : 0
  project = var.project_id
  topic   = google_pubsub_topic.alerts_topic.name
  role    = "roles/pubsub.publisher"
  member  = "serviceAccount:${google_service_account.continuous_query_sa[0].email}"
}

# Resource-level BigQuery dataset READER access
resource "google_bigquery_dataset_access" "cq_dataset_reader" {
  count         = var.enable_continuous_query ? 1 : 0
  project       = var.project_id
  dataset_id    = google_bigquery_dataset.cyber_dataset.dataset_id
  role          = "READER"
  user_by_email = google_service_account.continuous_query_sa[0].email
}

# These resources were unconditional before; keep their state when enabled.
moved {
  from = google_service_account.continuous_query_sa
  to   = google_service_account.continuous_query_sa[0]
}

moved {
  from = google_pubsub_topic_iam_member.cq_alerts_publisher
  to   = google_pubsub_topic_iam_member.cq_alerts_publisher[0]
}

moved {
  from = google_bigquery_dataset_access.cq_dataset_reader
  to   = google_bigquery_dataset_access.cq_dataset_reader[0]
}


# 2. ADK Multi-Agent Runtime Service Account
# Role: Runs the agents (Gemini reasoning) and the Pub/Sub webhook. It holds no evidence
# reads and no ticket writes: every tool call, including the default-deny escalation,
# goes to the MCP tool service (2a), which it may only invoke. What it keeps is its own
# bookkeeping: alert status on `alerts` and the ADK analytics rows in `agent_events`.
resource "google_service_account" "agent_sa" {
  project      = var.project_id
  account_id   = var.agent_service_account_id
  display_name = "Cymbal Cyber ADK Multi-Agent Runtime SA"
  description  = "Runs the ADK agents and the Pub/Sub webhook; calls tools only through the MCP tool service."

  depends_on = [google_project_service.required]
}

# Project-level least-privilege roles for Agent Runtime SA. aiplatform.user serves the
# agents' Gemini calls through Vertex AI; bigquery.jobUser runs the alert status queries.
locals {
  agent_project_roles = toset([
    "roles/aiplatform.user",
    "roles/bigquery.jobUser",
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

moved {
  from = google_project_iam_member.agent_sa_bq_job_user
  to   = google_project_iam_member.agent_project_bindings["roles/bigquery.jobUser"]
}

# Table-level dataEditor scoped strictly to alerts (dedupe and status updates)
resource "google_bigquery_table_iam_member" "agent_alerts_editor" {
  project    = var.project_id
  dataset_id = google_bigquery_dataset.cyber_dataset.dataset_id
  table_id   = google_bigquery_table.alerts.table_id
  role       = "roles/bigquery.dataEditor"
  member     = "serviceAccount:${google_service_account.agent_sa.email}"
}

# Table-level dataEditor scoped strictly to agent_events (ADK analytics plugin rows and
# additive schema upgrades; the plugin's views are disabled)
resource "google_bigquery_table_iam_member" "agent_agent_events_editor" {
  project    = var.project_id
  dataset_id = google_bigquery_dataset.cyber_dataset.dataset_id
  table_id   = google_bigquery_table.agent_events.table_id
  role       = "roles/bigquery.dataEditor"
  member     = "serviceAccount:${google_service_account.agent_sa.email}"
}

# The agent's only path to evidence and tickets: invoking the MCP tool service.
resource "google_cloud_run_v2_service_iam_member" "agent_invokes_mcp" {
  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.mcp_server.name
  role     = "roles/run.invoker"
  member   = "serviceAccount:${google_service_account.agent_sa.email}"
}


# 2a. MCP Tool Service Account
# Role: Runs the MCP tool server (cloud_run.tf) and is the identity behind every tool:
# reads telemetry and screenshots, runs the Gemini vision check, signs screenshot URLs,
# and writes tickets. Only the agent SA may call it (Cloud Run invoker plus the server's
# own ID-token check), and the server exposes nine fixed operations, no free-form SQL.
resource "google_service_account" "mcp_sa" {
  project      = var.project_id
  account_id   = var.mcp_service_account_id
  display_name = "Cymbal Cyber MCP Tool Server SA"
  description  = "Identity of the MCP tool service: evidence reads, vision analysis, signed URLs and ticket writes."

  depends_on = [google_project_service.required]
}

locals {
  mcp_project_roles = toset([
    "roles/aiplatform.user",
    "roles/bigquery.jobUser",
    "roles/logging.logWriter",
    "roles/serviceusage.serviceUsageConsumer",
  ])
}

resource "google_project_iam_member" "mcp_project_bindings" {
  for_each = local.mcp_project_roles

  project = var.project_id
  role    = each.value
  member  = "serviceAccount:${google_service_account.mcp_sa.email}"
}

# Dataset READER: event tables, the screenshots view and the ticket views the tools query.
# Uses google_bigquery_dataset_access like every other dataset grant here; do not mix in
# google_bigquery_dataset_iam_* resources.
resource "google_bigquery_dataset_access" "mcp_dataset_reader" {
  project       = var.project_id
  dataset_id    = google_bigquery_dataset.cyber_dataset.dataset_id
  role          = "READER"
  user_by_email = google_service_account.mcp_sa.email
}

# Table-level dataEditor scoped strictly to soc_tickets (ticket tools)
resource "google_bigquery_table_iam_member" "mcp_soc_tickets_editor" {
  project    = var.project_id
  dataset_id = google_bigquery_dataset.cyber_dataset.dataset_id
  table_id   = google_bigquery_table.soc_tickets.table_id
  role       = "roles/bigquery.dataEditor"
  member     = "serviceAccount:${google_service_account.mcp_sa.email}"
}

# Table-level dataEditor scoped strictly to adk_threat_assessment (verdict rows)
resource "google_bigquery_table_iam_member" "mcp_adk_threat_assessment_editor" {
  project    = var.project_id
  dataset_id = google_bigquery_dataset.cyber_dataset.dataset_id
  table_id   = google_bigquery_table.adk_threat_assessment.table_id
  role       = "roles/bigquery.dataEditor"
  member     = "serviceAccount:${google_service_account.mcp_sa.email}"
}

# Screenshots bucket: READ-ONLY (vision analysis)
resource "google_storage_bucket_iam_member" "mcp_screenshots_reader" {
  bucket = google_storage_bucket.screenshots.name
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:${google_service_account.mcp_sa.email}"
}

# Screenshots bucket: READ-ONLY for the BigQuery connection behind the
# user_screenshots_objects object table.
resource "google_storage_bucket_iam_member" "screenshots_connection_reader" {
  bucket = google_storage_bucket.screenshots.name
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:${google_bigquery_connection.screenshots.cloud_resource[0].service_account_id}"
}

# Escalations bucket: WRITE/READ (escalation request files)
resource "google_storage_bucket_iam_member" "mcp_escalations_writer" {
  bucket = google_storage_bucket.escalations.name
  role   = "roles/storage.objectUser"
  member = "serviceAccount:${google_service_account.mcp_sa.email}"
}

# Self-token-creation scoped strictly to itself for keyless V4 signed URLs
resource "google_service_account_iam_member" "mcp_self_impersonation" {
  service_account_id = google_service_account.mcp_sa.name
  role               = "roles/iam.serviceAccountTokenCreator"
  member             = "serviceAccount:${google_service_account.mcp_sa.email}"
}


# 2b. SOC Console Service Account
# Role: Runs the Streamlit analyst console. Reads tickets and telemetry, records analyst
# verdicts, answers ticket questions through Vertex AI, and publishes demo telemetry to
# the raw-logs topic. Kept separate from the agent SA so the agent can never publish
# raw telemetry, the evidence it investigates.
resource "google_service_account" "soc_console_sa" {
  project      = var.project_id
  account_id   = var.console_service_account_id
  display_name = "Cymbal Cyber SOC Console SA"
  description  = "Runs the SOC analyst console and publishes demo telemetry to the raw-logs topic."

  depends_on = [google_project_service.required]
}

# bigquery.jobUser runs dashboard and ticket queries; aiplatform.user serves the
# "Ask the Agent" ticket assistant through Vertex AI.
locals {
  console_project_roles = toset([
    "roles/bigquery.jobUser",
    "roles/aiplatform.user",
    "roles/logging.logWriter",
    "roles/serviceusage.serviceUsageConsumer",
  ])
}

resource "google_project_iam_member" "console_project_bindings" {
  for_each = local.console_project_roles

  project = var.project_id
  role    = each.value
  member  = "serviceAccount:${google_service_account.soc_console_sa.email}"
}

# Dataset READER: tickets, alerts and event tables for the dashboard
resource "google_bigquery_dataset_access" "console_dataset_reader" {
  project       = var.project_id
  dataset_id    = google_bigquery_dataset.cyber_dataset.dataset_id
  role          = "READER"
  user_by_email = google_service_account.soc_console_sa.email
}

# Table-level dataEditor on soc_tickets (simulated tickets and analyst verdicts)
resource "google_bigquery_table_iam_member" "console_soc_tickets_editor" {
  project    = var.project_id
  dataset_id = google_bigquery_dataset.cyber_dataset.dataset_id
  table_id   = google_bigquery_table.soc_tickets.table_id
  role       = "roles/bigquery.dataEditor"
  member     = "serviceAccount:${google_service_account.soc_console_sa.email}"
}

# Table-level dataEditor on adk_threat_assessment (analyst verdict rows)
resource "google_bigquery_table_iam_member" "console_adk_threat_assessment_editor" {
  project    = var.project_id
  dataset_id = google_bigquery_dataset.cyber_dataset.dataset_id
  table_id   = google_bigquery_table.adk_threat_assessment.table_id
  role       = "roles/bigquery.dataEditor"
  member     = "serviceAccount:${google_service_account.soc_console_sa.email}"
}

# Escalations bucket: list, read, write and delete escalation request/response files
resource "google_storage_bucket_iam_member" "console_escalations_user" {
  bucket = google_storage_bucket.escalations.name
  role   = "roles/storage.objectUser"
  member = "serviceAccount:${google_service_account.soc_console_sa.email}"
}

# Publisher scoped strictly to the raw-logs topic ("Inject scenario" / "Stream logs")
resource "google_pubsub_topic_iam_member" "console_raw_logs_publisher" {
  project = var.project_id
  topic   = google_pubsub_topic.raw_logs_topic.name
  role    = "roles/pubsub.publisher"
  member  = "serviceAccount:${google_service_account.soc_console_sa.email}"
}


# 3. Pub/Sub Push Identity
# Role: Signs the OIDC token on Pub/Sub pushes to the agent webhook, which accepts only
# this identity (EXPECTED_INVOKER_EMAIL). It can invoke nothing else.
resource "google_service_account" "invoker_sa" {
  project      = var.project_id
  account_id   = var.invoker_service_account_id
  display_name = "Cymbal Cyber Pub/Sub Push Invoker SA"
  description  = "Signs Pub/Sub push requests to the agent webhook; invoker on that service only."

  depends_on = [google_project_service.required]
}

# 3b. Cloud Scheduler Identity
# Role: Starts the threat detector job every 5 minutes. Kept apart from the push identity
# so a token for one trust path cannot be used on the other.
resource "google_service_account" "scheduler_sa" {
  project      = var.project_id
  account_id   = var.scheduler_service_account_id
  display_name = "Cymbal Cyber Threat Detector Scheduler SA"
  description  = "Cloud Scheduler identity that runs the threat-detector Cloud Run job."

  depends_on = [google_project_service.required]
}

# 3c. Console Access Identity (humans)
# Role: Analysts open the SOC console through `gcloud run services proxy` with an ID token
# minted for this account, audience = the console URL. User ID tokens from gcloud carry the
# OAuth client as audience, which Cloud Run can reject with 401. Invoker on the console only.
resource "google_service_account" "console_access_sa" {
  project      = var.project_id
  account_id   = var.console_access_service_account_id
  display_name = "SOC console access (humans)"
  description  = "Analysts impersonate this identity to open the SOC console; invoker on the console only."

  depends_on = [google_project_service.required]
}

# Allow Invoker SA to invoke the Cloud Run Agent Service (Pub/Sub push webhook)
resource "google_cloud_run_v2_service_iam_member" "agent_invoker" {
  name     = google_cloud_run_v2_service.adk_agent_service.name
  location = google_cloud_run_v2_service.adk_agent_service.location
  project  = google_cloud_run_v2_service.adk_agent_service.project
  role     = "roles/run.invoker"
  member   = "serviceAccount:${google_service_account.invoker_sa.email}"
}

# Allow deployer identity to invoke the Cloud Run Agent Service (the ADK web UI, when
# enable_adk_dev_ui is set)
resource "google_cloud_run_v2_service_iam_member" "agent_deployer_invoker" {
  count    = var.deployer_member != "" ? 1 : 0
  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.adk_agent_service.name
  role     = "roles/run.invoker"
  member   = var.deployer_member
}

# Allow the Scheduler SA to run the threat detector Cloud Run Job (5-minute trigger)
resource "google_cloud_run_v2_job_iam_member" "scheduler_invokes_detector" {
  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_job.threat_detector.name
  role     = "roles/run.invoker"
  member   = "serviceAccount:${google_service_account.scheduler_sa.email}"
}

# Allow deployer identity to invoke the SOC Console
resource "google_cloud_run_v2_service_iam_member" "soc_console_deployer_invoker" {
  count    = var.deployer_member != "" ? 1 : 0
  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.soc_console_service.name
  role     = "roles/run.invoker"
  member   = var.deployer_member
}


# Allow the console access identity to invoke the SOC Console
resource "google_cloud_run_v2_service_iam_member" "soc_console_access_invoker" {
  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.soc_console_service.name
  role     = "roles/run.invoker"
  member   = "serviceAccount:${google_service_account.console_access_sa.email}"
}

# Allow the deployer and listed analysts to mint ID tokens as the console access identity
resource "google_service_account_iam_member" "console_access_token_creators" {
  for_each           = toset(compact(concat([var.deployer_member], var.console_access_members)))
  service_account_id = google_service_account.console_access_sa.name
  role               = "roles/iam.serviceAccountTokenCreator"
  member             = each.value
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

resource "google_project_iam_member" "detector_sa_bq_job_user" {
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

# The detector only reads alerts_dead_letter; dataset READER above covers it.

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

# 6. BigQuery Service Agent KMS IAM (conditioned on CMEK configuration)
resource "google_project_service_identity" "bigquery_sa" {
  count    = var.kms_key_name != "" ? 1 : 0
  provider = google-beta
  project  = var.project_id
  service  = "bigquery.googleapis.com"
}

resource "google_kms_crypto_key_iam_member" "bigquery_kms_encrypter_decrypter" {
  count         = var.kms_key_name != "" ? 1 : 0
  crypto_key_id = var.kms_key_name
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:${google_project_service_identity.bigquery_sa[0].email}"
}

# ==============================================================================
# 7. Artifact Registry Build & Push Workload IAM (Container Image Deployment)
# ==============================================================================
# Grant Compute Engine default service account writer permissions (Cloud Build modern default)
resource "google_artifact_registry_repository_iam_member" "compute_sa_writer" {
  project    = var.project_id
  location   = var.region
  repository = google_artifact_registry_repository.agent_repo.name
  role       = "roles/artifactregistry.writer"
  member     = "serviceAccount:${data.google_project.project.number}-compute@developer.gserviceaccount.com"
}

# Grant the Compute Engine default service account (the Cloud Build identity) read access
# to the build source bucket only. A project-wide objectViewer would also expose ticket,
# screenshot and Terraform state buckets. deploy_cloud.sh creates this bucket and stages
# every build's source there.
resource "google_storage_bucket_iam_member" "compute_sa_build_source_viewer" {
  bucket = "${var.project_id}_cloudbuild"
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:${data.google_project.project.number}-compute@developer.gserviceaccount.com"
}

# Grant Compute Engine default service account logging writer permissions to publish build logs
resource "google_project_iam_member" "compute_sa_log_writer" {
  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${data.google_project.project.number}-compute@developer.gserviceaccount.com"
}

# Grant Cloud Build service account writer permissions on the repository
resource "google_artifact_registry_repository_iam_member" "cloudbuild_sa_writer" {
  project    = var.project_id
  location   = var.region
  repository = google_artifact_registry_repository.agent_repo.name
  role       = "roles/artifactregistry.writer"
  member     = "serviceAccount:${data.google_project.project.number}@cloudbuild.gserviceaccount.com"
}

# Grant deploying user or CI/CD identity writer permissions to push container images
resource "google_artifact_registry_repository_iam_member" "deployer_writer" {
  count      = var.deployer_member != "" ? 1 : 0
  project    = var.project_id
  location   = var.region
  repository = google_artifact_registry_repository.agent_repo.name
  role       = "roles/artifactregistry.writer"
  member     = var.deployer_member
}


