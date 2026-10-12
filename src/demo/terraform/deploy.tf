# ==============================================================================
# MISSING DEMO INFRASTRUCTURE (Cloud Run Agent, Dataflow, Continuous Query)
# ==============================================================================

locals {
  # Deterministic Cloud Run endpoint URL matching Google Cloud Run URL convention
  agent_service_url   = "https://cymbal-cyber-adk-agent-${data.google_project.project.number}.${var.region}.run.app"
  agent_push_endpoint = var.agent_push_endpoint != "" ? var.agent_push_endpoint : "${local.agent_service_url}/apps/adk_agent/trigger/pubsub"
}

# Dedicated Artifact Registry repository for container images (replaces deprecated Container Registry gcr.io)
resource "google_artifact_registry_repository" "agent_repo" {
  project       = var.project_id
  location      = var.region
  repository_id = "cymbal-cyber"
  description   = "Docker repository for Cymbal Cyber agent and detection container images"
  format        = "DOCKER"

  depends_on = [google_project_service.required]
}

# 1. Cloud Run Deployment for ADK Multi-Agent Team
# We deploy the ADK Agent to Cloud Run to natively support Pub/Sub OIDC push tokens
# without requiring an intermediary token-exchange relay service.
resource "google_cloud_run_v2_service" "adk_agent_service" {
  name                = "cymbal-cyber-adk-agent"
  location            = var.region
  project             = var.project_id
  ingress             = "INGRESS_TRAFFIC_ALL"
  deletion_protection = false

  template {
    timeout         = "600s"
    service_account = google_service_account.agent_sa.email

    scaling {
      min_instance_count = 0
      max_instance_count = 3
    }

    containers {
      image = "us-docker.pkg.dev/cloudrun/container/hello" # Placeholder until agents-cli deploy
      resources {
        limits = {
          cpu    = "1"
          memory = "4Gi"
        }
      }
      env {
        name  = "GOOGLE_CLOUD_PROJECT"
        value = var.project_id
      }
      env {
        name  = "LOCAL_MODE"
        value = "false"
      }
      env {
        name  = "GCS_SIGNER_SA"
        value = google_service_account.agent_sa.email
      }
      env {
        name  = "EXPECTED_OIDC_AUDIENCE"
        value = local.agent_push_endpoint
      }
      env {
        name  = "EXPECTED_INVOKER_EMAIL"
        value = google_service_account.invoker_sa.email
      }
    }
  }

  lifecycle {
    ignore_changes = [
      template[0].containers[0].image,
      client,
      client_version,
    ]
  }

  depends_on = [google_project_service.required]
}

# Allow Pub/Sub Invoker SA to invoke the Cloud Run Agent Service
resource "google_cloud_run_v2_service_iam_member" "agent_invoker" {
  name     = google_cloud_run_v2_service.adk_agent_service.name
  location = google_cloud_run_v2_service.adk_agent_service.location
  project  = google_cloud_run_v2_service.adk_agent_service.project
  role     = "roles/run.invoker"
  member   = "serviceAccount:${google_service_account.invoker_sa.email}"
}

# 2. BigQuery Continuous Query Infrastructure (Gated behind enable_continuous_query)
# BigQuery Continuous Queries require an Enterprise Edition slot reservation (billed 24/7).
# When enable_continuous_query is false (default), the background threat_scanner.py polling
# daemon serves as the zero-reservation, cost-free trigger path.
resource "google_bigquery_reservation" "continuous_query_reservation" {
  count             = var.enable_continuous_query ? 1 : 0
  project           = var.project_id
  location          = var.bigquery_location
  name              = "cymbal-cyber-continuous-reservation"
  slot_capacity     = 100
  edition           = "ENTERPRISE"
  ignore_idle_slots = false

  depends_on = [google_project_service.required]
}

resource "google_bigquery_reservation_assignment" "continuous_query_assignment" {
  count       = var.enable_continuous_query ? 1 : 0
  project     = var.project_id
  location    = var.bigquery_location
  reservation = google_bigquery_reservation.continuous_query_reservation[0].name
  job_type    = "CONTINUOUS"
  assignee    = "projects/${var.project_id}"

  depends_on = [google_bigquery_reservation.continuous_query_reservation]
}

# 3. Dataflow Streaming Ingestion Pipeline (Optional, gated behind enable_dataflow_streaming)
# Default ingestion uses zero-compute Pub/Sub -> BigQuery subscriptions (see pubsub.tf).
# For live demos, prefer the on-demand launcher: scripts/run_dataflow_demo.sh
resource "google_pubsub_subscription" "raw_logs_dataflow_sub" {
  count                      = var.enable_dataflow_streaming ? 1 : 0
  project                    = var.project_id
  name                       = "raw_logs_dataflow_sub"
  topic                      = google_pubsub_topic.raw_logs_topic.name
  ack_deadline_seconds       = 300
  message_retention_duration = "86400s" # 24 hours
}

resource "google_pubsub_subscription_iam_member" "dataflow_raw_sub_subscriber" {
  count        = var.enable_dataflow_streaming ? 1 : 0
  project      = var.project_id
  subscription = google_pubsub_subscription.raw_logs_dataflow_sub[0].name
  role         = "roles/pubsub.subscriber"
  member       = "serviceAccount:${google_service_account.dataflow_sa[0].email}"
}

resource "google_dataflow_job" "pubsub_to_bigquery" {
  count                 = var.enable_dataflow_streaming ? 1 : 0
  project               = var.project_id
  region                = var.region
  name                  = "cymbal-cyber-ingestion-pipeline"
  template_gcs_path     = "gs://dataflow-templates/latest/PubSub_Subscription_to_BigQuery"
  temp_gcs_location     = "gs://${google_storage_bucket.adk_staging.name}/temp"
  service_account_email = google_service_account.dataflow_sa[0].email
  on_delete             = "cancel"
  max_workers           = 1

  parameters = {
    inputSubscription = google_pubsub_subscription.raw_logs_dataflow_sub[0].id
    outputTableSpec   = "${var.project_id}:${google_bigquery_dataset.cyber_dataset.dataset_id}.user_access_events"
  }

  depends_on = [
    google_project_service.required,
    google_project_iam_member.dataflow_project_bindings,
    google_storage_bucket.adk_staging,
    google_bigquery_table.user_access_events
  ]
}

# NOTE: The legacy "threat_scanner_cron" (Cloud Scheduler -> /apps/adk_agent/trigger/scan)
# has been retired. Detection now runs as the threat-detector Cloud Run Job, scheduled
# every 2 minutes in cloud_run.tf (google_cloud_scheduler_job.threat_detector_schedule).

# 4. Upload Seed Desktop Screenshots to GCS
locals {
  seed_screenshots = ["u.lewis.png", "l.taylor.png", "c.wilson.png"]
}

resource "google_storage_bucket_object" "seed_screenshots" {
  for_each = toset(local.seed_screenshots)
  name     = each.key
  source   = "${path.module}/../user_screenshots/${each.key}"
  bucket   = google_storage_bucket.screenshots.name
}

# 5. FinOps: Cost Control & Teardown Warnings
# BigQuery Continuous Queries require an Enterprise reservation and Dataflow streams bill continuously.
resource "google_billing_budget" "demo_budget" {
  count           = var.billing_account_id != "" ? 1 : 0
  billing_account = var.billing_account_id
  display_name    = "Cymbal Cyber Demo Cost Alert"

  budget_filter {
    projects = ["projects/${var.project_id}"]
  }

  amount {
    specified_amount {
      currency_code = "USD"
      units         = "100"
    }
  }

  threshold_rules {
    threshold_percent = 0.5
  }
  threshold_rules {
    threshold_percent = 0.9
  }
}
