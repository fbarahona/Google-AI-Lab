# ==============================================================================
# MISSING DEMO INFRASTRUCTURE (Cloud Run Agent, Dataflow, Continuous Query)
# ==============================================================================

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

# 3. Dataflow Streaming Ingestion Pipeline (Gated behind enable_dataflow_streaming)
# Reads from Pub/Sub cymbal_cyber_raw_logs and streams to BigQuery tables.
# Uses the classic subscription-based PubSub_Subscription_to_BigQuery template.
# Gated to false by default to prevent continuous compute worker charges (~$100-$300/mo).
resource "google_dataflow_job" "pubsub_to_bigquery" {
  count                 = var.enable_dataflow_streaming ? 1 : 0
  project               = var.project_id
  region                = var.region
  name                  = "cymbal-cyber-ingestion-pipeline"
  template_gcs_path     = "gs://dataflow-templates/latest/PubSub_Subscription_to_BigQuery"
  temp_gcs_location     = "gs://${google_storage_bucket.adk_staging.name}/temp"
  service_account_email = google_service_account.dataflow_sa.email
  on_delete             = "cancel"

  parameters = {
    inputSubscription = google_pubsub_subscription.raw_logs_to_bq_sub.id
    outputTableSpec   = "${var.project_id}:${google_bigquery_dataset.cyber_dataset.dataset_id}.user_access_events"
  }

  depends_on = [
    google_project_service.required,
    google_service_account.dataflow_sa,
    google_project_iam_member.dataflow_project_bindings,
    google_storage_bucket.adk_staging,
    google_pubsub_subscription.raw_logs_to_bq_sub,
    google_bigquery_table.user_access_events
  ]
}

# 4. Cloud Scheduler Job for Periodic Threat Scanner Polling
# Runs when enable_continuous_query is false (the default cost-effective serverless path).
# Wakes Cloud Run every 2 minutes via OIDC auth to run an active threat scan pass at $0 continuous cost.
resource "google_cloud_scheduler_job" "threat_scanner_cron" {
  count       = var.enable_continuous_query ? 0 : 1
  project     = var.project_id
  region      = var.region
  name        = "cymbal-cyber-threat-scanner-cron"
  description = "Triggers Cloud Run threat scan every 2 minutes for zero-reservation threat triage."
  schedule    = "*/2 * * * *"
  time_zone   = "UTC"

  http_target {
    http_method = "POST"
    uri         = "${google_cloud_run_v2_service.adk_agent_service.uri}/apps/adk_agent/trigger/scan"

    oidc_token {
      service_account_email = google_service_account.invoker_sa.email
      audience              = "${google_cloud_run_v2_service.adk_agent_service.uri}/apps/adk_agent/trigger/scan"
    }
  }

  depends_on = [
    google_project_service.required,
    google_cloud_run_v2_service.adk_agent_service,
    google_service_account.invoker_sa
  ]
}

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
