# ==============================================================================
# MISSING DEMO INFRASTRUCTURE (Cloud Run Agent, Dataflow, Continuous Query)
# ==============================================================================

# 1. Cloud Run Deployment for ADK Multi-Agent Team
# We deploy the ADK Agent to Cloud Run to natively support Pub/Sub OIDC push tokens
# without requiring an intermediary token-exchange relay service.
resource "google_cloud_run_v2_service" "adk_agent_service" {
  name     = "cymbal-cyber-adk-agent"
  location = var.region
  project  = var.project_id
  ingress  = "INGRESS_TRAFFIC_ALL"

  template {
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
    }
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

# 2. BigQuery Continuous Query (Simulated via Scheduled Query for Demo)
# Since native BigQuery Continuous Queries require an Enterprise reservation and 
# are difficult to provision via standard Terraform without raw API calls,
# we represent the continuous streaming capability here.
resource "google_bigquery_data_transfer_config" "continuous_query_simulator" {
  project                = var.project_id
  display_name           = "Cymbal Cyber Threat Correlation (Continuous Query)"
  data_source_id         = "scheduled_query"
  schedule               = "every 2 minutes"
  destination_dataset_id = google_bigquery_dataset.cyber_dataset.dataset_id
  service_account_name   = google_service_account.continuous_query_sa.email

  params = {
    query = file("${path.module}/../data_pipeline/continuous_query.sql")
  }

  depends_on = [
    google_project_service.required,
    google_bigquery_table.user_access_events,
    google_bigquery_table.network_events
  ]
}

# 3. Dataflow Streaming Ingestion Pipeline
# Reads from Pub/Sub cymbal_cyber_raw_logs and streams to BigQuery tables.
resource "google_dataflow_job" "pubsub_to_bigquery" {
  project               = var.project_id
  region                = var.region
  name                  = "cymbal-cyber-ingestion-pipeline"
  template_gcs_path     = "gs://dataflow-templates/latest/PubSub_to_BigQuery"
  temp_gcs_location     = "gs://${google_storage_bucket.adk_staging.name}/temp"
  service_account_email = google_service_account.continuous_query_sa.email
  on_delete             = "cancel"

  parameters = {
    inputSubscription = google_pubsub_subscription.raw_logs_to_bq_sub.id
    outputTableSpec   = "${var.project_id}:${google_bigquery_dataset.cyber_dataset.dataset_id}.user_access_events"
  }

  depends_on = [
    google_project_service.required,
    google_storage_bucket.adk_staging,
    google_pubsub_subscription.raw_logs_to_bq_sub,
    google_bigquery_table.user_access_events
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
