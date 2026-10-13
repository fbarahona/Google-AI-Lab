# ==============================================================================
# SCHEDULED MICRO-BATCH THREAT DETECTOR (Budget Detection Architecture)
# ==============================================================================
# NOTE: The ADK agent webhook service (google_cloud_run_v2_service.adk_agent_service)
# is defined in deploy.tf. Do not redeclare it here.

# Scheduled Micro-Batch Threat Detector Cloud Run Job
resource "google_cloud_run_v2_job" "threat_detector" {
  project             = var.project_id
  name                = "threat-detector"
  location            = var.region
  deletion_protection = false

  template {
    template {
      service_account = google_service_account.detector_sa.email
      max_retries     = 1
      timeout         = "240s"

      containers {
        # Placeholder until the agent image is built/pushed (same image as the webhook service)
        image = "us-docker.pkg.dev/cloudrun/container/job"
        command = [
          "python",
          "-m",
          "adk_agent.threat_detector"
        ]

        env {
          name  = "PROJECT_ID"
          value = var.project_id
        }
        env {
          name  = "GOOGLE_CLOUD_PROJECT"
          value = var.project_id
        }
        env {
          name  = "GOOGLE_CLOUD_LOCATION"
          value = var.region
        }
        env {
          name  = "BIGQUERY_DATASET"
          value = var.dataset_id
        }
        env {
          name  = "ALERTS_TOPIC"
          value = google_pubsub_topic.alerts_topic.name
        }

        resources {
          limits = {
            cpu    = "1"
            memory = "1Gi"
          }
        }
      }
    }
  }

  lifecycle {
    ignore_changes = [
      template[0].template[0].containers[0].image,
      client,
      client_version,
    ]
  }

  depends_on = [
    google_project_service.required,
    google_service_account.detector_sa,
    google_project_iam_member.detector_sa_bq_job_user,
    google_bigquery_table.alerts,
    google_pubsub_topic.alerts_topic
  ]
}

# Cloud Scheduler Job running the Threat Detector every 5 minutes
resource "google_cloud_scheduler_job" "threat_detector_schedule" {
  project          = var.project_id
  name             = "threat-detector-trigger"
  region           = var.region
  description      = "Triggers the threat-detector Cloud Run Job every 5 minutes for idempotent micro-batch threat evaluation."
  schedule         = "*/5 * * * *"
  time_zone        = "UTC"
  attempt_deadline = "320s"

  http_target {
    http_method = "POST"
    uri         = "https://${var.region}-run.googleapis.com/apis/run.googleapis.com/v1/namespaces/${var.project_id}/jobs/${google_cloud_run_v2_job.threat_detector.name}:run"

    oauth_token {
      service_account_email = google_service_account.invoker_sa.email
      scope                 = "https://www.googleapis.com/auth/cloud-platform"
    }
  }

  depends_on = [
    google_project_service.required,
    google_cloud_run_v2_job.threat_detector,
    google_service_account.invoker_sa
  ]
}

# Grant Invoker SA permission to run the detector job
resource "google_cloud_run_v2_job_iam_member" "scheduler_invokes_detector" {
  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_job.threat_detector.name
  role     = "roles/run.invoker"
  member   = "serviceAccount:${google_service_account.invoker_sa.email}"
}
