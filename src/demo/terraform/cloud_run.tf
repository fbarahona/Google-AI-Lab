# Cloud Run Service for ADK Multi-Agent Webhook
resource "google_cloud_run_v2_service" "adk_agent_service" {
  project  = var.project_id
  name     = "cymbal-cyber-adk-agent"
  location = var.region
  ingress  = "INGRESS_TRAFFIC_ALL"

  template {
    service_account = google_service_account.agent_sa.email

    scaling {
      min_instance_count = 0
      max_instance_count = 3
    }

    containers {
      image = "gcr.io/${var.project_id}/cymbal-cyber-adk-agent:latest"

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
        name  = "GEMINI_MODEL"
        value = "gemini-2.0-flash"
      }

      resources {
        limits = {
          cpu    = "2"
          memory = "2Gi"
        }
      }
    }
  }

  depends_on = [
    google_project_service.required,
    google_service_account.agent_sa
  ]
}

# Scheduled Micro-Batch Threat Detector Cloud Run Job
resource "google_cloud_run_v2_job" "threat_detector" {
  project  = var.project_id
  name     = "threat-detector"
  location = var.region

  template {
    template {
      service_account = google_service_account.detector_sa.email
      max_retries     = 1
      timeout         = "300s"

      containers {
        image = "gcr.io/${var.project_id}/cymbal-cyber-adk-agent:latest"
        command = [
          "python",
          "-m",
          "adk_agent.threat_detector"
        ]

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

  depends_on = [
    google_project_service.required,
    google_service_account.detector_sa,
    google_bigquery_table.alerts,
    google_pubsub_topic.alerts_topic
  ]
}

# Cloud Scheduler Job running the Threat Detector every 2 minutes
resource "google_cloud_scheduler_job" "threat_detector_schedule" {
  project     = var.project_id
  name        = "threat-detector-2min-trigger"
  region      = var.region
  description = "Triggers the threat-detector Cloud Run Job every 2 minutes for idempotent micro-batch threat evaluation."
  schedule    = "*/2 * * * *"
  time_zone   = "UTC"

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

# Grant Invoker SA run.jobs.run on the detector job
resource "google_cloud_run_v2_job_iam_member" "scheduler_invokes_detector" {
  project = var.project_id
  location = var.region
  name    = google_cloud_run_v2_job.threat_detector.name
  role    = "roles/run.invoker"
  member  = "serviceAccount:${google_service_account.invoker_sa.email}"
}

