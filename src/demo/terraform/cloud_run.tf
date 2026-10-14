# ==============================================================================
# CLOUD RUN WORKLOADS: ADK AGENT WEBHOOK SERVICE & THREAT DETECTOR JOB
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
    timeout                          = "600s"
    service_account                  = google_service_account.agent_sa.email
    max_instance_request_concurrency = 4

    scaling {
      min_instance_count = 0
      max_instance_count = 10
    }

    containers {
      image = var.agent_image != "" ? var.agent_image : "us-docker.pkg.dev/cloudrun/container/hello" # Placeholder until agents-cli deploy
      resources {
        limits = {
          cpu    = "1"
          memory = "4Gi"
        }
      }
      env {
        name  = "PROJECT_ID"
        value = var.project_id
      }
      env {
        name  = "GOOGLE_CLOUD_PROJECT"
        value = var.project_id
      }
      dynamic "env" {
        for_each = var.gemini_api_key != "" ? [var.gemini_api_key] : []
        content {
          name  = "GEMINI_API_KEY"
          value = env.value
        }
      }
      env {
        name  = "LOCAL_MODE"
        value = "false"
      }
      env {
        name  = "SCREENSHOTS_BUCKET"
        value = google_storage_bucket.screenshots.name
      }
      env {
        name  = "MCP_TOOL_TIMEOUT_SECONDS"
        value = "90"
      }
      env {
        name  = "GCS_SIGNER_SA"
        value = google_service_account.agent_sa.email
      }
      env {
        name  = "EXPECTED_OIDC_AUDIENCE"
        value = local.agent_service_url
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

# NOTE: Invoker IAM binding (google_cloud_run_v2_service_iam_member.agent_invoker) is centralized in iam.tf

# 2. Scheduled Micro-Batch Threat Detector Cloud Run Job
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
        # Set to var.agent_image if provided, otherwise placeholder until built/pushed
        image   = var.agent_image != "" ? var.agent_image : "us-docker.pkg.dev/cloudrun/container/job"
        command = ["python"]
        args = [
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
    uri         = "https://run.googleapis.com/v2/projects/${var.project_id}/locations/${var.region}/jobs/${google_cloud_run_v2_job.threat_detector.name}:run"
    body        = base64encode("{}")
    headers = {
      "Content-Type" = "application/json"
    }

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

# NOTE: Cloud Scheduler Job invoker IAM binding (google_cloud_run_v2_job_iam_member.scheduler_invokes_detector) is centralized in iam.tf

# 3. Interactive SOC Analyst Console (Streamlit Dashboard)
resource "google_cloud_run_v2_service" "soc_console_service" {
  name                = "cymbal-cyber-soc-console"
  location            = var.region
  project             = var.project_id
  ingress             = "INGRESS_TRAFFIC_ALL"
  deletion_protection = false

  template {
    timeout                          = "300s"
    service_account                  = google_service_account.soc_console_sa.email
    max_instance_request_concurrency = 80

    scaling {
      min_instance_count = 0
      max_instance_count = 5
    }

    containers {
      image   = var.agent_image != "" ? var.agent_image : "us-docker.pkg.dev/cloudrun/container/hello"
      command = ["python"]
      args = [
        "-m",
        "streamlit",
        "run",
        "src/demo/soc_ticketing/streamlit_soc_console.py",
        "--server.port=8080",
        "--server.address=0.0.0.0",
        "--server.enableCORS=false",
        "--server.enableXsrfProtection=false",
        "--browser.gatherUsageStats=false"
      ]

      resources {
        limits = {
          cpu    = "1"
          memory = "2Gi"
        }
      }

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
        name  = "ESCALATION_BUCKET"
        value = google_storage_bucket.escalations.name
      }
      env {
        name  = "SCREENSHOTS_BUCKET"
        value = google_storage_bucket.screenshots.name
      }
      env {
        name  = "RAW_LOGS_TOPIC"
        value = google_pubsub_topic.raw_logs_topic.name
      }
      env {
        name  = "LOCAL_MODE"
        value = "false"
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

  depends_on = [
    google_project_service.required,
    google_service_account.soc_console_sa,
    google_storage_bucket.escalations,
    google_bigquery_dataset.cyber_dataset
  ]
}
