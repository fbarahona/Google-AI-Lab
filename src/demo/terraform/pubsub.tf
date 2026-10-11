# 1. Pub/Sub Topic for Continuous Query Alerts
resource "google_pubsub_topic" "alerts_topic" {
  project = var.project_id
  name    = "cymbal_cyber_alerts"

  labels = {
    environment = "demo"
    component   = "threat-alerts"
  }

  depends_on = [google_project_service.required]
}

# 2. Pub/Sub Subscription for ADK Agent Trigger
resource "google_pubsub_subscription" "adk_agent_trigger" {
  project                    = var.project_id
  name                       = "adk_agent_trigger"
  topic                      = google_pubsub_topic.alerts_topic.name
  ack_deadline_seconds       = 600
  message_retention_duration = "604800s" # 7 days
  retain_acked_messages      = false

  expiration_policy {
    ttl = "" # Never expire
  }

  # Push config is activated when push endpoint URL is provided
  dynamic "push_config" {
    for_each = var.agent_push_endpoint != "" ? [var.agent_push_endpoint] : []
    content {
      push_endpoint = push_config.value

      oidc_token {
        service_account_email = google_service_account.invoker_sa.email
        audience              = push_config.value
      }

      no_wrapper {
        write_metadata = false
      }
    }
  }

  retry_policy {
    minimum_backoff = "10s"
    maximum_backoff = "600s"
  }

  depends_on = [google_service_account.invoker_sa]
}

# 3. Pub/Sub Topic for Raw Synthetic Logs (Data Ingestion Pipeline)
resource "google_pubsub_topic" "raw_logs_topic" {
  project = var.project_id
  name    = "cymbal_cyber_raw_logs"

  labels = {
    environment = "demo"
    component   = "raw-logs"
  }

  depends_on = [google_project_service.required]
}

# 4. Pub/Sub Pull Subscription for Dataflow Ingestion Pipeline
resource "google_pubsub_subscription" "raw_logs_to_bq_sub" {
  project                    = var.project_id
  name                       = "raw_logs_to_bq_sub"
  topic                      = google_pubsub_topic.raw_logs_topic.name
  ack_deadline_seconds       = 300
  message_retention_duration = "86400s" # 24 hours

  retry_policy {
    minimum_backoff = "10s"
    maximum_backoff = "300s"
  }
}

