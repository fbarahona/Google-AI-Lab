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

  push_config {
    push_endpoint = local.agent_push_endpoint

    oidc_token {
      service_account_email = google_service_account.invoker_sa.email
      audience              = local.agent_push_endpoint
    }

    no_wrapper {
      write_metadata = true
    }
  }

  dead_letter_policy {
    dead_letter_topic     = google_pubsub_topic.alerts_dlq_topic.id
    max_delivery_attempts = 5
  }

  retry_policy {
    minimum_backoff = "10s"
    maximum_backoff = "600s"
  }

  depends_on = [
    google_service_account.invoker_sa,
    google_cloud_run_v2_service.adk_agent_service,
    google_pubsub_topic.alerts_dlq_topic,
    google_pubsub_topic_iam_member.pubsub_sa_dlq_publisher
  ]
}

# 3. Dead-Letter Topic for Failed Alert Investigations
resource "google_pubsub_topic" "alerts_dlq_topic" {
  project = var.project_id
  name    = "cymbal_cyber_alerts_dlq"

  labels = {
    environment = "demo"
    component   = "threat-alerts-dlq"
  }

  depends_on = [google_project_service.required]
}

# 4. BigQuery Subscription on DLQ Topic (Appends to alerts_dead_letter table)
resource "google_pubsub_subscription" "alerts_dlq_to_bq" {
  project                    = var.project_id
  name                       = "alerts_dlq_to_bq_sub"
  topic                      = google_pubsub_topic.alerts_dlq_topic.name
  ack_deadline_seconds       = 60
  message_retention_duration = "604800s" # 7 days

  bigquery_config {
    table               = "${var.project_id}:${google_bigquery_dataset.cyber_dataset.dataset_id}.${google_bigquery_table.alerts_dead_letter.table_id}"
    use_topic_schema    = false
    write_metadata      = true
    drop_unknown_fields = true
  }

  depends_on = [
    google_bigquery_table.alerts_dead_letter,
    google_bigquery_table_iam_member.pubsub_sa_dlq_editor
  ]
}

# 5. Pub/Sub Topic for Raw Synthetic Logs (Data Ingestion Pipeline)
resource "google_pubsub_topic" "raw_logs_topic" {
  project = var.project_id
  name    = "cymbal_cyber_raw_logs"

  labels = {
    environment = "demo"
    component   = "raw-logs"
  }

  depends_on = [google_project_service.required]
}

# 6. Direct BigQuery Subscription: user_access_events (Filtered by event_family = 'access')
resource "google_pubsub_subscription" "raw_access_to_bq" {
  project                    = var.project_id
  name                       = "raw_access_events_to_bq_sub"
  topic                      = google_pubsub_topic.raw_logs_topic.name
  filter                     = "attributes.event_family = \"access\""
  ack_deadline_seconds       = 60
  message_retention_duration = "86400s" # 24 hours

  bigquery_config {
    table               = "${var.project_id}:${google_bigquery_dataset.cyber_dataset.dataset_id}.${google_bigquery_table.user_access_events.table_id}"
    use_table_schema    = true
    use_topic_schema    = false
    drop_unknown_fields = true
    write_metadata      = false
  }

  depends_on = [
    google_bigquery_table.user_access_events,
    google_bigquery_table_iam_member.pubsub_sa_access_events_editor
  ]
}

# 7. Direct BigQuery Subscription: network_events (Filtered by event_family = 'network')
resource "google_pubsub_subscription" "raw_network_to_bq" {
  project                    = var.project_id
  name                       = "raw_network_events_to_bq_sub"
  topic                      = google_pubsub_topic.raw_logs_topic.name
  filter                     = "attributes.event_family = \"network\""
  ack_deadline_seconds       = 60
  message_retention_duration = "86400s" # 24 hours

  bigquery_config {
    table               = "${var.project_id}:${google_bigquery_dataset.cyber_dataset.dataset_id}.${google_bigquery_table.network_events.table_id}"
    use_table_schema    = true
    use_topic_schema    = false
    drop_unknown_fields = true
    write_metadata      = false
  }

  depends_on = [
    google_bigquery_table.network_events,
    google_bigquery_table_iam_member.pubsub_sa_network_events_editor
  ]
}

