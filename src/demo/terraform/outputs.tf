output "project_id" {
  description = "Target Google Cloud Project ID."
  value       = var.project_id
}

output "region" {
  description = "GCP deployment region."
  value       = var.region
}

output "service_account_email" {
  description = "Dedicated orchestrator service account email."
  value       = google_service_account.orchestrator_sa.email
}

output "bigquery_dataset_id" {
  description = "Full ID of the BigQuery cybersecurity dataset."
  value       = google_bigquery_dataset.cyber_dataset.id
}

output "table_user_access_events" {
  description = "BigQuery table for user access events."
  value       = "${var.project_id}.${google_bigquery_dataset.cyber_dataset.dataset_id}.${google_bigquery_table.user_access_events.table_id}"
}

output "table_network_events" {
  description = "BigQuery table for network events."
  value       = "${var.project_id}.${google_bigquery_dataset.cyber_dataset.dataset_id}.${google_bigquery_table.network_events.table_id}"
}

output "table_adk_threat_assessment" {
  description = "BigQuery table storing ADK agent threat assessments."
  value       = "${var.project_id}.${google_bigquery_dataset.cyber_dataset.dataset_id}.${google_bigquery_table.adk_threat_assessment.table_id}"
}

output "table_soc_tickets" {
  description = "BigQuery table storing tickets dispatched to the SOC ticketing system."
  value       = "${var.project_id}.${google_bigquery_dataset.cyber_dataset.dataset_id}.${google_bigquery_table.soc_tickets.table_id}"
}

output "gcs_adk_staging_bucket" {
  description = "GCS bucket for ADK Agent Engine staging."
  value       = "gs://${google_storage_bucket.adk_staging.name}"
}

output "gcs_escalations_bucket" {
  description = "GCS bucket for SOC human escalation queue."
  value       = "gs://${google_storage_bucket.escalations.name}"
}

output "gcs_screenshots_bucket" {
  description = "GCS bucket storing desktop screenshot evidence for multimodal vision analysis."
  value       = "gs://${google_storage_bucket.screenshots.name}"
}

output "gcs_raw_logs_bucket" {
  description = "GCS bucket for raw synthetic logs storage."
  value       = "gs://${google_storage_bucket.raw_logs.name}"
}

output "pubsub_alerts_topic" {
  description = "Pub/Sub topic receiving BigQuery continuous query alerts."
  value       = google_pubsub_topic.alerts_topic.id
}

output "pubsub_alerts_subscription" {
  description = "Pub/Sub subscription triggering ADK agent processing."
  value       = google_pubsub_subscription.adk_agent_trigger.id
}

output "pubsub_raw_logs_topic" {
  description = "Pub/Sub topic for raw logs ingestion pipeline."
  value       = google_pubsub_topic.raw_logs_topic.id
}

output "pubsub_raw_logs_subscription" {
  description = "Pub/Sub subscription for Dataflow streaming raw logs."
  value       = google_pubsub_subscription.raw_logs_to_bq_sub.id
}

output "bigquery_connection_id" {
  description = "BigQuery connection for Vertex AI and object tables."
  value       = google_bigquery_connection.vertex_ai_connection.name
}

output "bigquery_connection_sa" {
  description = "Service Account associated with the BigQuery Connection."
  value       = google_bigquery_connection.vertex_ai_connection.cloud_resource[0].service_account_id
}