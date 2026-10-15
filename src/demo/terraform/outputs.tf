output "project_id" {
  description = "Target Google Cloud Project ID."
  value       = var.project_id
}

output "region" {
  description = "GCP deployment region."
  value       = var.region
}

output "service_account_email" {
  description = "Dedicated ADK agent runtime service account email (backward compatibility alias)."
  value       = google_service_account.agent_sa.email
}

output "continuous_query_service_account_email" {
  description = "Dedicated BigQuery continuous query service account email (empty unless enable_continuous_query)."
  value       = one(google_service_account.continuous_query_sa[*].email)
}

output "agent_service_account_email" {
  description = "Dedicated ADK multi-agent runtime service account email."
  value       = google_service_account.agent_sa.email
}

output "console_service_account_email" {
  description = "Dedicated SOC console service account email."
  value       = google_service_account.soc_console_sa.email
}

output "invoker_service_account_email" {
  description = "Pub/Sub push identity, the only caller of the agent webhook."
  value       = google_service_account.invoker_sa.email
}

output "console_access_service_account_email" {
  description = "Identity analysts impersonate to open the SOC console (see DEPLOYMENT.md section 5)."
  value       = google_service_account.console_access_sa.email
}

output "scheduler_service_account_email" {
  description = "Cloud Scheduler identity that runs the threat detector job."
  value       = google_service_account.scheduler_sa.email
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

output "pubsub_raw_access_bq_subscription" {
  description = "Pub/Sub BigQuery subscription writing access events to user_access_events."
  value       = google_pubsub_subscription.raw_access_to_bq.id
}

output "pubsub_raw_network_bq_subscription" {
  description = "Pub/Sub BigQuery subscription writing network events to network_events."
  value       = google_pubsub_subscription.raw_network_to_bq.id
}

output "pubsub_alerts_dlq_topic" {
  description = "Dead-letter topic for alerts that exhausted webhook delivery attempts."
  value       = google_pubsub_topic.alerts_dlq_topic.id
}

output "pubsub_raw_events_dlq_topic" {
  description = "Dead-letter topic for raw log ingestion events that fail schema parsing or delivery."
  value       = google_pubsub_topic.raw_events_dlq.id
}

output "pubsub_raw_events_dlq_subscription" {
  description = "Dead-letter pull subscription retaining raw log ingestion failure messages for 7 days."
  value       = google_pubsub_subscription.raw_events_dlq_sub.id
}

output "table_alerts" {
  description = "BigQuery alerts table (keyed by alert_id, status lifecycle)."
  value       = "${var.project_id}.${google_bigquery_dataset.cyber_dataset.dataset_id}.${google_bigquery_table.alerts.table_id}"
}

output "threat_detector_job" {
  description = "Scheduled micro-batch threat detector Cloud Run Job."
  value       = google_cloud_run_v2_job.threat_detector.name
}

output "soc_console_url" {
  description = "Public URL of the interactive Streamlit SOC Analyst Console."
  value       = google_cloud_run_v2_service.soc_console_service.uri
}