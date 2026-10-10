variable "project_id" {
  description = "Google Cloud project ID where all resources will be provisioned."
  type        = string
}

variable "region" {
  description = "Default Google Cloud region for compute, Pub/Sub, and Vertex AI operations."
  type        = string
  default     = "us-east1"
}

variable "bigquery_location" {
  description = "Location for BigQuery dataset, tables, and reservations."
  type        = string
  default     = "US"
}

variable "dataset_id" {
  description = "Name of the BigQuery cybersecurity dataset."
  type        = string
  default     = "Cymbal_Cyber"
}

variable "service_account_id" {
  description = "ID for the dedicated orchestration and continuous query service account."
  type        = string
  default     = "bq-continuous-query-sa"
}

variable "disable_on_destroy" {
  description = "Whether to disable Google APIs when Terraform resources are destroyed."
  type        = bool
  default     = false
}

variable "agent_push_endpoint" {
  description = "Optional Push Endpoint URL for Vertex AI Agent Engine invocation."
  type        = string
  default     = ""
}