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
  description = "ID for the dedicated continuous query service account."
  type        = string
  default     = "bq-continuous-query-sa"
}

variable "agent_service_account_id" {
  description = "ID for the dedicated ADK Multi-Agent runtime service account."
  type        = string
  default     = "cymbal-adk-agent-sa"
}

variable "invoker_service_account_id" {
  description = "ID for the dedicated Pub/Sub push subscription invoker service account."
  type        = string
  default     = "pubsub-invoker-sa"
}

variable "dataflow_service_account_id" {
  description = "ID for the dedicated Dataflow streaming ingestion pipeline service account."
  type        = string
  default     = "cymbal-dataflow-pipeline-sa"
}

variable "enable_continuous_query" {
  description = "Whether to provision BigQuery Enterprise reservation and continuous query streaming job. When false (default), the background threat_scanner.py daemon serves as the zero-cost polling trigger."
  type        = bool
  default     = false
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

variable "billing_account_id" {
  description = "Optional Google Cloud Billing Account ID to provision a demo budget alert."
  type        = string
  default     = ""
}
