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

variable "storage_location" {
  description = "Location for Cloud Storage buckets aligned with BigQuery multi-region (US) or custom region."
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

variable "console_service_account_id" {
  description = "ID for the dedicated SOC console (Streamlit) service account."
  type        = string
  default     = "cymbal-soc-console-sa"
}

variable "invoker_service_account_id" {
  description = "ID for the Pub/Sub push identity, the only caller allowed to invoke the agent webhook."
  type        = string
  default     = "pubsub-invoker-sa"
}

variable "scheduler_service_account_id" {
  description = "ID for the Cloud Scheduler identity that starts the threat detector job."
  type        = string
  default     = "threat-detector-scheduler-sa"
}

variable "dataflow_service_account_id" {
  description = "ID for the dedicated Dataflow streaming ingestion pipeline service account."
  type        = string
  default     = "cymbal-dataflow-pipeline-sa"
}

variable "enable_continuous_query" {
  description = "Whether to provision BigQuery Enterprise reservation (100 slots) and continuous query assignment. CAUTION: BigQuery Enterprise slot reservations bill continuously (~$0.06/slot-hour = ~$6.00/hour or ~$4,320/month for 100 slots). Defaults to false; when false, Cloud Scheduler periodically triggers the threat scanner at zero continuous cost."
  type        = bool
  default     = false
}

variable "enable_dataflow_streaming" {
  description = "Whether to provision the Dataflow streaming log ingestion job. CAUTION: Dataflow streaming worker VMs bill continuously (~$100-$300/month). Defaults to false (zero-cost). When false, synthetic logs and GCS batch loader provide ingestion."
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

variable "kms_key_name" {
  description = "Optional Cloud KMS CryptoKey resource ID for Customer-Managed/Supplied Encryption Keys (CMEK/CSEK) on BigQuery dataset and tables. If omitted (empty string), Google-managed encryption is used."
  type        = string
  default     = ""
}

variable "agent_image" {
  description = "Container image URL for the ADK agent Cloud Run service and threat detector job."
  type        = string
  default     = ""
}

variable "vertex_ai_location" {
  description = "Vertex AI location for Gemini calls from the agent service (models and vision). 'global' serves the newest models; compute stays in var.region."
  type        = string
  default     = "global"
}

variable "enable_adk_dev_ui" {
  description = "Serve the ADK web UI, /run, session and A2A APIs on the agent service. They run investigations as the agent SA without the webhook's OIDC check, so keep false outside short, supervised demos."
  type        = bool
  default     = false
}

variable "deployer_member" {
  description = "Optional IAM member (e.g. user:name@example.com or serviceAccount:sa@...) granted roles/artifactregistry.writer to build and push container images."
  type        = string
  default     = ""
}

