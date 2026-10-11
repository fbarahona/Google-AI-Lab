# Dedicated Service Account for Continuous Queries, ADK, and Pub/Sub
resource "google_service_account" "orchestrator_sa" {
  project      = var.project_id
  account_id   = var.service_account_id
  display_name = "Cymbal Cyber Orchestrator Service Account"
  description  = "Runs BigQuery continuous queries, Pub/Sub transformations, and ADK agent operations."

  depends_on = [google_project_service.required]
}

locals {
  sa_roles = toset([
    "roles/bigquery.connectionUser",
    "roles/bigquery.dataEditor",
    "roles/bigquery.user",
    "roles/logging.logWriter",
    "roles/pubsub.publisher",
    "roles/pubsub.viewer",
    "roles/pubsub.subscriber",
    "roles/serviceusage.serviceUsageConsumer",
    "roles/storage.objectUser",
    "roles/aiplatform.user",
  ])
}

resource "google_project_iam_member" "sa_bindings" {
  for_each = local.sa_roles

  project = var.project_id
  role    = each.value
  member  = "serviceAccount:${google_service_account.orchestrator_sa.email}"
}

# Grant self-token-creation so the service account can generate keyless V4 signed URLs
resource "google_service_account_iam_member" "self_impersonation" {
  service_account_id = google_service_account.orchestrator_sa.name
  role               = "roles/iam.serviceAccountTokenCreator"
  member             = "serviceAccount:${google_service_account.orchestrator_sa.email}"
}

