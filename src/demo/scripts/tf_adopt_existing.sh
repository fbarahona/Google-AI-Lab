#!/usr/bin/env bash
# ==============================================================================
# One-time recovery: adopt existing GCP resources into Terraform state
# ==============================================================================
# Run this by hand only if Terraform state was lost before it moved to the GCS
# backend (for example, a devcontainer rebuild wiped the local terraform.tfstate)
# and `terraform plan` now wants to create resources that already exist (409s).
# deploy_cloud.sh never calls it: with remote state, nothing needs re-importing.
#
# Usage: ./src/demo/scripts/tf_adopt_existing.sh <PROJECT_ID> [REGION]
# Then run `terraform plan` and check it shows no creates for existing resources.
# ==============================================================================
set -euo pipefail

PROJECT_ID="${1:?Usage: tf_adopt_existing.sh <PROJECT_ID> [REGION]}"
REGION="${2:-us-east1}"
ARTIFACT_REPO="${ARTIFACT_REPO:-cymbal-cyber}"
TF_STATE_BUCKET="${TF_STATE_BUCKET:-${PROJECT_ID}-tfstate}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TERRAFORM_DIR="$(cd "${SCRIPT_DIR}/../terraform" && pwd)"
TF_VARS=(-var="project_id=${PROJECT_ID}" -var="region=${REGION}")

unset GOOGLE_OAUTH_ACCESS_TOKEN
terraform -chdir="${TERRAFORM_DIR}" init -input=false -backend-config="bucket=${TF_STATE_BUCKET}"
TF_STATE_LIST="$(terraform -chdir="${TERRAFORM_DIR}" state list)"

# adopt <terraform address> <import id> <describe command...>
# Imports the resource only if it exists in GCP and is missing from state.
adopt() {
  local address="$1" import_id="$2"
  shift 2
  if grep -qx "${address}" <<<"${TF_STATE_LIST}"; then
    echo "Already in state: ${address}"
  elif "$@" >/dev/null 2>&1; then
    echo "Importing ${address}..."
    terraform -chdir="${TERRAFORM_DIR}" import -input=false "${TF_VARS[@]}" "${address}" "${import_id}" ||
      echo "WARNING: import failed for ${address}; check the error above."
  else
    echo "Not found in GCP, Terraform will create it: ${address}"
  fi
}

adopt google_artifact_registry_repository.agent_repo \
  "projects/${PROJECT_ID}/locations/${REGION}/repositories/${ARTIFACT_REPO}" \
  gcloud artifacts repositories describe "${ARTIFACT_REPO}" --location="${REGION}" --project="${PROJECT_ID}"

# bq-continuous-query-sa is created only with enable_continuous_query, so it is not adopted.
for pair in \
  "cymbal-adk-agent-sa:google_service_account.agent_sa" \
  "cymbal-soc-console-sa:google_service_account.soc_console_sa" \
  "pubsub-invoker-sa:google_service_account.invoker_sa" \
  "soc-console-access:google_service_account.console_access_sa" \
  "threat-detector-job-sa:google_service_account.detector_sa"; do
  sa_email="${pair%%:*}@${PROJECT_ID}.iam.gserviceaccount.com"
  adopt "${pair#*:}" "projects/${PROJECT_ID}/serviceAccounts/${sa_email}" \
    gcloud iam service-accounts describe "${sa_email}" --project="${PROJECT_ID}"
done

for pair in \
  "cymbal_cyber_adk_staging_bucket_${PROJECT_ID}:google_storage_bucket.adk_staging" \
  "cymbal-cyber-adk-escalations-bucket_${PROJECT_ID}:google_storage_bucket.escalations" \
  "cymbal-cyber-screenshots_${PROJECT_ID}:google_storage_bucket.screenshots" \
  "cymbal-cyber-raw-logs_${PROJECT_ID}:google_storage_bucket.raw_logs"; do
  bucket="${pair%%:*}"
  adopt "${pair#*:}" "${bucket}" \
    gcloud storage buckets describe "gs://${bucket}" --project="${PROJECT_ID}"
done

for pair in \
  "cymbal-cyber-adk-agent:google_cloud_run_v2_service.adk_agent_service" \
  "cymbal-cyber-soc-console:google_cloud_run_v2_service.soc_console_service"; do
  service="${pair%%:*}"
  adopt "${pair#*:}" "projects/${PROJECT_ID}/locations/${REGION}/services/${service}" \
    gcloud run services describe "${service}" --project="${PROJECT_ID}" --region="${REGION}"
done

echo "Done. Next: terraform -chdir=${TERRAFORM_DIR} plan ${TF_VARS[*]}"
