#!/usr/bin/env bash
# ==============================================================================
# Cloud Deployment Script: ADK Multi-Agent Service & Threat Detector Job
# ==============================================================================
# Builds the unified container image and updates both:
# 1. Cloud Run Service: cymbal-cyber-adk-agent (Webhook & Multi-Agent Orchestrator)
# 2. Cloud Run Job: threat-detector (Scheduled Micro-Batch Detection Job)
# ==============================================================================
set -euo pipefail

PROJECT_ID="${1:-${GOOGLE_CLOUD_PROJECT:-}}"

# Resolve compute infrastructure region (Artifact Registry, Cloud Run, Cloud Scheduler, Dataflow).
# Note: GOOGLE_CLOUD_LOCATION is often set to 'global' for Vertex AI models, which is NOT
# a valid regional location for Cloud Run or Artifact Registry. We prioritize:
# 1. Positional argument $2
# 2. GOOGLE_CLOUD_REGION
# 3. CLOUDSDK_COMPUTE_REGION
# 4. GOOGLE_CLOUD_LOCATION (if not 'global')
# 5. Default: us-east1
CANDIDATE_REGION="${2:-${GOOGLE_CLOUD_REGION:-${CLOUDSDK_COMPUTE_REGION:-}}}"
if [ -z "${CANDIDATE_REGION}" ] && [ -n "${GOOGLE_CLOUD_LOCATION:-}" ] && [ "${GOOGLE_CLOUD_LOCATION}" != "global" ]; then
  CANDIDATE_REGION="${GOOGLE_CLOUD_LOCATION}"
fi
REGION="${CANDIDATE_REGION:-us-east1}"

# Strip accidental whitespace, quotes, and force lowercase for Docker/Artifact Registry compliance
export PROJECT_ID="$(echo -n "${PROJECT_ID}" | tr -d '[:space:]' | tr -d '"' | tr -d "'" | tr '[:upper:]' '[:lower:]')"
export REGION="$(echo -n "${REGION}" | tr -d '[:space:]' | tr -d '"' | tr -d "'" | tr '[:upper:]' '[:lower:]')"

if [ "${REGION}" == "global" ]; then
  echo "Warning: 'global' is a model endpoint location, not a valid regional compute location for Artifact Registry/Cloud Run. Defaulting region to 'us-east1'."
  export REGION="us-east1"
fi

if [ -z "${PROJECT_ID}" ]; then
  echo "Error: GOOGLE_CLOUD_PROJECT environment variable or argument is required."
  echo "Usage: ./src/demo/scripts/deploy_cloud.sh <PROJECT_ID> [REGION]"
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
TERRAFORM_DIR="${REPO_ROOT}/src/demo/terraform"

# Load GEMINI_API_KEY from .env if present and not already exported in environment
if [ -z "${GEMINI_API_KEY:-}" ] && [ -f "${REPO_ROOT}/.env" ]; then
  GEMINI_API_KEY="$(grep -E '^GEMINI_API_KEY=' "${REPO_ROOT}/.env" | cut -d'=' -f2- | tr -d '"' | tr -d "'" || true)"
fi

if [ -z "${GEMINI_API_KEY:-}" ]; then
  echo "WARNING: GEMINI_API_KEY is unset. The agent will rely on Vertex AI / Application Default Credentials."
else
  echo "GEMINI_API_KEY detected and will be injected into Cloud Run."
fi

# Ensure Terraform uses the active gcloud authentication token, preventing "invalid token JSON from metadata: EOF"
if command -v gcloud >/dev/null 2>&1; then
  ACTIVE_OAUTH_TOKEN="$(gcloud auth print-access-token 2>/dev/null || true)"
  if [ -n "${ACTIVE_OAUTH_TOKEN}" ]; then
    export GOOGLE_OAUTH_ACCESS_TOKEN="${ACTIVE_OAUTH_TOKEN}"
  fi
fi

# Validation guard: Verify active billing is enabled for the target GCP project
if command -v gcloud >/dev/null 2>&1; then
  echo "Validating billing status for project: ${PROJECT_ID}..."
  gcloud billing projects describe "${PROJECT_ID}" --format="value(billingEnabled)" --quiet 2>/dev/null | grep -qi "true" || {
    echo "Error: Billing is not enabled for project ${PROJECT_ID}"
    exit 1
  }

  echo "Enabling essential Google Cloud APIs..."
  gcloud services enable \
    cloudbilling.googleapis.com \
    run.googleapis.com \
    pubsub.googleapis.com \
    bigquery.googleapis.com \
    bigquerystorage.googleapis.com \
    artifactregistry.googleapis.com \
    cloudscheduler.googleapis.com \
    cloudbuild.googleapis.com \
    --project="${PROJECT_ID}" --quiet || true
fi

ARTIFACT_REPO="${ARTIFACT_REPO:-cymbal-cyber}"
IMAGE_TAG="${REGION}-docker.pkg.dev/${PROJECT_ID}/${ARTIFACT_REPO}/cymbal-cyber-agent:latest"

# Detect active deploying account to ensure it is granted Artifact Registry writer permissions
DEPLOYER_MEMBER=""
if command -v gcloud >/dev/null 2>&1; then
  ACTIVE_ACCOUNT=$(gcloud auth list --filter=status:ACTIVE --format="value(account)" 2>/dev/null | head -n1 || true)
  if [[ -n "${ACTIVE_ACCOUNT}" ]]; then
    if [[ "${ACTIVE_ACCOUNT}" == *".gserviceaccount.com"* ]]; then
      DEPLOYER_MEMBER="serviceAccount:${ACTIVE_ACCOUNT}"
    else
      DEPLOYER_MEMBER="user:${ACTIVE_ACCOUNT}"
    fi
    echo "Deploying identity detected: ${DEPLOYER_MEMBER}"
  fi
fi

DEPLOYER_VAR=()
if [[ -n "${DEPLOYER_MEMBER}" ]]; then
  DEPLOYER_VAR=(-var="deployer_member=${DEPLOYER_MEMBER}")
fi

# 1. Provision Artifact Registry repository via targeted Terraform first
if command -v terraform >/dev/null 2>&1 && [ -d "${TERRAFORM_DIR}" ]; then
  echo "================================================================="
  echo "1. Provisioning Artifact Registry repository via Terraform..."
  echo "================================================================="
  if [ ! -d "${TERRAFORM_DIR}/.terraform" ]; then
    echo "Initializing Terraform..."
    terraform -chdir="${TERRAFORM_DIR}" init
  fi

  # Ensure the Artifact Registry repository physically exists in GCP first.
  # This prevents 403 Forbidden errors when Terraform attempts to refresh/read IAM policies on a nonexistent repo.
  if command -v gcloud >/dev/null 2>&1; then
    if ! gcloud artifacts repositories describe "${ARTIFACT_REPO}" --location="${REGION}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
      echo "Creating Artifact Registry repository '${ARTIFACT_REPO}' in ${REGION}..."
      gcloud artifacts repositories create "${ARTIFACT_REPO}" \
        --repository-format=docker \
        --location="${REGION}" \
        --project="${PROJECT_ID}" \
        --description="Docker repository for Cymbal Cyber agent and detection container images" \
        --quiet || true
    fi
  fi

  # Import pre-existing GCP repository into state if not yet tracked
  if command -v gcloud >/dev/null 2>&1 && gcloud artifacts repositories describe "${ARTIFACT_REPO}" --location="${REGION}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
    if ! terraform -chdir="${TERRAFORM_DIR}" state list 2>/dev/null | grep -q "^google_artifact_registry_repository.agent_repo$"; then
      echo "Importing existing Artifact Registry repository into Terraform state..."
      terraform -chdir="${TERRAFORM_DIR}" import \
        -var="project_id=${PROJECT_ID}" \
        -var="region=${REGION}" \
        google_artifact_registry_repository.agent_repo \
        "projects/${PROJECT_ID}/locations/${REGION}/repositories/${ARTIFACT_REPO}" 2>/dev/null || true
    fi
  fi

  # 1a. Ensure repository resource is provisioned and reconciled in Terraform first
  terraform -chdir="${TERRAFORM_DIR}" apply -auto-approve \
    -target=google_artifact_registry_repository.agent_repo \
    -var="project_id=${PROJECT_ID}" \
    -var="region=${REGION}" \
    "${DEPLOYER_VAR[@]}"

  # 1b. Provision repository build & push IAM permissions (now guaranteed to succeed because repo exists)
  TARGET_IAM_OPTS=(
    -target=google_artifact_registry_repository_iam_member.compute_sa_writer
    -target=google_project_iam_member.compute_sa_storage_viewer
    -target=google_project_iam_member.compute_sa_log_writer
    -target=google_artifact_registry_repository_iam_member.cloudbuild_sa_writer
  )
  if [[ -n "${DEPLOYER_MEMBER}" ]]; then
    TARGET_IAM_OPTS+=(-target=google_artifact_registry_repository_iam_member.deployer_writer)
  fi

  terraform -chdir="${TERRAFORM_DIR}" apply -auto-approve \
    "${TARGET_IAM_OPTS[@]}" \
    -var="project_id=${PROJECT_ID}" \
    -var="region=${REGION}" \
    "${DEPLOYER_VAR[@]}"
fi

# 2. Configure regional Docker authentication for Artifact Registry
if command -v gcloud >/dev/null 2>&1; then
  echo "Configuring Docker authentication for Artifact Registry (${REGION}-docker.pkg.dev)..."
  gcloud auth configure-docker "${REGION}-docker.pkg.dev" --quiet
fi

# 3. Build & Push Image (anchored to repository root where Dockerfile resides)
echo "================================================================="
echo "2. Building and pushing container image: ${IMAGE_TAG}"
echo "Project: ${PROJECT_ID} | Region: ${REGION}"
echo "================================================================="
if [[ "${FORCE_BUILD:-true}" != "true" ]] && command -v gcloud >/dev/null 2>&1 && gcloud artifacts docker images describe "${IMAGE_TAG}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
  echo "Container image already exists in Artifact Registry: ${IMAGE_TAG}"
  echo "Proceeding with rollout of existing image (FORCE_BUILD=false)..."
elif command -v docker >/dev/null 2>&1; then
  echo "Building and pushing container image with Docker: ${IMAGE_TAG}..."
  docker build -t "${IMAGE_TAG}" -f "${REPO_ROOT}/Dockerfile" "${REPO_ROOT}"
  docker push "${IMAGE_TAG}"
elif command -v gcloud >/dev/null 2>&1; then
  echo "Submitting container image build to Cloud Build (--async)..."
  BUILD_ID=$(gcloud builds submit \
    --project="${PROJECT_ID}" \
    --tag="${IMAGE_TAG}" \
    --async \
    --format="value(id)" \
    "${REPO_ROOT}" | tr -d '[:space:]')
  echo "Cloud Build job submitted: ${BUILD_ID}. Polling status..."
  while true; do
    BUILD_STATUS=$(gcloud builds describe "${BUILD_ID}" --project="${PROJECT_ID}" --format="value(status)" 2>/dev/null || echo "UNKNOWN")
    if [[ "${BUILD_STATUS}" == "SUCCESS" ]]; then
      echo "Cloud Build ${BUILD_ID} finished successfully!"
      break
    elif [[ "${BUILD_STATUS}" =~ ^(FAILURE|INTERNAL_ERROR|TIMEOUT|CANCELLED)$ ]]; then
      echo "Error: Cloud Build ${BUILD_ID} failed with status: ${BUILD_STATUS}"
      exit 1
    fi
    sleep 10
  done
else
  echo "Error: Neither docker nor gcloud is available to build and push the container."
  exit 1
fi

# 4. Apply complete Terraform configuration
if command -v terraform >/dev/null 2>&1 && [ -d "${TERRAFORM_DIR}" ]; then
  echo "================================================================="
  echo "3. Applying complete Terraform configuration: ${TERRAFORM_DIR}"
  echo "================================================================="

  # Pre-import existing GCP resources into Terraform state if created out-of-band to prevent 409 conflicts
  TF_STATE_LIST="$(terraform -chdir="${TERRAFORM_DIR}" state list 2>/dev/null || true)"

  # Service Accounts
  for SA_NAME in bq-continuous-query-sa cymbal-adk-agent-sa pubsub-invoker-sa threat-detector-job-sa; do
    case "${SA_NAME}" in
      bq-continuous-query-sa) TF_RES="google_service_account.continuous_query_sa" ;;
      cymbal-adk-agent-sa)    TF_RES="google_service_account.agent_sa" ;;
      pubsub-invoker-sa)      TF_RES="google_service_account.invoker_sa" ;;
      threat-detector-job-sa) TF_RES="google_service_account.detector_sa" ;;
    esac
    if ! echo "${TF_STATE_LIST}" | grep -q "^${TF_RES}$"; then
      if gcloud iam service-accounts describe "${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com" --project="${PROJECT_ID}" >/dev/null 2>&1; then
        echo "Importing existing Service Account ${SA_NAME} into Terraform state..."
        terraform -chdir="${TERRAFORM_DIR}" import \
          -var="project_id=${PROJECT_ID}" \
          -var="region=${REGION}" \
          "${TF_RES}" "projects/${PROJECT_ID}/serviceAccounts/${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com" 2>/dev/null || true
      fi
    fi
  done

  # Storage Buckets
  for BUCKET_NAME in "cymbal_cyber_adk_staging_bucket_${PROJECT_ID}" "cymbal-cyber-adk-escalations-bucket_${PROJECT_ID}" "cymbal-cyber-screenshots_${PROJECT_ID}" "cymbal-cyber-raw-logs_${PROJECT_ID}"; do
    case "${BUCKET_NAME}" in
      "cymbal_cyber_adk_staging_bucket_"*)      TF_RES="google_storage_bucket.adk_staging" ;;
      "cymbal-cyber-adk-escalations-bucket_"*)  TF_RES="google_storage_bucket.escalations" ;;
      "cymbal-cyber-screenshots_"*)             TF_RES="google_storage_bucket.screenshots" ;;
      "cymbal-cyber-raw-logs_"*)                TF_RES="google_storage_bucket.raw_logs" ;;
    esac
    if ! echo "${TF_STATE_LIST}" | grep -q "^${TF_RES}$"; then
      if gcloud storage buckets describe "gs://${BUCKET_NAME}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
        echo "Importing existing bucket ${BUCKET_NAME} into Terraform state..."
        terraform -chdir="${TERRAFORM_DIR}" import \
          -var="project_id=${PROJECT_ID}" \
          -var="region=${REGION}" \
          "${TF_RES}" "${BUCKET_NAME}" 2>/dev/null || true
      fi
    fi
  done

  # Cloud Run Service
  if ! echo "${TF_STATE_LIST}" | grep -q "^google_cloud_run_v2_service.adk_agent_service$"; then
    if gcloud run services describe cymbal-cyber-adk-agent --project="${PROJECT_ID}" --region="${REGION}" >/dev/null 2>&1; then
      echo "Importing existing Cloud Run service cymbal-cyber-adk-agent into Terraform state..."
      terraform -chdir="${TERRAFORM_DIR}" import \
        -var="project_id=${PROJECT_ID}" \
        -var="region=${REGION}" \
        -var="agent_image=${IMAGE_TAG}" \
        google_cloud_run_v2_service.adk_agent_service "projects/${PROJECT_ID}/locations/${REGION}/services/cymbal-cyber-adk-agent" 2>/dev/null || true
    fi
  fi

  if ! echo "${TF_STATE_LIST}" | grep -q "^google_cloud_run_v2_service.soc_console_service$"; then
    if gcloud run services describe cymbal-cyber-soc-console --project="${PROJECT_ID}" --region="${REGION}" >/dev/null 2>&1; then
      echo "Importing existing Cloud Run service cymbal-cyber-soc-console into Terraform state..."
      terraform -chdir="${TERRAFORM_DIR}" import \
        -var="project_id=${PROJECT_ID}" \
        -var="region=${REGION}" \
        -var="agent_image=${IMAGE_TAG}" \
        google_cloud_run_v2_service.soc_console_service "projects/${PROJECT_ID}/locations/${REGION}/services/cymbal-cyber-soc-console" 2>/dev/null || true
    fi
  fi

  TF_APPLY_MAX_ATTEMPTS=3
  TF_APPLY_ATTEMPT=1
  until terraform -chdir="${TERRAFORM_DIR}" apply -auto-approve \
    -var="project_id=${PROJECT_ID}" \
    -var="region=${REGION}" \
    -var="agent_image=${IMAGE_TAG}" \
    -var="gemini_api_key=${GEMINI_API_KEY:-}" \
    "${DEPLOYER_VAR[@]}"; do
    if [ "${TF_APPLY_ATTEMPT}" -ge "${TF_APPLY_MAX_ATTEMPTS}" ]; then
      echo "Error: Terraform apply failed after ${TF_APPLY_MAX_ATTEMPTS} attempts."
      exit 1
    fi
    echo "Terraform apply encountered a transient error (commonly GCP IAM propagation delay for newly minted BigQuery connection service accounts)."
    echo "Waiting 25 seconds for IAM global consistency before retry (${TF_APPLY_ATTEMPT}/${TF_APPLY_MAX_ATTEMPTS})..."
    sleep 25
    TF_APPLY_ATTEMPT=$((TF_APPLY_ATTEMPT + 1))
  done
fi

# 3. Direct update of Cloud Run Service & Job (ensures active revision rollout)
if command -v gcloud >/dev/null 2>&1; then
  echo "================================================================="
  echo "Updating Cloud Run Service: cymbal-cyber-adk-agent"
  echo "================================================================="
  gcloud run deploy cymbal-cyber-adk-agent \
    --project="${PROJECT_ID}" \
    --region="${REGION}" \
    --image="${IMAGE_TAG}" 2>/dev/null || true

  echo "================================================================="
  echo "Updating Cloud Run Job: threat-detector"
  echo "================================================================="
  gcloud run jobs update threat-detector \
    --project="${PROJECT_ID}" \
    --region="${REGION}" \
    --image="${IMAGE_TAG}" 2>/dev/null || true
  echo "================================================================="
  echo "Updating Cloud Run Service: cymbal-cyber-soc-console"
  echo "================================================================="
  gcloud run deploy cymbal-cyber-soc-console \
    --project="${PROJECT_ID}" \
    --region="${REGION}" \
    --image="${IMAGE_TAG}" \
    --service-account="cymbal-adk-agent-sa@${PROJECT_ID}.iam.gserviceaccount.com" \
    --command="python" \
    --args="-m,streamlit,run,src/demo/soc_ticketing/streamlit_soc_console.py,--server.port=8080,--server.address=0.0.0.0,--server.enableCORS=false,--server.enableXsrfProtection=false,--browser.gatherUsageStats=false" \
    --set-env-vars="PROJECT_ID=${PROJECT_ID},GOOGLE_CLOUD_PROJECT=${PROJECT_ID},GOOGLE_CLOUD_LOCATION=${REGION},BIGQUERY_DATASET=Cymbal_Cyber,ESCALATION_BUCKET=cymbal-cyber-adk-escalations-bucket_${PROJECT_ID},SCREENSHOTS_BUCKET=cymbal-cyber-screenshots_${PROJECT_ID},LOCAL_MODE=false" \
    --port=8080 \
    --cpu=1 \
    --memory=2Gi \
    --min-instances=0 \
    --max-instances=5 \
    --no-allow-unauthenticated \
    --quiet 2>/dev/null || true
fi

echo "================================================================="
echo "Deployment Complete!"
echo "- Webhook Service : cymbal-cyber-adk-agent"
echo "- Scheduled Job   : threat-detector"
SOC_CONSOLE_URL="$(gcloud run services describe cymbal-cyber-soc-console --project="${PROJECT_ID}" --region="${REGION}" --format="value(status.url)" 2>/dev/null || true)"
if [ -n "${SOC_CONSOLE_URL}" ]; then
  echo "- SOC Console     : ${SOC_CONSOLE_URL}"
fi
echo "- Image           : ${IMAGE_TAG}"
echo "================================================================="
echo ""
echo "================================================================="
echo "Live Verification Workflow:"
echo "0. Ensure Application Default Credentials (ADC) are active:"
echo "   gcloud auth application-default login"
echo ""
echo "1. Publish synthetic threat telemetry to Pub/Sub:"
echo "   PYTHONPATH=src uv run python -m demo.data_generator.log_generator --mode threat --threat-type malicious --user u.lewis --sink=pubsub"
echo ""
echo "2. Allow 60s for BigQuery Storage Write API buffer ingestion:"
echo "   echo \"Allowing 60s for BigQuery streaming buffer ingestion...\" && sleep 60"
echo ""
echo "3. Trigger the Threat Detector job:"
echo "   gcloud run jobs execute threat-detector --project=${PROJECT_ID} --region=${REGION}"
echo "================================================================="

