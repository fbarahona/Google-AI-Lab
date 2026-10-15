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

# The deployed services call Gemini on Vertex AI with their service accounts. No API key
# is read or passed to Terraform, so none ends up in Cloud Run env or Terraform state.

# Terraform authenticates with Application Default Credentials, which the provider refreshes
# itself. A static GOOGLE_OAUTH_ACCESS_TOKEN would take precedence and expire after about an
# hour, failing long applies partway, so never pass one through.
unset GOOGLE_OAUTH_ACCESS_TOKEN
if command -v terraform >/dev/null 2>&1 && command -v gcloud >/dev/null 2>&1; then
  if ! gcloud auth application-default print-access-token >/dev/null 2>&1; then
    echo "Error: Application Default Credentials are not set up for Terraform."
    echo "Run once (and again after rebuilding the devcontainer unless gcloud config is mounted):"
    echo "  gcloud auth application-default login"
    echo "  gcloud auth application-default set-quota-project ${PROJECT_ID}"
    exit 1
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
BUILD_SOURCE_BUCKET="${PROJECT_ID}_cloudbuild"
IMAGE_REPO="${REGION}-docker.pkg.dev/${PROJECT_ID}/${ARTIFACT_REPO}/cymbal-cyber-agent"

# Tag images with the git commit so every deployed image traces back to its source.
# A clean checkout reuses an existing image for the same commit (set FORCE_BUILD=true to
# rebuild); uncommitted changes or no git get a unique tag and always build.
FORCE_BUILD="${FORCE_BUILD:-false}"
if GIT_SHA="$(git -C "${REPO_ROOT}" rev-parse --short=12 HEAD 2>/dev/null)"; then
  if [ -n "$(git -C "${REPO_ROOT}" status --porcelain 2>/dev/null)" ]; then
    IMAGE_VERSION="${GIT_SHA}-dirty-$(date -u +%Y%m%d%H%M%S)"
    FORCE_BUILD="true"
    echo "WARNING: Working tree has uncommitted changes; building image ${IMAGE_VERSION}."
  else
    IMAGE_VERSION="${GIT_SHA}"
  fi
else
  IMAGE_VERSION="build-$(date -u +%Y%m%d%H%M%S)"
  FORCE_BUILD="true"
  echo "WARNING: Not a git checkout; building image ${IMAGE_VERSION}."
fi
IMAGE_TAG="${IMAGE_REPO}:${IMAGE_VERSION}"

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
  # State lives in a versioned GCS bucket so it survives devcontainer rebuilds. The bucket
  # name is passed at init (backend.tf holds no project ID).
  TF_STATE_BUCKET="${TF_STATE_BUCKET:-${PROJECT_ID}-tfstate}"
  if command -v gcloud >/dev/null 2>&1 && ! gcloud storage buckets describe "gs://${TF_STATE_BUCKET}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
    echo "Creating Terraform state bucket gs://${TF_STATE_BUCKET}..."
    gcloud storage buckets create "gs://${TF_STATE_BUCKET}" \
      --project="${PROJECT_ID}" \
      --location="${REGION}" \
      --uniform-bucket-level-access \
      --public-access-prevention
    gcloud storage buckets update "gs://${TF_STATE_BUCKET}" --versioning
  fi

  # Refuse to start from empty remote state while a local state file still holds resources.
  LOCAL_STATE="${TERRAFORM_DIR}/terraform.tfstate"
  if [ -s "${LOCAL_STATE}" ] && grep -q '"type"' "${LOCAL_STATE}"; then
    echo "Error: Found local Terraform state at ${LOCAL_STATE}."
    echo "Migrate it to the GCS backend once, then move the local file aside:"
    echo "  terraform -chdir=${TERRAFORM_DIR} init -migrate-state -backend-config=\"bucket=${TF_STATE_BUCKET}\""
    echo "  mv ${LOCAL_STATE} ${LOCAL_STATE}.migrated"
    exit 1
  fi

  echo "Initializing Terraform (state: gs://${TF_STATE_BUCKET})..."
  terraform -chdir="${TERRAFORM_DIR}" init -input=false -backend-config="bucket=${TF_STATE_BUCKET}"

  # 1a. Ensure repository resource is provisioned and reconciled in Terraform first
  terraform -chdir="${TERRAFORM_DIR}" apply -auto-approve \
    -target=google_artifact_registry_repository.agent_repo \
    -var="project_id=${PROJECT_ID}" \
    -var="region=${REGION}" \
    "${DEPLOYER_VAR[@]}"

  # 1b. Cloud Build stages source in this bucket; the build identity may read only it.
  if command -v gcloud >/dev/null 2>&1 && ! gcloud storage buckets describe "gs://${BUILD_SOURCE_BUCKET}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
    echo "Creating Cloud Build source bucket gs://${BUILD_SOURCE_BUCKET}..."
    gcloud storage buckets create "gs://${BUILD_SOURCE_BUCKET}" \
      --project="${PROJECT_ID}" \
      --location=US \
      --uniform-bucket-level-access \
      --public-access-prevention
  fi

  # 1c. Provision repository build & push IAM permissions (now guaranteed to succeed because repo exists)
  TARGET_IAM_OPTS=(
    -target=google_artifact_registry_repository_iam_member.compute_sa_writer
    -target=google_storage_bucket_iam_member.compute_sa_build_source_viewer
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
if [[ "${FORCE_BUILD}" != "true" ]] && command -v gcloud >/dev/null 2>&1 && gcloud artifacts docker images describe "${IMAGE_TAG}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
  echo "Container image already exists in Artifact Registry: ${IMAGE_TAG}"
  echo "Reusing the image built for this commit (set FORCE_BUILD=true to rebuild)..."
elif command -v docker >/dev/null 2>&1; then
  echo "Building and pushing container image with Docker: ${IMAGE_TAG}..."
  docker build -t "${IMAGE_TAG}" -f "${REPO_ROOT}/Dockerfile" "${REPO_ROOT}"
  docker push "${IMAGE_TAG}"
elif command -v gcloud >/dev/null 2>&1; then
  echo "Submitting container image build to Cloud Build (--async)..."
  # IAM granted in step 1 can take a minute or more to propagate, so the first submit
  # may fail with storage.objects.get denied on the source tarball. Retry before failing.
  BUILD_SUBMIT_MAX_ATTEMPTS=4
  BUILD_SUBMIT_ATTEMPT=1
  until BUILD_ID=$(gcloud builds submit \
    --project="${PROJECT_ID}" \
    --tag="${IMAGE_TAG}" \
    --gcs-source-staging-dir="gs://${BUILD_SOURCE_BUCKET}/source" \
    --async \
    --format="value(id)" \
    "${REPO_ROOT}" | tr -d '[:space:]') && [ -n "${BUILD_ID}" ]; do
    if [ "${BUILD_SUBMIT_ATTEMPT}" -ge "${BUILD_SUBMIT_MAX_ATTEMPTS}" ]; then
      echo "Error: Cloud Build submit failed after ${BUILD_SUBMIT_MAX_ATTEMPTS} attempts."
      exit 1
    fi
    echo "Cloud Build submit failed (commonly IAM propagation delay for the build service account)."
    echo "Waiting 60 seconds before retry (${BUILD_SUBMIT_ATTEMPT}/${BUILD_SUBMIT_MAX_ATTEMPTS})..."
    sleep 60
    BUILD_SUBMIT_ATTEMPT=$((BUILD_SUBMIT_ATTEMPT + 1))
  done
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

# :latest is only a convenience pointer to the newest image; nothing deploys from it.
if command -v gcloud >/dev/null 2>&1; then
  gcloud artifacts docker tags add "${IMAGE_TAG}" "${IMAGE_REPO}:latest" --quiet >/dev/null 2>&1 || \
    echo "WARNING: Could not move the :latest tag to ${IMAGE_TAG}."
fi

# 4. Apply complete Terraform configuration
if command -v terraform >/dev/null 2>&1 && [ -d "${TERRAFORM_DIR}" ]; then
  echo "================================================================="
  echo "3. Applying complete Terraform configuration: ${TERRAFORM_DIR}"
  echo "================================================================="

  TF_APPLY_MAX_ATTEMPTS=3
  TF_APPLY_ATTEMPT=1
  until terraform -chdir="${TERRAFORM_DIR}" apply -auto-approve \
    -var="project_id=${PROJECT_ID}" \
    -var="region=${REGION}" \
    -var="agent_image=${IMAGE_TAG}" \
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

# 4. Roll the new image out. Terraform owns every other setting of these workloads (it
# ignores only the image), so this changes the image and nothing else, and any failure
# stops the script before it reports success.
if command -v gcloud >/dev/null 2>&1; then
  for service in cymbal-cyber-adk-agent cymbal-cyber-soc-console; do
    echo "================================================================="
    echo "Rolling out ${IMAGE_TAG} to Cloud Run service: ${service}"
    echo "================================================================="
    gcloud run services update "${service}" \
      --project="${PROJECT_ID}" \
      --region="${REGION}" \
      --image="${IMAGE_TAG}" \
      --quiet
  done

  echo "================================================================="
  echo "Rolling out ${IMAGE_TAG} to Cloud Run job: threat-detector"
  echo "================================================================="
  gcloud run jobs update threat-detector \
    --project="${PROJECT_ID}" \
    --region="${REGION}" \
    --image="${IMAGE_TAG}" \
    --quiet
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
echo "   uv run python -m src.demo.data_generator.log_generator --mode threat --threat-type malicious --user u.lewis --sink=pubsub"
echo ""
echo "2. Allow 60s for BigQuery Storage Write API buffer ingestion:"
echo "   echo \"Allowing 60s for BigQuery streaming buffer ingestion...\" && sleep 60"
echo ""
echo "3. Trigger the Threat Detector job:"
echo "   gcloud run jobs execute threat-detector --project=${PROJECT_ID} --region=${REGION}"
echo "================================================================="

