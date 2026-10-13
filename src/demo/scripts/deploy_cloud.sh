#!/usr/bin/env bash
# ==============================================================================
# Cloud Deployment Script: ADK Multi-Agent Service & Threat Detector Job
# ==============================================================================
# Builds the unified container image and updates both:
# 1. Cloud Run Service: cymbal-cyber-adk-agent (Webhook & Multi-Agent Orchestrator)
# 2. Cloud Run Job: threat-detector (Scheduled Micro-Batch Detection Job)
# ==============================================================================
set -euo pipefail

PROJECT_ID="${GOOGLE_CLOUD_PROJECT:-${1:-}}"
REGION="${GOOGLE_CLOUD_LOCATION:-${2:-us-east1}}"

# Strip accidental whitespace, quotes, and force lowercase for Docker/Artifact Registry compliance
export PROJECT_ID="$(echo -n "${PROJECT_ID}" | tr -d '[:space:]' | tr -d '"' | tr -d "'" | tr '[:upper:]' '[:lower:]')"
export REGION="$(echo -n "${REGION}" | tr -d '[:space:]' | tr -d '"' | tr -d "'" | tr '[:upper:]' '[:lower:]')"

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

# Validation guard: Verify active billing is enabled for the target GCP project
if command -v gcloud >/dev/null 2>&1; then
  echo "Validating billing status for project: ${PROJECT_ID}..."
  gcloud billing projects describe "${PROJECT_ID}" --format="value(billingEnabled)" 2>/dev/null | grep -q "true" || {
    echo "Error: Billing is not enabled for project ${PROJECT_ID}"
    exit 1
  }

  echo "Enabling essential Google Cloud APIs..."
  gcloud services enable \
    run.googleapis.com \
    pubsub.googleapis.com \
    bigquery.googleapis.com \
    bigquerystorage.googleapis.com \
    artifactregistry.googleapis.com \
    cloudscheduler.googleapis.com \
    --project="${PROJECT_ID}" --quiet || true
fi

ARTIFACT_REPO="${ARTIFACT_REPO:-cymbal-cyber}"
IMAGE_TAG="${REGION}-docker.pkg.dev/${PROJECT_ID}/${ARTIFACT_REPO}/cymbal-cyber-agent:latest"

echo "================================================================="
echo "Building unified container image: ${IMAGE_TAG}"
echo "Project: ${PROJECT_ID} | Region: ${REGION}"
echo "================================================================="

# Pre-flight Docker & Artifact Registry Setup:
# 1. Explicitly configure Docker credential helper for Artifact Registry regional domain.
#    Standard 'gcloud auth configure-docker' only registers legacy gcr.io hosts.
# 2. Ensure Artifact Registry repository exists prior to pushing to prevent 404 Not Found.
if command -v gcloud >/dev/null 2>&1; then
  echo "Configuring Docker authentication for Artifact Registry (${REGION}-docker.pkg.dev)..."
  gcloud auth configure-docker "${REGION}-docker.pkg.dev" --quiet

  if ! gcloud artifacts repositories describe "${ARTIFACT_REPO}" --location="${REGION}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
    echo "Provisioning Artifact Registry repository (${ARTIFACT_REPO})..."
    gcloud artifacts repositories create "${ARTIFACT_REPO}" \
      --repository-format=docker \
      --location="${REGION}" \
      --description="Cymbal Cyber Agent Registry" \
      --project="${PROJECT_ID}"
  fi
fi

# 1. Build & Push Image (anchored to repository root where Dockerfile resides)
if command -v docker >/dev/null 2>&1; then
  echo "Building and pushing container image with Docker: ${IMAGE_TAG}..."
  docker build -t "${IMAGE_TAG}" -f "${REPO_ROOT}/Dockerfile" "${REPO_ROOT}"
  docker push "${IMAGE_TAG}"
elif command -v gcloud >/dev/null 2>&1; then
  echo "Docker CLI not detected; building image remotely via Cloud Build..."
  gcloud builds submit \
    --project="${PROJECT_ID}" \
    --tag="${IMAGE_TAG}" \
    "${REPO_ROOT}"
else
  echo "Error: Neither docker nor gcloud is available to build and push the container."
  exit 1
fi

# 2. Target Terraform directory explicitly
if command -v terraform >/dev/null 2>&1 && [ -d "${TERRAFORM_DIR}" ]; then
  echo "================================================================="
  echo "Applying Terraform configuration: ${TERRAFORM_DIR}"
  echo "================================================================="
  if [ ! -d "${TERRAFORM_DIR}/.terraform" ]; then
    echo "Initializing Terraform..."
    terraform -chdir="${TERRAFORM_DIR}" init
  fi

  # If Artifact Registry repository exists in GCP, ensure it is imported into Terraform state to prevent 409 Conflict
  if command -v gcloud >/dev/null 2>&1 && gcloud artifacts repositories describe "${ARTIFACT_REPO}" --location="${REGION}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
    if ! terraform -chdir="${TERRAFORM_DIR}" state list 2>/dev/null | grep -q "google_artifact_registry_repository.agent_repo"; then
      echo "Importing Artifact Registry repository into Terraform state..."
      terraform -chdir="${TERRAFORM_DIR}" import \
        -var="project_id=${PROJECT_ID}" \
        -var="region=${REGION}" \
        -var="agent_image=${IMAGE_TAG}" \
        -var="gemini_api_key=${GEMINI_API_KEY:-}" \
        google_artifact_registry_repository.agent_repo \
        "projects/${PROJECT_ID}/locations/${REGION}/repositories/${ARTIFACT_REPO}" 2>/dev/null || true
    fi
  fi

  terraform -chdir="${TERRAFORM_DIR}" apply -auto-approve \
    -var="project_id=${PROJECT_ID}" \
    -var="region=${REGION}" \
    -var="agent_image=${IMAGE_TAG}" \
    -var="gemini_api_key=${GEMINI_API_KEY:-}"
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
fi

echo "================================================================="
echo "Deployment Complete!"
echo "- Webhook Service : cymbal-cyber-adk-agent"
echo "- Scheduled Job   : threat-detector"
echo "- Image           : ${IMAGE_TAG}"
echo "================================================================="
echo ""
echo "================================================================="
echo "Live Verification Workflow:"
echo "1. Publish synthetic threat telemetry to Pub/Sub:"
echo "   PYTHONPATH=src uv run python -m demo.data_generator.log_generator --mode threat --threat-type malicious --user u.lewis --sink=pubsub"
echo ""
echo "2. Allow 60s for BigQuery Storage Write API buffer ingestion:"
echo "   echo \"Allowing 60s for BigQuery streaming buffer ingestion...\" && sleep 60"
echo ""
echo "3. Trigger the Threat Detector job:"
echo "   gcloud run jobs execute threat-detector --project=${PROJECT_ID} --region=${REGION}"
echo "================================================================="

