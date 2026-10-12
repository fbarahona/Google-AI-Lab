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

if [ -z "${PROJECT_ID}" ]; then
  echo "Error: GOOGLE_CLOUD_PROJECT environment variable or argument is required."
  echo "Usage: ./src/demo/deploy_cloud.sh <PROJECT_ID> [REGION]"
  exit 1
fi

# Validation guard: Verify active billing is enabled for the target GCP project
if command -v gcloud >/dev/null 2>&1; then
  echo "Validating billing status for project: ${PROJECT_ID}..."
  gcloud billing projects describe "${PROJECT_ID}" --format="value(billingEnabled)" 2>/dev/null | grep -q "true" || {
    echo "Error: Billing is not enabled for project ${PROJECT_ID}"
    exit 1
  }
fi

IMAGE_TAG="${REGION}-docker.pkg.dev/${PROJECT_ID}/cymbal-cyber/cymbal-cyber-agent:latest"

echo "================================================================="
echo "Building unified container image: ${IMAGE_TAG}"
echo "Project: ${PROJECT_ID} | Region: ${REGION}"
echo "================================================================="

# Note: Cloud Build (gcloud builds submit) authenticates and pushes remotely on GCP.
# Docker credential helpers are configured only if local docker CLI is present.
if command -v docker >/dev/null 2>&1 && command -v gcloud >/dev/null 2>&1; then
  echo "Configuring Docker authentication..."
  gcloud auth configure-docker --quiet 2>/dev/null || true
  gcloud auth configure-docker "${REGION}-docker.pkg.dev" --quiet 2>/dev/null || true
fi

# 1. Build & Push Image via Cloud Build
gcloud builds submit \
  --project="${PROJECT_ID}" \
  --tag="${IMAGE_TAG}" \
  .

echo "================================================================="
echo "Updating Cloud Run Service: cymbal-cyber-adk-agent"
echo "================================================================="

# 2. Deploy Cloud Run Service (ADK Agent Webhook)
gcloud run deploy cymbal-cyber-adk-agent \
  --project="${PROJECT_ID}" \
  --region="${REGION}" \
  --image="${IMAGE_TAG}"

echo "================================================================="
echo "Updating Cloud Run Job: threat-detector"
echo "================================================================="

# 3. Update Cloud Run Job (Threat Detector micro-batch job)
gcloud run jobs update threat-detector \
  --project="${PROJECT_ID}" \
  --region="${REGION}" \
  --image="${IMAGE_TAG}"

echo "================================================================="
echo "Deployment Complete!"
echo "- Webhook Service : cymbal-cyber-adk-agent"
echo "- Scheduled Job   : threat-detector"
echo "- Image           : ${IMAGE_TAG}"
echo "================================================================="

