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

IMAGE_TAG="gcr.io/${PROJECT_ID}/cymbal-cyber-agent:latest"

echo "================================================================="
echo "Building unified container image: ${IMAGE_TAG}"
echo "Project: ${PROJECT_ID} | Region: ${REGION}"
echo "================================================================="

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

