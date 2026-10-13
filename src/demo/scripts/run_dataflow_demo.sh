#!/usr/bin/env bash
# ==============================================================================
# Optional On-Demand Dataflow Streaming Demo Launcher
# ==============================================================================
# Launches an Apache Beam streaming pipeline on Google Cloud Dataflow with 1 worker.
# Designed for live interactive demonstrations, to be drained after testing.
# ==============================================================================

set -euo pipefail

# ==============================================================================
# ARCHITECTURAL NOTICE (Ingestion Alternative):
# This Apache Beam Dataflow pipeline provides an alternative, custom ETL ingestion
# pipeline from Pub/Sub to BigQuery.
#
# DO NOT run this pipeline concurrently with the direct Pub/Sub BigQuery subscriptions
# deployed in Terraform. Running both simultaneously ingests duplicate log events into
# user_access_events and network_events, inflating aggregation scores.
# ==============================================================================

PROJECT_ID="${GOOGLE_CLOUD_PROJECT:-${1:-}}"
PROJECT_ID="$(echo -n "${PROJECT_ID}" | tr -d '[:space:]' | tr -d '"' | tr -d "'" | tr '[:upper:]' '[:lower:]')"
if [[ -z "${PROJECT_ID}" ]]; then
  echo "❌ Error: GOOGLE_CLOUD_PROJECT environment variable is not set and no project ID argument provided."
  echo "Usage: ./src/demo/scripts/run_dataflow_demo.sh [PROJECT_ID]"
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"

CANDIDATE_REGION="${GOOGLE_CLOUD_REGION:-${CLOUDSDK_COMPUTE_REGION:-${GOOGLE_CLOUD_LOCATION:-}}}"
if [ -z "${CANDIDATE_REGION}" ] || [ "${CANDIDATE_REGION}" == "global" ]; then
  CANDIDATE_REGION="us-east1"
fi
REGION="${CANDIDATE_REGION}"
REGION="$(echo -n "${REGION}" | tr -d '[:space:]' | tr -d '"' | tr -d "'" | tr '[:upper:]' '[:lower:]')"
DATASET_ID="${BIGQUERY_DATASET:-Cymbal_Cyber}"
BUCKET_NAME="cymbal_cyber_adk_staging_bucket_${PROJECT_ID}"
JOB_NAME="demo-pubsub-to-bigquery-$(date +%s)"

echo "=========================================================="
echo "🚀 Launching Optional On-Demand Dataflow Streaming Ingestion"
echo "=========================================================="
echo "Project ID:    ${PROJECT_ID}"
echo "Region:        ${REGION}"
echo "Job Name:      ${JOB_NAME}"
echo "Staging GCS:   gs://${BUCKET_NAME}/dataflow_staging"
echo "Notice:        Replaces direct Pub/Sub-to-BQ subscriptions for ETL demo"
echo "=========================================================="

python3 "${REPO_ROOT}/src/demo/data_pipeline/pubsub_to_bigquery_dataflow.py" \
  --project="${PROJECT_ID}" \
  --runner="DataflowRunner" \
  --region="${REGION}" \
  --temp_location="gs://${BUCKET_NAME}/temp" \
  --staging_location="gs://${BUCKET_NAME}/staging" \
  --job_name="${JOB_NAME}" \
  --max_num_workers=1 \
  --num_workers=1

echo ""
echo "✅ Dataflow job successfully submitted: ${JOB_NAME}"
echo "To drain the job after the demonstration completes, run:"
echo "  gcloud dataflow jobs drain --region=${REGION} \$(gcloud dataflow jobs list --region=${REGION} --status=active --filter='name:${JOB_NAME}' --format='value(id)')"

