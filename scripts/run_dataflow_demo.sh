#!/usr/bin/env bash
# ==============================================================================
# Optional On-Demand Dataflow Streaming Demo Launcher
# ==============================================================================
# Launches an Apache Beam streaming pipeline on Google Cloud Dataflow with 1 worker.
# Designed for live interactive demonstrations, to be drained after testing.
# ==============================================================================

set -euo pipefail

PROJECT_ID="${GOOGLE_CLOUD_PROJECT:-oso-ai-503519}"
REGION="${GOOGLE_CLOUD_LOCATION:-us-east1}"
DATASET_ID="${BIGQUERY_DATASET:-Cymbal_Cyber}"
BUCKET_NAME="cymbal_cyber_adk_staging_bucket_${PROJECT_ID}"
JOB_NAME="demo-pubsub-to-bigquery-$(date +%s)"

echo "=========================================================="
echo "🚀 Launching Optional On-Demand Dataflow Streaming Demo"
echo "=========================================================="
echo "Project ID:    ${PROJECT_ID}"
echo "Region:        ${REGION}"
echo "Job Name:      ${JOB_NAME}"
echo "Staging GCS:   gs://${BUCKET_NAME}/dataflow_staging"
echo "=========================================================="

python3 src/demo/data_pipeline/pubsub_to_bigquery_dataflow.py \
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

