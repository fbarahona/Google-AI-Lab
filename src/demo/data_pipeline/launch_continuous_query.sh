#!/usr/bin/env bash
# ==============================================================================
# Cymbal Cyber — BigQuery Continuous Query Launch Script
#
# PREREQUISITE:
# Requires an active BigQuery Enterprise Edition reservation with a CONTINUOUS
# assignment (provisioned via Terraform with enable_continuous_query = true).
#
# ⚠️ COST WARNING:
# 100 Enterprise slots bill continuously at ~$0.06/slot-hour = ~$6.00/hour (~$4,320/month).
# Cancel the continuous query when testing completes to stop slot consumption!
# ==============================================================================

set -euo pipefail

PROJECT_ID="${1:-${GOOGLE_CLOUD_PROJECT:-}}"

if [[ -z "$PROJECT_ID" ]]; then
  echo "Error: GCP Project ID must be specified as an argument or set in GOOGLE_CLOUD_PROJECT." >&2
  echo "Usage: ./launch_continuous_query.sh <PROJECT_ID>" >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SQL_TEMPLATE="$SCRIPT_DIR/continuous_query.sql"
TMP_SQL="$(mktemp /tmp/continuous_query_rendered_XXXXXX.sql)"

trap 'rm -f "$TMP_SQL"' EXIT

echo "Rendering continuous query SQL for project: $PROJECT_ID..."
sed "s/\${project_id}/$PROJECT_ID/g" "$SQL_TEMPLATE" > "$TMP_SQL"

echo "======================================================================"
echo "⚠️  BIGQUERY CONTINUOUS QUERY EXECUTION"
echo "Project: $PROJECT_ID"
echo "Dataset: Cymbal_Cyber"
echo "Pub/Sub: cymbal_cyber_alerts"
echo "Reservation Requirement: Enterprise slots (job_type = CONTINUOUS)"
echo "Estimated Cost: ~$6.00/hour (~$4,320/month for 100 slots)"
echo "======================================================================"

echo "Submitting Continuous Query job to BigQuery..."
bq query \
  --project_id="$PROJECT_ID" \
  --use_legacy_sql=false \
  --continuous=true \
  < "$TMP_SQL"

echo ""
echo "✅ Continuous Query submitted successfully!"
echo "To monitor or cancel running continuous queries:"
echo "  bq ls --jobs --project_id=$PROJECT_ID --max_results=10"
echo "  bq cancel <JOB_ID>"
