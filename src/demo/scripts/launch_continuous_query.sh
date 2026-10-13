#!/usr/bin/env bash
# ==============================================================================
# Cymbal Cyber — BigQuery Continuous Query Launch Script
#
# PREREQUISITE:
# Requires an active BigQuery Enterprise Edition reservation with a CONTINUOUS
# assignment (provisioned via Terraform with enable_continuous_query = true).
#
# ⚠️ CRITICAL BILLING NOTICE:
# BigQuery Enterprise reservations bill continuously 24/7 at ~$0.06/slot-hour
# (~$6.00/hour or ~$4,320/month for 100 baseline slots) WHETHER OR NOT A QUERY IS RUNNING!
# Canceling the continuous query job DOES NOT stop slot charges.
# To stop billing completely, you MUST disable the reservation in Terraform:
#   terraform apply -var="project_id=<PROJECT_ID>" -var="enable_continuous_query=false"
# ==============================================================================

set -euo pipefail

PROJECT_ID="${1:-${GOOGLE_CLOUD_PROJECT:-}}"
PROJECT_ID="$(echo -n "${PROJECT_ID}" | tr -d '[:space:]' | tr -d '"' | tr -d "'" | tr '[:upper:]' '[:lower:]')"

if [[ -z "$PROJECT_ID" ]]; then
  echo "Error: GCP Project ID must be specified as an argument or set in GOOGLE_CLOUD_PROJECT." >&2
  echo "Usage: ./launch_continuous_query.sh <PROJECT_ID>" >&2
  exit 1
fi

CQ_SA_EMAIL="bq-continuous-query-sa@${PROJECT_ID}.iam.gserviceaccount.com"
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
echo "Topic:   projects/$PROJECT_ID/topics/cymbal_cyber_alerts"
echo "SA:      $CQ_SA_EMAIL"
echo "Cost:    ~$6.00/hour (~$4,320/month for 100 slots) continuously while reservation exists."
echo "NOTE:    Canceling the query saves no money; set enable_continuous_query=false"
echo "         in Terraform to stop Enterprise slot billing!"
echo "======================================================================"

echo "Submitting Continuous Query job as service account: $CQ_SA_EMAIL..."
bq query \
  --project_id="$PROJECT_ID" \
  --use_legacy_sql=false \
  --continuous=true \
  --connection_property=service_account="$CQ_SA_EMAIL" \
  < "$TMP_SQL"

echo ""
echo "✅ Continuous Query submitted successfully as $CQ_SA_EMAIL!"
echo "To monitor or cancel the running continuous query job:"
echo "  bq ls --jobs --project_id=$PROJECT_ID --max_results=10"
echo "  bq cancel <JOB_ID>"
echo ""
echo "⚠️  REMINDER: To stop slot charges, destroy the reservation in Terraform:"
echo "  terraform apply -var=\"project_id=$PROJECT_ID\" -var=\"enable_continuous_query=false\""
