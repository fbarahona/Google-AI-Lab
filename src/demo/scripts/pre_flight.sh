#!/usr/bin/env bash
# ==============================================================================
# Pre-Flight Environment & IAM Setup Script
# ==============================================================================
# Interactive helper that:
# 1. Prompts for and validates PROJECT_ID, REGION, and role emails.
# 2. Verifies active GCP billing on the target project.
# 3. Assigns IAM roles: bootstrap roles for the Admin, deployment roles for a dedicated
#    deployer service account the Deployer impersonates (or the Deployer directly, if
#    declined). The Analyst gets no project roles: console access is granted by
#    Terraform when deploy_cloud.sh runs with ANALYST_EMAIL set.
# 4. Safely upserts environment variables into the repository root .env file.
#
# Usage:
#   source ./src/demo/scripts/pre_flight.sh   # (Recommended: exports vars into current shell)
#   ./src/demo/scripts/pre_flight.sh          # (Or run directly, then `set -a && source .env && set +a`)
# ==============================================================================

run_preflight() {
  local SCRIPT_DIR REPO_ROOT ENV_FILE
  SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
  ENV_FILE="${PREFLIGHT_ENV_FILE:-${REPO_ROOT}/.env}"

  echo "================================================================="
  echo "Pre-Flight Check & Environment Setup"
  echo "================================================================="
  echo "Follow the prompts to configure your GCP project, verify billing,"
  echo "assign IAM roles, and populate your .env file."
  echo ""

  die() {
    echo "  [Error] $1" >&2
    return 1
  }

  # ---------------------------------------------------------------------------
  # 0. Verify gcloud CLI Authentication
  # ---------------------------------------------------------------------------
  if ! command -v gcloud >/dev/null 2>&1; then
    die "gcloud CLI is not installed or not in PATH." || return 1
  fi

  local ACTIVE_ACCOUNT
  ACTIVE_ACCOUNT=$(gcloud auth list --filter=status:ACTIVE --format="value(account)" 2>/dev/null | head -n1 || true)
  if [[ -z "${ACTIVE_ACCOUNT}" ]]; then
    die "No active gcloud account found. Run 'gcloud auth login --update-adc' first." || return 1
  fi
  echo "Authenticated gcloud session: ${ACTIVE_ACCOUNT}"
  echo ""

  # ---------------------------------------------------------------------------
  # 1. Inputs & Interactive Prompts
  # ---------------------------------------------------------------------------
  local PROJECT_REGEX="^[a-z][a-z0-9-]{4,28}[a-z0-9]$"
  local REGION_REGEX="^[a-z]+-[a-z]+[0-9]+$"
  local EMAIL_REGEX="^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"

  local INPUT_PROJECT INPUT_REGION INPUT_ADMIN INPUT_DEPLOYER INPUT_ANALYST

  while true; do
    read -rp "Enter GCP Project ID: " INPUT_PROJECT || { echo ""; return 1; }
    if [[ "${INPUT_PROJECT}" =~ ${PROJECT_REGEX} ]]; then
      export PROJECT_ID="${INPUT_PROJECT}"
      break
    fi
    echo "  [Error] Invalid Project ID format (6-30 chars, lowercase letters, digits, hyphens)."
  done

  while true; do
    read -rp "Enter Target Compute Region [us-east1]: " INPUT_REGION || { echo ""; return 1; }
    INPUT_REGION="${INPUT_REGION:-us-east1}"
    if [[ "${INPUT_REGION}" =~ ${REGION_REGEX} ]]; then
      export REGION="${INPUT_REGION}"
      break
    fi
    echo "  [Error] Invalid region format (e.g., us-east1, us-central1, europe-west1). Note: 'global' is not a valid compute region."
  done

  while true; do
    read -rp "Enter Project Admin Email [${ACTIVE_ACCOUNT}]: " INPUT_ADMIN || { echo ""; return 1; }
    INPUT_ADMIN="${INPUT_ADMIN:-${ACTIVE_ACCOUNT}}"
    if [[ "${INPUT_ADMIN}" =~ ${EMAIL_REGEX} ]]; then
      export ADMIN_EMAIL="${INPUT_ADMIN}"
      break
    fi
    echo "  [Error] Invalid email format."
  done

  while true; do
    read -rp "Enter Deployer Email/Service Account [press Enter for ${ADMIN_EMAIL}]: " INPUT_DEPLOYER || { echo ""; return 1; }
    INPUT_DEPLOYER="${INPUT_DEPLOYER:-${ADMIN_EMAIL}}"
    if [[ "${INPUT_DEPLOYER}" =~ ${EMAIL_REGEX} ]]; then
      export DEPLOYER_EMAIL="${INPUT_DEPLOYER}"
      break
    fi
    echo "  [Error] Invalid email or service account format."
  done

  while true; do
    read -rp "Enter SOC Data Analyst Email [press Enter to skip]: " INPUT_ANALYST || { echo ""; return 1; }
    if [[ -z "${INPUT_ANALYST}" ]] || [[ "${INPUT_ANALYST}" =~ ${EMAIL_REGEX} ]]; then
      export ANALYST_EMAIL="${INPUT_ANALYST:-}"
      break
    fi
    echo "  [Error] Invalid email format."
  done

  # Deployment roles are owner-equivalent (they manage IAM). Holding them on a service
  # account the Deployer impersonates keeps them off the personal account.
  local INPUT_USE_SA
  read -rp "Run deployments as a dedicated deployer service account (recommended)? [Y/n]: " INPUT_USE_SA || { echo ""; return 1; }
  export DEPLOYER_SA=""
  if [[ ! "${INPUT_USE_SA}" =~ ^[Nn]$ ]]; then
    export DEPLOYER_SA="cymbal-deployer@${PROJECT_ID}.iam.gserviceaccount.com"
  fi

  # ---------------------------------------------------------------------------
  # 2. Pre-Flight Billing Verification
  # ---------------------------------------------------------------------------
  echo ""
  echo "Verifying billing for '${PROJECT_ID}'..."

  local BILLING_STATUS RAW_BILLING_ACCOUNT BILLING_ACCOUNT_ID
  if ! BILLING_STATUS=$(gcloud billing projects describe "${PROJECT_ID}" --format="value(billingEnabled)" 2>/dev/null); then
    die "Failed to query billing status. Verify authentication and project existence." || return 1
  fi

  if [[ "${BILLING_STATUS}" != "True" && "${BILLING_STATUS}" != "true" ]]; then
    die "Billing is NOT active on project '${PROJECT_ID}'." || return 1
  fi

  RAW_BILLING_ACCOUNT=$(gcloud billing projects describe "${PROJECT_ID}" --format="value(billingAccountName)" 2>/dev/null || true)
  BILLING_ACCOUNT_ID="${RAW_BILLING_ACCOUNT#billingAccounts/}"
  echo "Billing is active (Account: ${BILLING_ACCOUNT_ID:-unknown})."

  # ---------------------------------------------------------------------------
  # 3. Principal Resolution
  # ---------------------------------------------------------------------------
  format_member() {
    local id="$1"
    if [[ "${id}" == user:* || "${id}" == group:* || "${id}" == serviceAccount:* ]]; then
      echo "${id}"  # explicit prefix, e.g. group:soc@example.com
    elif [[ "${id}" == *".gserviceaccount.com" ]]; then
      echo "serviceAccount:${id}"
    elif [[ "${id}" == *"@googlegroups.com" ]]; then
      echo "group:${id}"
    else
      echo "user:${id}"
    fi
  }

  local ADMIN_MEMBER DEPLOYER_MEMBER ANALYST_MEMBER="" DEPLOY_ROLES_MEMBER
  ADMIN_MEMBER=$(format_member "${ADMIN_EMAIL}")
  DEPLOYER_MEMBER=$(format_member "${DEPLOYER_EMAIL}")
  [[ -n "${ANALYST_EMAIL}" ]] && ANALYST_MEMBER=$(format_member "${ANALYST_EMAIL}")
  DEPLOY_ROLES_MEMBER="${DEPLOYER_MEMBER}"
  [[ -n "${DEPLOYER_SA}" ]] && DEPLOY_ROLES_MEMBER="serviceAccount:${DEPLOYER_SA}"

  echo ""
  echo "=== IAM Assignment Plan ==="
  echo "Project ID : ${PROJECT_ID}"
  echo "Region     : ${REGION}"
  echo "Admin      : ${ADMIN_MEMBER}"
  if [[ -n "${DEPLOYER_SA}" ]]; then
    echo "Deployer   : ${DEPLOYER_MEMBER} (Token Creator on ${DEPLOYER_SA} only)"
    echo "Deploy SA  : ${DEPLOY_ROLES_MEMBER} (deployment roles)"
  else
    echo "Deployer   : ${DEPLOYER_MEMBER} (deployment roles)"
  fi
  echo "Analyst    : ${ANALYST_MEMBER:-[None]} (console access only, granted at deploy)"
  echo "==========================="
  local CONFIRM
  read -rp "Apply role bindings? [y/N]: " CONFIRM || { echo ""; return 1; }
  if [[ ! "${CONFIRM}" =~ ^[Yy]$ ]]; then
    echo "Operation cancelled."
    return 0
  fi

  # ---------------------------------------------------------------------------
  # 4. Role Assignments
  # ---------------------------------------------------------------------------
  bind_roles() {
    local member="$1"
    shift
    local roles=("$@")
    local role
    for role in "${roles[@]}"; do
      echo "  -> ${member} => ${role}"
      if ! gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
        --member="${member}" \
        --role="${role}" \
        --condition=None \
        --quiet > /dev/null; then
        die "Failed to bind role ${role} to ${member} on project ${PROJECT_ID}." || return 1
      fi
    done
  }

  local ADMIN_ROLES=(
    "roles/resourcemanager.projectIamAdmin"
    "roles/serviceusage.serviceUsageAdmin"
    "roles/viewer"
  )

  local DEPLOYER_ROLES=(
    "roles/resourcemanager.projectIamAdmin"
    "roles/serviceusage.serviceUsageAdmin"
    "roles/iam.serviceAccountAdmin"
    "roles/iam.serviceAccountUser"
    "roles/bigquery.admin"
    "roles/run.admin"
    "roles/pubsub.admin"
    "roles/storage.admin"
    "roles/artifactregistry.admin"
    "roles/cloudbuild.builds.editor"
    "roles/cloudscheduler.admin"
  )


  echo ""
  echo "Assigning Admin roles..."
  bind_roles "${ADMIN_MEMBER}" "${ADMIN_ROLES[@]}" || return 1

  if [[ -n "${DEPLOYER_SA}" ]]; then
    # Impersonation mints short-lived tokens through the IAM Credentials API.
    gcloud services enable iamcredentials.googleapis.com iam.googleapis.com \
      --project="${PROJECT_ID}" --quiet > /dev/null || { die "Failed to enable the IAM Credentials API."; return 1; }
    if ! gcloud iam service-accounts describe "${DEPLOYER_SA}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
      echo "Creating deployer service account ${DEPLOYER_SA}..."
      gcloud iam service-accounts create "${DEPLOYER_SA%%@*}" \
        --project="${PROJECT_ID}" \
        --display-name="Cymbal Cyber deployer (impersonated by deployers)" \
        --quiet > /dev/null || { die "Failed to create ${DEPLOYER_SA}."; return 1; }
    fi
    echo "Assigning deployment roles to ${DEPLOY_ROLES_MEMBER}..."
    bind_roles "${DEPLOY_ROLES_MEMBER}" "${DEPLOYER_ROLES[@]}" || return 1

    echo "Letting ${DEPLOYER_MEMBER} impersonate ${DEPLOYER_SA}..."
    if ! gcloud iam service-accounts add-iam-policy-binding "${DEPLOYER_SA}" \
      --project="${PROJECT_ID}" \
      --member="${DEPLOYER_MEMBER}" \
      --role="roles/iam.serviceAccountTokenCreator" \
      --condition=None \
      --quiet > /dev/null; then
      die "Failed to grant Token Creator on ${DEPLOYER_SA} to ${DEPLOYER_MEMBER}." || return 1
    fi
  else
    echo "Assigning Deployer roles..."
    if [[ "${DEPLOYER_MEMBER}" == "${ADMIN_MEMBER}" ]]; then
      # Avoid re-binding roles already applied in ADMIN_ROLES
      local DEDUPED_DEPLOYER_ROLES=(
        "roles/iam.serviceAccountAdmin"
        "roles/iam.serviceAccountUser"
        "roles/bigquery.admin"
        "roles/run.admin"
        "roles/pubsub.admin"
        "roles/storage.admin"
        "roles/artifactregistry.admin"
        "roles/cloudbuild.builds.editor"
        "roles/cloudscheduler.admin"
      )
      bind_roles "${DEPLOYER_MEMBER}" "${DEDUPED_DEPLOYER_ROLES[@]}" || return 1
    else
      bind_roles "${DEPLOYER_MEMBER}" "${DEPLOYER_ROLES[@]}" || return 1
    fi
  fi

  if [[ -n "${ANALYST_MEMBER}" ]]; then
    echo "Analyst ${ANALYST_MEMBER}: no project roles. deploy_cloud.sh grants console access"
    echo "  (Token Creator on soc-console-access) through Terraform."
  fi

  # ---------------------------------------------------------------------------
  # 5. Safe Upsert into .env & Export to Current Session
  # ---------------------------------------------------------------------------
  upsert_env_var() {
    local key="$1"
    local val="$2"
    local file="${ENV_FILE}"

    touch "${file}"

    # Escape backslashes, pipes, and ampersands for safe sed replacement
    local safe_val
    safe_val=$(printf '%s\n' "${val}" | sed -e 's/[\/&|]/\\&/g')

    if grep -q -E "^${key}=" "${file}"; then
      sed -i -E "s|^${key}=.*|${key}=\"${safe_val}\"|" "${file}"
    else
      echo "${key}=\"${val}\"" >> "${file}"
    fi
  }

  echo ""
  echo "Upserting variables into ${ENV_FILE}..."
  upsert_env_var "PROJECT_ID" "${PROJECT_ID}"
  upsert_env_var "REGION" "${REGION}"
  upsert_env_var "ADMIN_EMAIL" "${ADMIN_EMAIL}"
  upsert_env_var "DEPLOYER_EMAIL" "${DEPLOYER_EMAIL}"
  upsert_env_var "ANALYST_EMAIL" "${ANALYST_EMAIL}"
  upsert_env_var "DEPLOYER_SA" "${DEPLOYER_SA}"
  upsert_env_var "GOOGLE_GENAI_USE_ENTERPRISE" "true"
  upsert_env_var "GOOGLE_CLOUD_LOCATION" "global"
  upsert_env_var "GOOGLE_CLOUD_PROJECT" "${PROJECT_ID}"
  upsert_env_var "GEMINI_MODEL" "gemini-3.8-flash"

  export GOOGLE_GENAI_USE_ENTERPRISE="true"
  export GOOGLE_CLOUD_LOCATION="global"
  export GOOGLE_CLOUD_PROJECT="${PROJECT_ID}"
  export GEMINI_MODEL="gemini-3.8-flash"

  # Set ADC quota project if ADC credentials are already present
  if gcloud auth application-default print-access-token >/dev/null 2>&1; then
    gcloud auth application-default set-quota-project "${PROJECT_ID}" --quiet >/dev/null 2>&1 || true
  else
    echo ""
    echo "  [Note] Application Default Credentials (ADC) are not yet initialized."
    echo "  Run before deploying: gcloud auth application-default login"
  fi

  echo ""
  echo "Configuration complete! Updated entries in ${ENV_FILE}."

  if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "To load these variables into your current terminal session, run:"
    echo "  set -a && source .env && set +a"
  fi

  echo ""
  echo "Next step — deploy the platform to Google Cloud:"
  echo "  ./src/demo/scripts/deploy_cloud.sh \"\${PROJECT_ID}\" \"\${REGION}\""
}

run_preflight
__preflight_rc=$?
# Sourced runs would otherwise leave the helpers defined in the caller's shell.
unset -f run_preflight die format_member bind_roles upsert_env_var
return "${__preflight_rc}" 2>/dev/null || exit "${__preflight_rc}"
