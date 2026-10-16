# Cloud Deployment & Operations Runbook

This guide covers the end-to-end cloud deployment, post-deployment operations, console access, and FinOps teardown procedures for the **Real-Time Cybersecurity AI & ADK Platform** on Google Cloud Platform (project `${PROJECT_ID}`).

> [!TIP]
> **3-Step Quickstart (Recommended):**
> ```bash
> # 1. Authenticate gcloud & Application Default Credentials (ADC)
> gcloud auth login --update-adc
>
> # 2. Run the interactive pre-flight script (validates billing, binds IAM roles, and writes .env)
> source ./src/demo/scripts/pre_flight.sh
>
> # 3. Deploy the platform to Google Cloud
> ./src/demo/scripts/deploy_cloud.sh "${PROJECT_ID}" "${REGION}"
> ```

---

## 📋 Table of Contents
1. [Prerequisites & Deployer IAM Roles](#1-prerequisites--deployer-iam-roles)
2. [Environment & IAM Role Setup](#2-environment--iam-role-setup)
   - [Option A: Interactive Pre-Flight Script (Recommended)](#option-a-interactive-pre-flight-script-recommended)
   - [Option B: Manual CLI Role Assignment & Environment Setup](#option-b-manual-cli-role-assignment--environment-setup)
3. [Deployment Workflows](#3-deployment-workflows)
   - [Option A: One-Command Deployment Script (Recommended)](#option-a-one-command-deployment-script-recommended)
   - [Option B: Manual Step-by-Step Deployment](#option-b-manual-step-by-step-deployment)
4. [Live Cloud Verification Workflow](#4-live-cloud-verification-workflow)
5. [Accessing Cloud Consoles (SOC Portal & ADK Playground)](#5-accessing-cloud-consoles-soc-portal--adk-playground)
   - [Option 1: Proxied Access via gcloud (Recommended)](#option-1-proxied-access-via-gcloud-recommended)
   - [Option 2: Direct HTTPS Access](#option-2-direct-https-access)
   - [Agent Webhook: Not Callable by Humans](#agent-webhook-not-callable-by-humans)
6. [FinOps: Cost Management & Cloud Teardown](#6-finops-cost-management--cloud-teardown)

---

## 1. Prerequisites & Deployer IAM Roles

To execute `./src/demo/scripts/deploy_cloud.sh` or run `terraform apply`, the deploying identity (user account or CI/CD service account) requires administrative rights to provision resources **and** configure least-privilege workload IAM bindings:

| Domain | Role ID | Purpose |
| :--- | :--- | :--- |
| **Project IAM** | `roles/resourcemanager.projectIamAdmin` | **Required**: Grants project roles (`aiplatform.user`, `bigquery.jobUser`) to workload SAs. |
| **Service Accounts** | `roles/iam.serviceAccountAdmin` | Creates the workload SAs (`agent-sa`, `mcp-tools-sa`, `console-sa`, `invoker-sa`, `scheduler-sa`, `console-access`, `detector-sa`, and `cq-sa` when continuous queries are on). |
| **Service Account Actor** | `roles/iam.serviceAccountUser` | Authorizes attaching SAs to Cloud Run services and jobs (`actAs`). |
| **API Management** | `roles/serviceusage.serviceUsageAdmin` | Enables necessary Google Cloud APIs (`gcloud services enable`). |
| **BigQuery** | `roles/bigquery.admin` | Creates dataset `Cymbal_Cyber`, tables, and SQL routines. |
| **Cloud Run** | `roles/run.admin` | Deploys container services (`adk-agent`, `mcp`, `soc-console`) and jobs (`threat-detector`). |
| **Pub/Sub** | `roles/pubsub.admin` | Creates telemetry topics, DLQ stores, and BigQuery direct subscriptions. |
| **Cloud Storage** | `roles/storage.admin` | Provisions evidence buckets and configures bucket-level IAM policies. |
| **Artifact Registry** | `roles/artifactregistry.admin` | Provisions Docker repo `cymbal-cyber` and configures push permissions. |
| **Cloud Build** | `roles/cloudbuild.builds.editor` | Submits remote container builds (`gcloud builds submit`). |
| **Cloud Scheduler** | `roles/cloudscheduler.admin` | Provisions the threat detector cron trigger. |
| **Billing Check** | `roles/billing.viewer` | Permits `deploy_cloud.sh` pre-flight billing verification (`gcloud billing projects describe`). |

> [!WARNING]
> **Why `roles/editor` is NOT sufficient:**  
> Standard `roles/editor` cannot modify IAM policies (`resourcemanager.projects.setIamPolicy` is forbidden). Because our Terraform configuration declares least-privilege `google_project_iam_member` and resource-level `*_iam_member` bindings, `roles/editor` will fail during `terraform apply`. The deployer must possess `roles/resourcemanager.projectIamAdmin` or the individual admin roles above.

---

## 2. Environment & IAM Role Setup

Before initiating your first deployment, configure your environment variables and grant the required IAM roles using either the interactive pre-flight script (**Option A**) or manual CLI commands (**Option B**).

### Option A: Interactive Pre-Flight Script (Recommended)

Run `src/demo/scripts/pre_flight.sh` to interactively validate your GCP Project ID, region, and emails, verify active project billing, bind least-privilege IAM roles (Admin, Deployer, and optional SOC Data Analyst), and automatically populate your `.env` file and current shell session:

```bash
# 1. Authenticate gcloud CLI and Application Default Credentials (once per session)
gcloud auth login --update-adc

# 2. Source the pre-flight script so exported variables persist in your current terminal
source ./src/demo/scripts/pre_flight.sh
```

What `pre_flight.sh` does automatically:
1. **Validates Inputs:** Prompts for `PROJECT_ID`, `REGION` (defaults to `us-east1`), `ADMIN_EMAIL` (defaults to your active `gcloud` account), `DEPLOYER_EMAIL` (defaults to `ADMIN_EMAIL`), and an optional `ANALYST_EMAIL`.
2. **Verifies Active Billing:** Checks `gcloud billing projects describe` before making any IAM changes and halts early if billing is disabled.
3. **Assigns IAM Roles:** Resolves `user:`, `serviceAccount:`, or `group:` member prefixes and binds the required Admin, Deployer, Analyst, and Billing Viewer roles after confirmation.
4. **Populates `.env` & ADC Quota Project:** Safely upserts `PROJECT_ID`, `REGION`, `GOOGLE_CLOUD_PROJECT`, `GOOGLE_CLOUD_LOCATION="global"`, `GOOGLE_GENAI_USE_ENTERPRISE="true"`, `GEMINI_MODEL="gemini-3.8-flash"`, and `ADK_ALLOW_CONFIG_STDIO_MCP_SERVERS="true"` into `.env` and aligns your ADC quota project.

*(If you run `./src/demo/scripts/pre_flight.sh` directly instead of `source`, load the generated `.env` into your current shell afterward with `set -a && source .env && set +a`.)*

---

### Option B: Manual CLI Role Assignment & Environment Setup

If you prefer manual CLI setup or are configuring a headless CI/CD environment without interactive prompts:

```bash
export PROJECT_ID="<your-gcp-project-id>"
export REGION="us-east1"
export ADMIN_EMAIL="<your-email@domain.com>"  # e.g., deployer@example.com or sa@project.iam.gserviceaccount.com

if [[ "${ADMIN_EMAIL}" == *".gserviceaccount.com"* ]]; then
  MEMBER="serviceAccount:${ADMIN_EMAIL}"
else
  MEMBER="user:${ADMIN_EMAIL}"
fi

ROLES=(
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
  "roles/billing.viewer"
)

echo "Granting minimum deployment roles to ${MEMBER} in ${PROJECT_ID}..."
for role in "${ROLES[@]}"; do
  gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
    --member="${MEMBER}" \
    --role="${role}" \
    --condition=None \
    --quiet
done

# Configure local Application Default Credentials (ADC) quota project
gcloud auth application-default login
gcloud auth application-default set-quota-project "${PROJECT_ID}"
```

---

## 3. Deployment Workflows

### Option A: One-Command Deployment Script (Recommended)

Once you have completed [Section 2](#2-environment--iam-role-setup), run `deploy_cloud.sh` to handle API enablement, Terraform provisioning, Cloud Build container compilation, Cloud Run service deployment, and Cloud Scheduler configuration:

```bash
./src/demo/scripts/deploy_cloud.sh "${PROJECT_ID}" "${REGION}"
```

- **Credentials:** Terraform uses Application Default Credentials, which refresh themselves, so long applies don't fail when a token expires. The script stops early if ADC is missing.
- **State:** Terraform state lives in `gs://${PROJECT_ID}-tfstate` (versioned; created by the script). Rebuilding the devcontainer loses nothing, so there are no import steps and no 409 conflicts. If an older local `terraform.tfstate` still exists, the script stops and prints the one-time `terraform init -migrate-state` command.
- **Images:** Tagged with the git commit (`cymbal-cyber-agent:<sha>`). A clean checkout reuses the image already built for that commit; set `FORCE_BUILD=true` to rebuild. Uncommitted changes get a `<sha>-dirty-<timestamp>` tag and always build. `:latest` points at the newest image but nothing deploys from it.
- **Lost state before migrating:** run `./src/demo/scripts/tf_adopt_existing.sh ${PROJECT_ID} ${REGION}` once, then `terraform plan`.

---

### Option B: Manual Step-by-Step Deployment

If you prefer full control over each deployment step:

```bash
# 1. Enable Required APIs
gcloud services enable \
    bigqueryunified.googleapis.com \
    aiplatform.googleapis.com \
    pubsub.googleapis.com \
    iamcredentials.googleapis.com \
    cloudresourcemanager.googleapis.com \
    storage.googleapis.com \
    run.googleapis.com \
    cloudbuild.googleapis.com \
    artifactregistry.googleapis.com \
    cloudscheduler.googleapis.com \
    --project="${PROJECT_ID}"

# 2. Provision Infrastructure via Terraform (state in a versioned GCS bucket)
gcloud storage buckets create gs://${PROJECT_ID}-tfstate --project=${PROJECT_ID} --location=${REGION} \
    --uniform-bucket-level-access --public-access-prevention
gcloud storage buckets update gs://${PROJECT_ID}-tfstate --versioning
cd src/demo/terraform
terraform init -backend-config="bucket=${PROJECT_ID}-tfstate"
terraform apply -var="project_id=${PROJECT_ID}" -var="region=${REGION}" -auto-approve
cd ../../..

# 3. Build & Push Unified Container Image
IMAGE_TAG="${REGION}-docker.pkg.dev/${PROJECT_ID}/cymbal-cyber/cymbal-cyber-agent:$(git rev-parse --short=12 HEAD)"
gcloud builds submit --project="${PROJECT_ID}" --tag="${IMAGE_TAG}" .

# 4. Roll the image out to the Cloud Run services (MCP tool service first: the agent calls it)
for service in cymbal-cyber-mcp cymbal-cyber-adk-agent cymbal-cyber-soc-console; do
  gcloud run services update "${service}" \
    --project="${PROJECT_ID}" \
    --region="${REGION}" \
    --image="${IMAGE_TAG}"
done

# 5. Deploy Cloud Run Job (Threat Detector Micro-Batch Job)
gcloud run jobs update threat-detector \
  --project="${PROJECT_ID}" \
  --region="${REGION}" \
  --image="${IMAGE_TAG}"
```

---

## 4. Live Cloud Verification Workflow

Verify that the deployed cloud pipeline processes live security telemetry end-to-end:

> **Behind a TLS-intercepting proxy** (corporate network, some devcontainers): if a step fails with `CERTIFICATE_VERIFY_FAILED` / `self-signed certificate in certificate chain`, point each client at the system CA bundle, which includes the proxy's root:
> ```bash
> # gRPC clients: the Pub/Sub publisher (Step B) and the console in cloud mode
> export GRPC_DEFAULT_SSL_ROOTS_FILE_PATH=/etc/ssl/certs/ca-certificates.crt
> # bq ignores that variable; pass its own flag on every call (Steps F and G)
> bq --ca_certificates_file=/etc/ssl/certs/ca-certificates.crt query ...
> ```
> Never disable certificate verification instead.

```bash
# Step A: Ensure local Application Default Credentials (ADC) are active
gcloud auth application-default login

# Step B: Publish synthetic malicious threat scenario to Cloud Pub/Sub
uv run python -m src.demo.data_generator.log_generator \
  --mode threat \
  --threat-type malicious \
  --user u.lewis \
  --sink=pubsub

# Step C: Allow 60s for BigQuery Storage Write API buffer ingestion
# (Freshly provisioned BigQuery subscriptions take 30-90s to commit records to streaming buffers)
echo "Allowing 60s for BigQuery streaming buffer ingestion..."
sleep 60

# Step D: Execute a detection pass and wait for it to finish
gcloud run jobs execute threat-detector \
  --project="${PROJECT_ID}" \
  --region="${REGION}" \
  --wait

# Step E: Read the latest execution's logs
EXECUTION="$(gcloud run jobs executions list --job=threat-detector \
  --project="${PROJECT_ID}" --region="${REGION}" --limit=1 --format='value(name)')"
gcloud beta run jobs executions logs read "${EXECUTION}" \
  --project="${PROJECT_ID}" --region="${REGION}"

# Step F: One injection is one incident: the first window is published to the agent
# (NEW, then DONE once adjudicated), the rest are CORRELATED under the same incident_id
bq query --use_legacy_sql=false \
  "SELECT alert_id, incident_id, status, total_2_min_threat_score
   FROM \`${PROJECT_ID}.Cymbal_Cyber.alerts\` WHERE user_id = 'u.lewis' ORDER BY window_end"

# Step G: The incidents view rolls those windows into one row
bq query --use_legacy_sql=false \
  "SELECT * FROM \`${PROJECT_ID}.Cymbal_Cyber.incidents\` WHERE user_id = 'u.lewis'"

# Step H: The tools ran in the MCP tool service, as its own identity
gcloud logging read 'resource.type="cloud_run_revision" AND resource.labels.service_name="cymbal-cyber-mcp"' \
  --project="${PROJECT_ID}" --freshness=30m --limit=20 --format='value(timestamp, textPayload)'

# Step I: Nobody but the agent can call the tools (expect 403 from Cloud Run IAM)
MCP_URL="$(gcloud run services describe cymbal-cyber-mcp --project="${PROJECT_ID}" \
  --region="${REGION}" --format='value(status.url)')"
curl -s -o /dev/null -w '%{http_code}\n' -X POST "${MCP_URL}/mcp"
```

---

## 5. Accessing Cloud Consoles (SOC Portal & ADK Playground)

Both Cloud Run services are deployed with IAM authentication (`--no-allow-unauthenticated`) to protect sensitive security telemetry. You can access the consoles using either an **authenticated local proxy** (recommended) or **direct HTTPS**.

### Option 1: Proxied Access via `gcloud` (Recommended)

The `gcloud run services proxy` command securely tunnels web traffic through your authenticated CLI identity:

> [!TIP]
> If your environment has `gcloud` installed via a package manager (`apt-get`), install the proxy component once before running:
> ```bash
> sudo apt-get update && sudo apt-get install -y google-cloud-cli-cloud-run-proxy
> ```

#### Interactive SOC Analyst Console (Streamlit):
The proxy authenticates with an ID token for `soc-console-access`, a service account that holds `roles/run.invoker` on the console only. Terraform lets `deployer_member` (and anyone in `console_access_members`) mint tokens for it. Its tokens carry the console URL as their audience, which Cloud Run always accepts; a plain user token from `gcloud auth print-identity-token` carries the OAuth client as audience and can be rejected with `401 Unauthorized`. Do not use `pubsub-invoker-sa` for this: it is reserved for Pub/Sub pushes to the agent webhook.
```bash
CONSOLE_SA="soc-console-access@${PROJECT_ID}.iam.gserviceaccount.com"
CONSOLE_URL="$(gcloud run services describe cymbal-cyber-soc-console \
  --project="${PROJECT_ID}" --region="${REGION}" --format="value(status.url)")"

gcloud run services proxy cymbal-cyber-soc-console \
  --project="${PROJECT_ID}" \
  --region="${REGION}" \
  --port=8501 \
  --token="$(gcloud auth print-identity-token \
    --impersonate-service-account="${CONSOLE_SA}" --audiences="${CONSOLE_URL}")"
```
The token lasts one hour; restart the proxy to refresh it. `401` means the token was rejected (check the `--token` step printed no error); `403` means the token is fine but the invoker grant is missing or still propagating (allow a few minutes after a new grant).
Open **`http://localhost:8501`** in your browser to view the incident queue, triage tickets, and inspect visual evidence.

#### ADK Agent Web Playground (off by default):
The cloud agent service serves only the Pub/Sub webhook. The ADK web UI, `/run`, session and A2A APIs, and `/docs` are not routed, because they run investigations as the agent SA without the webhook's OIDC check. Even then, the playground's tools run in the MCP tool service as its own identity, exactly as in the webhook path. For a supervised demo, turn it on by deploying with the flag (Terraform reads it from the environment; a plain `deploy_cloud.sh` run turns it off again):
```bash
TF_VAR_enable_adk_dev_ui=true ./src/demo/scripts/deploy_cloud.sh "${PROJECT_ID}"
```
The flag also lets `soc-console-access` invoke the agent service, so you open it the same way as the console, with an impersonated token whose audience is the agent URL:
```bash
CONSOLE_SA="soc-console-access@${PROJECT_ID}.iam.gserviceaccount.com"
AGENT_URL="$(gcloud run services describe cymbal-cyber-adk-agent \
  --project="${PROJECT_ID}" --region="${REGION}" --format="value(status.url)")"

gcloud run services proxy cymbal-cyber-adk-agent \
  --project="${PROJECT_ID}" \
  --region="${REGION}" \
  --port=8080 \
  --token="$(gcloud auth print-identity-token \
    --impersonate-service-account="${CONSOLE_SA}" --audiences="${AGENT_URL}")"
```
Open **`http://localhost:8080/dev-ui/`** for the playground, pick `adk_agent`, and paste an alert (for example `investigate user c.wilson`). A plain-text prompt carries no alert, so the ticket names the user the evidence tools ran for and shows Device and Origin IP as "Not in alert"; paste the alert JSON instead (for example `investigate {"alert_id": "c.wilson|2026-10-15T05:00:00Z", "user_id": "c.wilson", "device_id": "ws-dev-10", "source_ip": "10.0.4.21", "total_2_min_threat_score": 100, "window_end": "2026-10-15T05:00:00Z"}`) to fill the whole header. The flag also sets `ALLOW_ORIGINS` to the proxy's local addresses (`adk_dev_ui_origins`, default ports 8080 on localhost and 127.0.0.1); without it ADK refuses to create a session ("Failed to create session") because the browser's origin is the proxy, not the run.app URL. If you proxy on another port, add it to that variable. Sessions live in memory on one instance, so a session can disappear if Cloud Run scales to another instance; start a new one if that happens. When the demo is over, deploy again without the variable: that turns the UI off and removes the extra invoker grant. Locally, `LOCAL_MODE=true agents-cli playground` needs no flag.

---

### Option 2: Direct HTTPS Access

1. **Retrieve the live service URLs:**
   ```bash
   gcloud run services describe cymbal-cyber-soc-console \
     --project="${PROJECT_ID}" \
     --region="${REGION}" \
     --format="value(status.url)"

   gcloud run services describe cymbal-cyber-adk-agent \
     --project="${PROJECT_ID}" \
     --region="${REGION}" \
     --format="value(status.url)"
   ```

2. **Call it with an ID token:**  
   A browser opening the URL directly gets `403 Forbidden`, because it sends no ID token; use the proxy (Option 1) for the console. For scripted checks, pass the same impersonated token as a header:
   ```bash
   curl -H "Authorization: Bearer $(gcloud auth print-identity-token \
     --impersonate-service-account="${CONSOLE_SA}" --audiences="${CONSOLE_URL}")" "${CONSOLE_URL}"
   ```
   The agent URL answers only Pub/Sub pushes.

3. **No public access:**  
   Do not grant `allUsers` the invoker role. The console shows security telemetry and tickets, and domain-restricted sharing org policies reject the binding anyway (`FAILED_PRECONDITION`).

---

### Agent Webhook: Not Callable by Humans

The agent's `/apps/adk_agent/trigger/pubsub` endpoint is the Pub/Sub push target, and nothing else may call it. Cloud Run checks the ID token's audience (a plain `gcloud auth print-identity-token` user token gets `401`), and the app itself then rejects any caller other than `pubsub-invoker-sa` with `403` (`verify_incoming_oidc_token` in `adk_agent/fast_api_app.py`). The body must also be a Pub/Sub push envelope carrying an alert. A hand-made `curl` therefore cannot succeed, by design.

To exercise the webhook, run the [Live Cloud Verification Workflow](#4-live-cloud-verification-workflow): the detector publishes the alert, Pub/Sub pushes it as `pubsub-invoker-sa`, and the alert reaching `DONE` in Step F proves the agent received and adjudicated it. The agent's request logs are in Cloud Logging:

```bash
gcloud logging read 'resource.type="cloud_run_revision" AND resource.labels.service_name="cymbal-cyber-adk-agent"' \
  --project="${PROJECT_ID}" --freshness=1h --limit=50
```

---

## 6. FinOps: Cost Management & Cloud Teardown

### Zero-Continuous-Cost Serverless Baseline
Terraform defaults to a **$0 continuous-cost baseline** by avoiding continuous slot reservations or dedicated streaming VMs:
- **Default Trigger Path ($0/month continuous):** Cloud Scheduler triggers the `threat-detector` Cloud Run Job every 5 minutes via OAuth, evaluating 2-minute tumbling windows via standard BigQuery on-demand queries.
- **Continuous Queries Warning (`enable_continuous_query = true`):** Requires a 100-slot Enterprise Edition reservation. Slot reservations bill 24/7 at **~$0.06/slot-hour = ~$6.00/hour (~$4,320/month)** whether or not a query is running.
- **Dataflow Streaming Pipeline (`src/demo/scripts/run_dataflow_demo.sh`):** An optional Apache Beam ETL pipeline that provisions continuous streaming worker VMs (**~$100–$300/month**). Gated off by default.
- **Cloud Run & Vertex AI:** Billed on-demand per request execution duration and token usage.

### Automated Budget Alert
The Terraform configuration in `src/demo/terraform/deploy.tf` provisions an automated budget alert (`google_billing_budget.demo_budget`) with a $100 ceiling and 50% / 90% threshold notifications when supplied with your Billing Account ID:

```bash
cd src/demo/terraform
terraform apply -var="project_id=${PROJECT_ID}" -var="billing_account_id=<YOUR_BILLING_ACCOUNT_ID>"
```

### Complete Cloud Teardown
To avoid unexpected billing, tear down cloud infrastructure immediately after testing:

```bash
cd src/demo/terraform
terraform destroy -var="project_id=${PROJECT_ID}"
```
*(All BigQuery datasets and Cloud Storage buckets are configured with `delete_contents_on_destroy = true` and `force_destroy = true` so teardown succeeds cleanly without manual bucket purging).*

