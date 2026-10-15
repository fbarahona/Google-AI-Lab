# Cymbal Cyber Security AI — Infrastructure as Code (Terraform)

This Terraform module provisions the complete enterprise infrastructure for the Cymbal Cyber Security AI platform:

- **BigQuery Analytical Lakehouse**: Datasets (`Cymbal_Cyber`), scalar SQL UDFs (`calculate_threat_score`, `is_malicious_*`), partitioned tables (`user_access_events`, `network_events`, `alerts`, `soc_tickets`), views (`soc_tickets_current`, `incidents`), a BigLake object table over the screenshots bucket (`user_screenshots_objects`) and a protobuf data contract on the raw telemetry topic.
- **Pub/Sub Telemetry Streaming**: Event ingestion topics, BigQuery direct-write subscriptions, dead-letter queues (DLQ), and agent push subscriptions.
- **Multi-Agent Cloud Run Services**: Containerized ADK multi-agent orchestrator (`cymbal-cyber-adk-agent`), the MCP tool service it calls (`cymbal-cyber-mcp`, its own identity), and interactive SOC console (`cymbal-cyber-soc-console`).
- **Scheduled Micro-Batch Threat Detector**: Cloud Run Job (`threat-detector`) invoked on a cron schedule via Cloud Scheduler.
- **Cloud Storage Evidence Buckets**: Raw logs, staging, multimodal desktop screenshots, and human escalation queues.
- **Granular Least-Privilege IAM**: Service accounts for the ADK Agent (no evidence or ticket access), the MCP tool service (evidence reads and ticket writes; invocable only by the agent), SOC console, Continuous Query, Pub/Sub Invoker, and Threat Detector.

---

## State Management: GCS Remote Backend

State lives in a versioned Cloud Storage bucket (`backend.tf`), so it survives devcontainer rebuilds and is shared by every machine that deploys. `backend.tf` holds no project ID; the bucket is passed at init:

```bash
terraform init -backend-config="bucket=<PROJECT_ID>-tfstate"
```

`./src/demo/scripts/deploy_cloud.sh` creates the bucket (versioning, uniform access, public access prevention) and runs this init on every deploy. Terraform authenticates with Application Default Credentials (`gcloud auth application-default login`), never a static access token.

### One-time migration from local state
If `terraform.tfstate` still exists in this directory:

```bash
terraform init -migrate-state -backend-config="bucket=<PROJECT_ID>-tfstate"
mv terraform.tfstate terraform.tfstate.migrated
```

If local state was already lost and resources exist in GCP, run `./src/demo/scripts/tf_adopt_existing.sh <PROJECT_ID> [REGION]` once instead. The deploy script never imports resources.

---

## 🔐 Deployer Prerequisites: Minimum IAM Permissions

To execute `terraform apply` or run the automated deployment script, the deploying identity (user or CI/CD service account) requires administrative rights to provision resources **and** configure least-privilege workload IAM bindings:

| Domain | Role ID | Purpose |
| :--- | :--- | :--- |
| **Project IAM** | `roles/resourcemanager.projectIamAdmin` | **Required**: Grants project roles (`aiplatform.user`, `bigquery.jobUser`) to workload SAs. |
| **Service Accounts** | `roles/iam.serviceAccountAdmin` | Creates the workload SAs (`agent-sa`, `mcp-tools-sa`, `console-sa`, `invoker-sa`, `scheduler-sa`, `console-access`, `detector-sa`, and `cq-sa` when continuous queries are on). |
| **Service Account Actor** | `roles/iam.serviceAccountUser` | Authorizes attaching SAs to Cloud Run services and jobs (`actAs`). |
| **API Management** | `roles/serviceusage.serviceUsageAdmin` | Enables necessary Google Cloud APIs (`gcloud services enable`). |
| **BigQuery** | `roles/bigquery.admin` | Creates dataset `Cymbal_Cyber`, tables, SQL routines, and Vertex AI connections. |
| **Cloud Run** | `roles/run.admin` | Deploys container services (`adk-agent`, `mcp`, `soc-console`) and jobs (`threat-detector`). |
| **Pub/Sub** | `roles/pubsub.admin` | Creates telemetry topics, DLQ stores, and BigQuery direct subscriptions. |
| **Cloud Storage** | `roles/storage.admin` | Provisions evidence buckets and configures bucket-level IAM policies. |
| **Artifact Registry** | `roles/artifactregistry.admin` | Provisions Docker repo `cymbal-cyber` and configures push permissions. |
| **Cloud Build** | `roles/cloudbuild.builds.editor` | Submits remote container builds (`gcloud builds submit`). |
| **Cloud Scheduler** | `roles/cloudscheduler.admin` | Provisions the threat detector cron trigger. |
| **Billing Check** | `roles/billing.viewer` | Permits pre-flight billing verification (`gcloud billing projects describe`). |

> [!WARNING]
> **Why `roles/editor` is NOT sufficient:**  
> Standard `roles/editor` cannot modify IAM policies (`resourcemanager.projects.setIamPolicy` is forbidden). Because our Terraform configuration declares least-privilege `google_project_iam_member` and resource-level `*_iam_member` bindings, `roles/editor` will fail during `terraform apply`. The deployer must possess `roles/resourcemanager.projectIamAdmin` or the individual admin roles above.

### Automated Role Assignment Script
```bash
PROJECT_ID="<YOUR_PROJECT_ID>"
DEPLOYER_EMAIL="<DEPLOYER_EMAIL>"  # e.g., deployer@example.com or sa@project.iam.gserviceaccount.com

if [[ "${DEPLOYER_EMAIL}" == *".gserviceaccount.com"* ]]; then
  MEMBER="serviceAccount:${DEPLOYER_EMAIL}"
else
  MEMBER="user:${DEPLOYER_EMAIL}"
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
```

---

## Deployment & Teardown

### Full Pipeline Automated Rollout
```bash
./src/demo/scripts/deploy_cloud.sh <PROJECT_ID> <REGION>
```

### Manual Terraform Workflow
```bash
terraform init
terraform plan -var="project_id=<PROJECT_ID>"
terraform apply -var="project_id=<PROJECT_ID>"
```

### Infrastructure Teardown
```bash
terraform destroy -var="project_id=<PROJECT_ID>"
```

> [!NOTE]
> By default, destroying this module preserves Google Cloud APIs (`disable_on_destroy = false`) and non-force-destroyed Cloud Storage buckets containing historical data.
