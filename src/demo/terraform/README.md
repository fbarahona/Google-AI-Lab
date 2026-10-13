# Cymbal Cyber Security AI — Infrastructure as Code (Terraform)

This Terraform module provisions the complete enterprise infrastructure for the Cymbal Cyber Security AI platform:

- **BigQuery Analytical Lakehouse**: Datasets (`Cymbal_Cyber`), scalar SQL UDFs (`calculate_threat_score`, `is_malicious_*`), partitioned tables (`user_access_events`, `network_events`, `alerts`, `soc_tickets`), and BigLake object tables (`user_screenshots_view`).
- **Pub/Sub Telemetry Streaming**: Event ingestion topics, BigQuery direct-write subscriptions, dead-letter queues (DLQ), and agent push subscriptions.
- **Multi-Agent Cloud Run Services**: Containerized ADK multi-agent orchestrator (`cymbal-cyber-adk-agent`) and interactive SOC console (`cymbal-cyber-soc-console`).
- **Scheduled Micro-Batch Threat Detector**: Cloud Run Job (`threat-detector`) invoked on a cron schedule via Cloud Scheduler.
- **Cloud Storage Evidence Buckets**: Raw logs, staging, multimodal desktop screenshots, and human escalation queues.
- **Granular Least-Privilege IAM**: Service accounts for ADK Agent, Continuous Query, Pub/Sub Invoker, and Threat Detector.

---

## State Management: Enterprise Remote Backend vs. Brownfield Discovery

### 1. Enterprise Remote State Backend (Recommended)
To prevent "split-brain" state desynchronization across developer devcontainers, Cloud Shell, and CI/CD runners, configure a dedicated Cloud Storage backend with distributed state locking:

```bash
# 1. Create the dedicated state bucket with object versioning enabled (run once):
gcloud storage buckets create gs://<PROJECT_ID>-tfstate --project=<PROJECT_ID> --location=us-east1
gcloud storage buckets update gs://<PROJECT_ID>-tfstate --versioning

# 2. Copy the template and insert your project ID:
cp backend.tf.example backend.tf
sed -i "s/<PROJECT_ID>/your-project-id/g" backend.tf

# 3. Initialize Terraform with state migration:
terraform init -migrate-state
```

### 2. Brownfield Import Loops (Transitional Discovery)
If deploying into an existing environment with unmanaged pre-existing resources, the automated deployment script (`./src/demo/scripts/deploy_cloud.sh`) includes idempotent import loops that probe GCP APIs and auto-adopt existing resources into state prior to `terraform apply`.

---

## 🔐 Deployer Prerequisites: Minimum IAM Permissions

To execute `terraform apply` or run the automated deployment script, the deploying identity (user or CI/CD service account) requires administrative rights to provision resources **and** configure least-privilege workload IAM bindings:

| Domain | Role ID | Purpose |
| :--- | :--- | :--- |
| **Project IAM** | `roles/resourcemanager.projectIamAdmin` | **Required**: Grants project roles (`aiplatform.user`, `bigquery.jobUser`) to workload SAs. |
| **Service Accounts** | `roles/iam.serviceAccountAdmin` | Creates the 4 workload SAs (`agent-sa`, `cq-sa`, `invoker-sa`, `detector-sa`). |
| **Service Account Actor** | `roles/iam.serviceAccountUser` | Authorizes attaching SAs to Cloud Run services and jobs (`actAs`). |
| **API Management** | `roles/serviceusage.serviceUsageAdmin` | Enables necessary Google Cloud APIs (`gcloud services enable`). |
| **BigQuery** | `roles/bigquery.admin` | Creates dataset `Cymbal_Cyber`, tables, SQL routines, and Vertex AI connections. |
| **Cloud Run** | `roles/run.admin` | Deploys container services (`adk-agent`, `soc-console`) and jobs (`threat-detector`). |
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