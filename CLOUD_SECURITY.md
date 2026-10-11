# Cloud Security & IAM Architecture Guide

This guide details the security baseline, IAM role requirements, separation of operational duties, and manual/automated configuration procedures for the **Real-Time Cybersecurity AI & ADK Platform** on Google Cloud Platform.

---

## 🛡️ Architecture & Security Model: Principle of Least Privilege

In enterprise security engineering, granting broad administrative roles across all components introduces lateral movement risks and violates the principle of least privilege. This architecture enforces **strict separation of duties** across four distinct identity tiers:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           SECURITY IDENTITY TIERS                           │
├─────────────────────────────────────────────────────────────────────────────┤
│ 1. Bootstrap / Provisioning Identity (CI/CD Pipeline or Cloud Admin)        │
│    - One-time resource creation, IAM bindings, API enablement               │
│    - Elevated: Project IAM Admin, Storage Admin, Vertex AI Admin            │
├─────────────────────────────────────────────────────────────────────────────┤
│ 2. Day-2 Operator & SOC Analyst Identity (Human Incident Responder)         │
│    - Daily operations: Run Streamlit console, review tickets, query logs   │
│    - Least-Privilege: BigQuery User & DataViewer, Storage ObjectViewer      │
│    - ZERO administrative, IAM mutation, or storage deletion permissions     │
├─────────────────────────────────────────────────────────────────────────────┤
│ 3. Application Runtime Workload Identity (`bq-continuous-query-sa`)         │
│    - Automated daemon, Continuous Queries, Pub/Sub, ADK Agent server        │
│    - Scoped execution: BigQuery dataEditor on dataset, Pub/Sub publisher,   │
│      Storage objectUser on escalations, self-impersonation for V4 URLs      │
├─────────────────────────────────────────────────────────────────────────────┤
│ 4. Platform Connection Identity (`continuous-query-vertex-ai-connection`)   │
│    - Managed by BigQuery for Vertex AI foundation model & object queries    │
│    - Read-only inference & storage access: Vertex AI User, Object Viewer    │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 📌 Prerequisites & Variables

Set your deployment parameters in your shell:

```bash
export PROJECT_ID="<your-gcp-project-id>"
export ADMIN_EMAIL="<your-admin-email@domain.com>"
export ANALYST_EMAIL="<your-analyst-email@domain.com>"
export REGION="us-east1"
export BQ_LOCATION="US"
```

---

## 1. Required Google Cloud APIs

Ensure the following 7 core APIs are enabled in your target project:

| API Service Name | Identifier | Purpose |
|---|---|---|
| **BigQuery Unified API** | `bigqueryunified.googleapis.com` | High-throughput query processing and continuous queries |
| **BigQuery Connection API** | `bigqueryconnection.googleapis.com` | Remote connections to Vertex AI and Cloud Storage |
| **Vertex AI API** | `aiplatform.googleapis.com` | Gemini model endpoints and Agent Runtime |
| **Cloud Pub/Sub API** | `pubsub.googleapis.com` | Streaming event bus for raw logs and continuous alerts |
| **IAM Service Account Credentials API** | `iamcredentials.googleapis.com` | Generation of short-lived tokens and V4 signed URLs |
| **Cloud Resource Manager API** | `cloudresourcemanager.googleapis.com` | Managing IAM policy bindings and metadata |
| **Google Cloud Storage JSON API** | `storage.googleapis.com` | Storing screenshots, raw logs, and escalation files |

### Enable via CLI:
```bash
gcloud services enable \
    bigqueryunified.googleapis.com \
    bigqueryconnection.googleapis.com \
    aiplatform.googleapis.com \
    pubsub.googleapis.com \
    iamcredentials.googleapis.com \
    cloudresourcemanager.googleapis.com \
    storage.googleapis.com \
    --project="${PROJECT_ID}"
```

---

## 2. Human Identity Access Control: Provisioning vs. Day-2 Operations

To demonstrate rigorous security engineering, human identities must not share monolithic administrative permissions. Initial bootstrapping is separated from day-to-day operational analysis.

### 2A. Day-2 Operator & SOC Analyst (Least-Privilege Human Baseline)

Human analysts investigating alerts, reviewing desktop screenshots, and using the interactive Streamlit SOC console require only **4 least-privilege roles**. They do not have rights to alter IAM policies, delete buckets, or modify infrastructure.

| Role Name | IAM Role ID | Purpose |
|---|---|---|
| **BigQuery User** | `roles/bigquery.user` | Run read-only diagnostic and investigative queries |
| **BigQuery Data Viewer** | `roles/bigquery.dataViewer` | View event logs, threat continuous queries, and ticket tables |
| **Storage Object Viewer** | `roles/storage.objectViewer` | View desktop screenshots and escalation metadata in GCS |
| **Vertex AI User** | `roles/aiplatform.user` | Query Gemini models for assisted threat triage |

#### Grant Day-2 Analyst Roles via CLI:
```bash
ANALYST_ROLES=(
  "roles/bigquery.user"
  "roles/bigquery.dataViewer"
  "roles/storage.objectViewer"
  "roles/aiplatform.user"
)

for role in "${ANALYST_ROLES[@]}"; do
  echo "Granting $role to ${ANALYST_EMAIL}..."
  gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
    --member="user:${ANALYST_EMAIL}" \
    --role="$role" \
    --condition=None
done
```

---

### 2B. Bootstrap / Provisioning Identity (Admin / Terraform CI/CD Only)

During initial project provisioning, a deployment identity (such as a Terraform service account in CI/CD or a designated cloud administrator) requires elevated permissions to create datasets, external connections, service accounts, and buckets.

> ⚠️ **Production Security Note:** In enterprise environments, these elevated roles should be assigned to an automated CI/CD pipeline or granted via Privileged Access Management (PAM) / Just-In-Time (JIT) access with an expiration window, rather than held permanently by personal user accounts.

| Role Name | IAM Role ID | Provisioning Purpose |
|---|---|---|
| **BigQuery Data Editor** | `roles/bigquery.dataEditor` | Create initial tables, schemas, and views |
| **BigQuery Connection Admin** | `roles/bigquery.connectionAdmin` | Establish BigLake / Vertex AI external connection |
| **BigQuery Resource Editor** | `roles/bigquery.resourceEditor` | Allocate query slots and continuous query reservations |
| **Storage Admin** | `roles/storage.admin` | Create buckets for screenshots and escalation archives |
| **Service Account Admin** | `roles/iam.serviceAccountAdmin` | Provision application runtime service accounts |
| **Project IAM Admin** | `roles/resourcemanager.projectIamAdmin` | Bind scoped IAM roles to service accounts |
| **Pub/Sub Editor** | `roles/pubsub.editor` | Provision alerting topics and dead-letter subscriptions |
| **Vertex AI Administrator** | `roles/aiplatform.admin` | Configure Vertex AI agent endpoints and foundation model access |

#### Grant Bootstrap Roles (Temporary / Admin Only):
```bash
BOOTSTRAP_ROLES=(
  "roles/bigquery.dataEditor"
  "roles/bigquery.connectionAdmin"
  "roles/bigquery.resourceEditor"
  "roles/bigquery.user"
  "roles/storage.admin"
  "roles/iam.serviceAccountAdmin"
  "roles/iam.serviceAccountUser"
  "roles/iam.serviceAccountTokenCreator"
  "roles/resourcemanager.projectIamAdmin"
  "roles/pubsub.editor"
  "roles/aiplatform.admin"
)

for role in "${BOOTSTRAP_ROLES[@]}"; do
  echo "Granting $role to ${ADMIN_EMAIL} for initial provisioning..."
  gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
    --member="user:${ADMIN_EMAIL}" \
    --role="$role" \
    --condition=None
done
```

---

## 3. BigQuery Remote Connection (`continuous-query-vertex-ai-connection`)

BigQuery requires an external Cloud Resource connection to query object tables (forensic screenshots in GCS) and invoke remote Vertex AI foundation models (`gemini-3.8-flash`).

### Least-Privilege Role Assignment:
The generated connection service account (`bqcx-...`) requires strictly **two read/user roles**:
1. **Vertex AI User** (`roles/aiplatform.user`): To execute remote `ML.GENERATE_TEXT` calls.
2. **Storage Object Viewer** (`roles/storage.objectViewer`): To read screenshot PNG objects referenced in BigLake object tables.

### Setup Procedure:
```bash
# 1. Create connection
bq mk --connection \
    --location="${BQ_LOCATION}" \
    --project_id="${PROJECT_ID}" \
    --connection_type=CLOUD_RESOURCE \
    continuous-query-vertex-ai-connection

# 2. Extract generated Service Account ID
CONNECTION_SA=$(bq show --connection "${PROJECT_ID}.${BQ_LOCATION}.continuous-query-vertex-ai-connection" \
    --format=json | jq -r '.cloudResource.serviceAccountId')
echo "Connection Service Account: ${CONNECTION_SA}"

# 3. Grant scoped IAM permissions to the Connection SA
gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
    --member="serviceAccount:${CONNECTION_SA}" \
    --role="roles/aiplatform.user"

gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
    --member="serviceAccount:${CONNECTION_SA}" \
    --role="roles/storage.objectViewer"
```

---

## 4. Application Workload Runtime Identity (`bq-continuous-query-sa`)

The deployed application runs headless workloads (BigQuery Continuous Queries, Pub/Sub event processing, background threat scanner daemon, and ADK agent server). It executes under a dedicated non-human service account: `bq-continuous-query-sa`.

### Runtime Roles & Least-Privilege Rationale:

| Role Name | IAM Role ID | Rationale |
|---|---|---|
| **BigQuery User** | `roles/bigquery.user` | Run queries and initiate query jobs |
| **BigQuery Data Editor** | `roles/bigquery.dataEditor` | Insert incident rows into `adk_threat_assessment` and `soc_tickets` |
| **BigQuery Connection User** | `roles/bigquery.connectionUser` | Execute queries utilizing the remote Vertex AI connection |
| **Pub/Sub Publisher** | `roles/pubsub.publisher` | Publish high-risk alerts to Pub/Sub topics |
| **Pub/Sub Viewer** | `roles/pubsub.viewer` | Monitor subscriber backlogs |
| **Storage Object User** | `roles/storage.objectUser` | Upload human escalation JSON files into the escalation GCS bucket |
| **Vertex AI User** | `roles/aiplatform.user` | Invoke Gemini multimodal models during multi-agent investigations |
| **Logs Writer** | `roles/logging.logWriter` | Stream structured audit logs to Cloud Logging |
| **Service Usage Consumer** | `roles/serviceusage.serviceUsageConsumer` | Consume project quota for BigQuery and Vertex AI calls |

### Keyless V4 Signed URL Generation (Self-Impersonation):
To avoid distributing or storing permanent JSON service account keys on disk, the runtime identity uses **keyless V4 signed URLs**:
- The service account is granted `roles/iam.serviceAccountTokenCreator` **only on itself** (resource-level binding).
- This allows the running container to call the Cloud IAM Credentials API to produce cryptographic signatures for temporary (30-minute) screenshot URLs without holding private keys.

### CLI Setup:
```bash
# 1. Create the Workload Service Account
gcloud iam service-accounts create bq-continuous-query-sa \
    --project="${PROJECT_ID}" \
    --display-name="Cymbal Cyber Workload SA" \
    --description="Runs continuous queries, Pub/Sub pipeline, and ADK agent runtime"

SA_EMAIL="bq-continuous-query-sa@${PROJECT_ID}.iam.gserviceaccount.com"

# 2. Grant project-level runtime roles
SA_ROLES=(
  "roles/bigquery.connectionUser"
  "roles/bigquery.dataEditor"
  "roles/bigquery.user"
  "roles/logging.logWriter"
  "roles/pubsub.publisher"
  "roles/pubsub.viewer"
  "roles/serviceusage.serviceUsageConsumer"
  "roles/storage.objectUser"
  "roles/aiplatform.user"
)

for role in "${SA_ROLES[@]}"; do
  echo "Granting $role to ${SA_EMAIL}..."
  gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
    --member="serviceAccount:${SA_EMAIL}" \
    --role="$role" \
    --condition=None
done

# 3. Grant resource-level self-impersonation for keyless V4 signed URL signing
gcloud iam service-accounts add-iam-policy-binding "${SA_EMAIL}" \
    --project="${PROJECT_ID}" \
    --member="serviceAccount:${SA_EMAIL}" \
    --role="roles/iam.serviceAccountTokenCreator"
```

---

## 5. Automated Setup via Terraform

The security architecture and IAM role bindings outlined above are codified in Terraform (`src/demo/terraform/`):

* **API Enablement:** `src/demo/terraform/main.tf`
* **Remote Connection & Read-Only Bindings:** `src/demo/terraform/bigquery.tf`
* **Workload Identity & Scoped Role Bindings:** `src/demo/terraform/iam.tf`

### Apply via Terraform:
```bash
cd src/demo/terraform

# 1. Initialize Terraform
terraform init

# 2. Preview changes
terraform plan -var="project_id=${PROJECT_ID}"

# 3. Apply changes with strict IAM boundaries
terraform apply -var="project_id=${PROJECT_ID}" -auto-approve
```

---

## 6. Security Verification & Audit Commands

Run these commands to verify that permissions conform to the least-privilege model:

```bash
# 1. Verify enabled APIs
gcloud services list --enabled --filter="name:(bigquery OR aiplatform OR pubsub OR iamcredentials)" --project="${PROJECT_ID}"

# 2. Verify BigQuery Connection permissions
bq show --connection "${PROJECT_ID}.${BQ_LOCATION}.continuous-query-vertex-ai-connection"

# 3. Verify Workload Service Account bindings (ensure no Project IAM Admin or broad owner roles exist)
gcloud projects get-iam-policy "${PROJECT_ID}" \
    --flatten="bindings[].members" \
    --format="table(bindings.role)" \
    --filter="bindings.members:bq-continuous-query-sa"

# 4. Verify Day-2 Analyst account lacks administrative roles
gcloud projects get-iam-policy "${PROJECT_ID}" \
    --flatten="bindings[].members" \
    --format="table(bindings.role)" \
    --filter="bindings.members:${ANALYST_EMAIL}"
```
