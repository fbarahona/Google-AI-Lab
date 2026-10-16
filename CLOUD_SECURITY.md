# Cloud Security & IAM Architecture Guide

This guide details the security baseline, IAM role requirements, separation of operational duties, and manual/automated configuration procedures for the **Real-Time Cybersecurity AI & ADK Platform** on Google Cloud Platform.

---

## 🛡️ Architecture & Security Model: Principle of Least Privilege

In enterprise security engineering, granting broad administrative roles across all components introduces lateral movement risks and violates the principle of least privilege. This architecture enforces **strict separation of duties** across distinct identity tiers, one per workload and trust path:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           SECURITY IDENTITY TIERS                           │
├─────────────────────────────────────────────────────────────────────────────┤
│ 1. Bootstrap / Provisioning Identity (CI/CD Pipeline or Cloud Admin)        │
│    - One-time resource creation, IAM bindings, API enablement               │
│    - Elevated: Project IAM Admin, Storage Admin, Vertex AI Admin            │
├─────────────────────────────────────────────────────────────────────────────┤
│ 2. Day-2 Operator & SOC Analyst Identity (Human Incident Responder)         │
│    - Daily operations: Run Streamlit console, review tickets, query logs    │
│    - Least-Privilege: BigQuery User & DataViewer, Storage ObjectViewer      │
│    - ZERO administrative, IAM mutation, or storage deletion permissions     │
├─────────────────────────────────────────────────────────────────────────────┤
│ 3. Continuous Query Workload Identity (`bq-continuous-query-sa`)            │
│    - Created only when enable_continuous_query = true                       │
│    - Headless BigQuery Continuous Query stream processing                   │
│    - Least-Privilege: BigQuery jobUser, dataset READER, publisher on alerts │
│    - ZERO storage access, ZERO Vertex AI access, ZERO token creation        │
├─────────────────────────────────────────────────────────────────────────────┤
│ 4. ADK Agent Runtime Workload Identity (`cymbal-adk-agent-sa`)              │
│    - Runs the agents (Gemini reasoning) and the Pub/Sub webhook             │
│    - Scoped: aiplatform.user, BigQuery jobUser, table-level dataEditor on   │
│      alerts and agent_events only; run.invoker on the MCP tool service      │
│    - ZERO evidence reads, ZERO ticket writes, ZERO bucket access            │
│    - ZERO publish rights on raw telemetry (cannot forge its own evidence)   │
├─────────────────────────────────────────────────────────────────────────────┤
│ 4a. MCP Tool Service Identity (`cymbal-mcp-tools-sa`)                       │
│    - Identity behind every agent tool (Cloud Run service cymbal-cyber-mcp)  │
│    - Scoped: BigQuery jobUser, dataset READER, table-level dataEditor on    │
│      soc_tickets and adk_threat_assessment, read on screenshots, write on   │
│      escalations, aiplatform.user (vision), self token creator (signing)    │
│    - Callable only by the agent SA: run.invoker + in-app ID token check     │
├─────────────────────────────────────────────────────────────────────────────┤
│ 4b. SOC Console Workload Identity (`cymbal-soc-console-sa`)                 │
│    - Streamlit analyst console: dashboards, verdicts, ticket Q&A, demo data │
│    - Scoped: BigQuery jobUser, dataset READER, table-level dataEditor on    │
│      soc_tickets and adk_threat_assessment, bucket-level objectUser on      │
│      escalations, aiplatform.user, publisher on cymbal_cyber_raw_logs only  │
├─────────────────────────────────────────────────────────────────────────────┤
│ 5. Pub/Sub Push Invoker Identity (`pubsub-invoker-sa`)                      │
│    - OIDC token identity for authenticating push subscription delivery      │
│    - run.invoker on the agent service only; ZERO ambient project roles      │
├─────────────────────────────────────────────────────────────────────────────┤
│ 5b. Scheduler Identity (`threat-detector-scheduler-sa`)                     │
│    - Cloud Scheduler OAuth identity that starts the threat-detector job     │
│    - run.invoker on that job only; ZERO ambient project roles               │
├─────────────────────────────────────────────────────────────────────────────┤
│ 5c. Console Access Identity (`soc-console-access`)                          │
│    - Humans impersonate it to open the console through gcloud proxy         │
│    - run.invoker on the console only; ZERO ambient project roles            │
├─────────────────────────────────────────────────────────────────────────────┤
│ 6. Tool Isolation Layer: Model Context Protocol (MCP) Tool Service          │
│    - Own Cloud Run service and identity in the cloud, stdio locally         │
│    - Nine fixed operations, no free-form SQL, 1 GB scan ceiling per query   │
│    - Per-agent tool_filter allow-lists; one platform-only escalation tool   │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 📌 Prerequisites & Variables

> [!TIP]
> You can run `source ./src/demo/scripts/pre_flight.sh` to interactively configure these variables, populate `.env`, and automatically assign the required bootstrap and analyst IAM roles.

Or set your deployment parameters manually in your shell:

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
| **BigQuery Unified API** | `bigqueryunified.googleapis.com` | High-throughput query processing and event ingestion |
| **Vertex AI API** | `aiplatform.googleapis.com` | Gemini model endpoints and Agent Runtime |
| **Cloud Pub/Sub API** | `pubsub.googleapis.com` | Streaming event bus for raw logs and continuous alerts |
| **IAM Service Account Credentials API** | `iamcredentials.googleapis.com` | Generation of short-lived tokens and V4 signed URLs |
| **Cloud Resource Manager API** | `cloudresourcemanager.googleapis.com` | Managing IAM policy bindings and metadata |
| **Google Cloud Storage JSON API** | `storage.googleapis.com` | Storing screenshots, raw logs, and escalation files |
| **BigQuery Connection API** | `bigqueryconnection.googleapis.com` | *(Optional / Legacy Continuous Query)* Remote connection to external services |

### Enable via CLI:
```bash
gcloud services enable \
    bigqueryunified.googleapis.com \
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
| **BigQuery Resource Editor** | `roles/bigquery.resourceEditor` | Allocate query slots and continuous query reservations (if enabled) |
| **Storage Admin** | `roles/storage.admin` | Create buckets for screenshots and escalation archives |
| **Service Account Admin** | `roles/iam.serviceAccountAdmin` | Provision application runtime service accounts |
| **Project IAM Admin** | `roles/resourcemanager.projectIamAdmin` | Bind scoped IAM roles to service accounts |
| **Pub/Sub Editor** | `roles/pubsub.editor` | Provision alerting topics and dead-letter subscriptions |
| **Vertex AI Administrator** | `roles/aiplatform.admin` | Configure Vertex AI agent endpoints and foundation model access |

#### Grant Bootstrap Roles (Temporary / Admin Only):
```bash
BOOTSTRAP_ROLES=(
  "roles/bigquery.dataEditor"
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

## 3. Decoupled Tool Execution via the Model Context Protocol (MCP) Tool Service

In legacy multi-agent setups, BigQuery required an external Cloud Resource connection (`continuous-query-vertex-ai-connection`) with an autogenerated service account (`bqcx-...`) to query object tables and invoke remote Gemini models via SQL `ML.GENERATE_TEXT`.

### Why BigQuery External Connections Were Decommissioned:
1. **IAM Propagation Delays:** The GCP-managed connection SA (`bqcx-...`) creates an asynchronous 15–30 second propagation window during provisioning, leading to `Error 400: Service account ... does not exist` during automated `terraform apply` executions.
2. **Brittle Cross-Service Coupling:** Running generative AI calls inside BigQuery SQL tightly couples database queries to foundation model availability, complicating error handling, rate limiting, and observability.
3. **Decoupled Architecture:** The system now delegates all AI calls to the **ADK Agents** via the Python Vertex AI SDK under Workload Identity (`roles/aiplatform.user`), while database and forensic operations run through a **Model Context Protocol (MCP) tool server** (`adk_agent/mcp_server/`).

### MCP as a Privilege Boundary
In the cloud the MCP server is its own Cloud Run service, `cymbal-cyber-mcp`, running as its own service account, `cymbal-mcp-tools-sa`. That identity holds every evidence read and ticket write; the agent's identity holds none of them.

```
 Pub/Sub push (pubsub-invoker-sa)
        │
        ▼
 cymbal-cyber-adk-agent  ── runs as cymbal-adk-agent-sa ──────────────────┐
   agents + webhook        Gemini (aiplatform.user), alerts + agent_events │
        │                                                                  │
        │ MCP Streamable HTTP, Authorization: Bearer <ID token>            │
        │ audience = MCP service URL, minted by cymbal-adk-agent-sa        │
        ▼                                                                  │
 cymbal-cyber-mcp  ── runs as cymbal-mcp-tools-sa ─────────────────────────┘
   9 fixed tools       event tables, screenshots, vision, signed URLs, tickets
```

- **Two checks on every call:** Cloud Run IAM admits only principals with `roles/run.invoker` on the service, and the only one is the agent SA. The server then verifies the ID token itself (`CallerAuthMiddleware`): audience must be the service URL (`MCP_EXPECTED_AUDIENCE`) and the caller must be the agent SA (`MCP_ALLOWED_CALLER`). The server refuses to start in the cloud without both settings.
- **What a compromised agent can do:** ask for the nine operations below with model-chosen arguments, each validated server-side. It cannot run SQL, read a table, list a bucket, sign an arbitrary URL, or write a ticket outside these tools, because its credentials do not allow it.
- **Default-deny included:** when the model resolves nothing, the guardrail files its escalation through the platform-only MCP tool `auto_escalate_unresolved_alert`, so even that write uses the tool identity. No agent's `tool_filter` lists the tool, and its ticket decision is fixed server-side.
- **Stateless transport:** the server runs Streamable HTTP with stateless JSON responses, so any instance can serve any request and the service scales horizontally. The agent caches its ID token until it nears expiry, so MCP sessions are reused rather than reopened per call.
- **Locally** (`MCP_SERVER_URL` unset) the agent starts the same server over `stdio` as a child process, with no network or token involved.

### MCP Security Controls:
- **Least-Privilege Tool Scoping:** Sub-agents only connect to tools explicitly bound to their role via `create_mcp_toolset([...])` / `ScopedMcpToolset`: one MCP connection per sub-agent, with a `tool_filter` allow-list of that agent's tools. The BigQuery agent cannot access GCS signed URLs, and the Vision agent cannot modify ticket queues.
- **No Free-Form SQL Surface:** The server exposes no `execute_sql` or schema-discovery tool. Agents and any other MCP client can only call fixed, parameterized investigation and ticketing operations, with entity values validated against an allow-list pattern before they reach a query.
- **Scan Ceilings:** Every BigQuery job issued by the tools sets `maximum_bytes_billed` (1 GB default, configurable via `BQ_MAX_BYTES_BILLED`), so a query that would scan more fails instead of running. The event tables are day-partitioned for pruning but do not set `require_partition_filter`; the byte ceiling is the cost guardrail.
- **Native Grounding Preservation:** `google_search_agent` retains the native ADK `google_search` tool for search-grounded OSINT without proxying external queries through third-party protocols.

---

## 4. Scoped Workload Identities & Resource-Level Bindings

To enforce the principle of least privilege, background automation is split into **dedicated service accounts**, one per trust path, rather than relying on a single monolithic identity:

### 4A. Continuous Query Workload Identity (`bq-continuous-query-sa`)
- **Purpose:** Executes headless BigQuery continuous streaming queries and writes alerts to Pub/Sub. Terraform creates it, with its bindings, only when `enable_continuous_query = true`.
- **Project Roles:** `roles/bigquery.jobUser` (run jobs), `roles/logging.logWriter`, `roles/serviceusage.serviceUsageConsumer`.
- **Resource Bindings:**
  - `READER` access on BigQuery dataset `Cymbal_Cyber`
  - `roles/pubsub.publisher` scoped strictly to Pub/Sub topic `cymbal_cyber_alerts`
- **Zero Access:** No access to GCS, Vertex AI, or token creation.

### 4B. ADK Multi-Agent Runtime Identity (`cymbal-adk-agent-sa`)
- **Purpose:** Runs the ADK multi-agent team and the Pub/Sub webhook. Every tool call goes to the MCP tool service (4B1).
- **Project Roles:** `roles/aiplatform.user` (the agents' Gemini calls through Vertex AI; there is no API key), `roles/bigquery.jobUser` (alert status queries), `roles/logging.logWriter`, `roles/serviceusage.serviceUsageConsumer`.
- **Resource Bindings (Least-Privilege Scoped):**
  - Table-level `roles/bigquery.dataEditor` on `alerts` (dedupe and status updates) and `agent_events` (ADK analytics plugin rows; its per-event views are disabled because they would need dataset-level create).
  - `roles/run.invoker` on `cymbal-cyber-mcp`, its only path to evidence and tickets.
- **Zero Access:** No dataset READER, no `soc_tickets` or `adk_threat_assessment` write, no bucket access, no token creation, no publish right on raw telemetry.

### 4B1. MCP Tool Service Identity (`cymbal-mcp-tools-sa`)
- **Purpose:** Runs the MCP tool server (`cymbal-cyber-mcp`) and is the identity behind every agent tool.
- **Project Roles:** `roles/bigquery.jobUser`, `roles/aiplatform.user` (Gemini vision in `get_visual_analysis_for_user`), `roles/logging.logWriter`, `roles/serviceusage.serviceUsageConsumer`.
- **Resource Bindings (Least-Privilege Scoped):**
  - `READER` access on BigQuery dataset `Cymbal_Cyber` (event tables, the screenshots view, ticket views). No dataset-level write: the tools cannot modify the raw event tables they investigate.
  - Table-level `roles/bigquery.dataEditor` on `soc_tickets` and `adk_threat_assessment` (incident tickets and triage decisions).
  - `roles/storage.objectViewer` on the `screenshots` bucket and `roles/storage.objectUser` on the `escalations` bucket.
  - `roles/iam.serviceAccountTokenCreator` bound **strictly to itself** for short-lived keyless V4 signed URLs.
- **Callers:** the agent SA only (Cloud Run invoker binding plus the server's own ID token check).

### 4B2. SOC Console Identity (`cymbal-soc-console-sa`)
- **Purpose:** Runs the Streamlit analyst console (`cymbal-cyber-soc-console`). It has its own identity so the agent never holds a publish right on raw telemetry: the console's "Inject scenario" and "Stream logs" controls publish to `cymbal_cyber_raw_logs`, which feeds the same BigQuery subscriptions, detector and agent as real traffic.
- **Project Roles:** `roles/bigquery.jobUser`, `roles/aiplatform.user` (the "Ask the Agent" ticket assistant), `roles/logging.logWriter`, `roles/serviceusage.serviceUsageConsumer`.
- **Resource Bindings (Least-Privilege Scoped):**
  - `READER` access on BigQuery dataset `Cymbal_Cyber` (dashboard metrics, ticket queue and archive).
  - Table-level `roles/bigquery.dataEditor` on `soc_tickets` (simulated demo tickets and analyst verdicts) and `adk_threat_assessment` (analyst verdict rows).
  - `roles/storage.objectUser` on the `escalations` bucket (escalation request and response files).
  - `roles/pubsub.publisher` scoped strictly to topic `cymbal_cyber_raw_logs`.
- **Zero Access:** No screenshots bucket access (the console shows bundled demo screenshots or the agent's signed URLs), no token creation, no write access to the raw event tables.

### 4C. Pub/Sub Push Invoker Identity (`pubsub-invoker-sa`)
- **Purpose:** Provides the OIDC identity used by Pub/Sub push subscription (`adk_agent_trigger`) to authenticate delivery to the agent webhook endpoint. The webhook rejects any other caller (`EXPECTED_INVOKER_EMAIL`).
- **Roles:** `roles/run.invoker` on `cymbal-cyber-adk-agent` only. Zero ambient project roles.

### 4D. Scheduler Identity (`threat-detector-scheduler-sa`)
- **Purpose:** OAuth identity Cloud Scheduler uses to start the `threat-detector` job every 5 minutes. Separate from the push identity, so neither trust path can be used for the other.
- **Roles:** `roles/run.invoker` on the `threat-detector` job only. Zero ambient project roles.

### 4D-2. Console Access Identity (`soc-console-access`)
- **Purpose:** Analysts open the SOC console with `gcloud run services proxy` and an ID token minted for this account, with the console URL as audience. The console stays private: no `allUsers` binding.
- **Roles:** `roles/run.invoker` on `cymbal-cyber-soc-console` only. Zero ambient project roles. `roles/iam.serviceAccountTokenCreator` on this account goes to `deployer_member` and `console_access_members` only.

### 4E. Agent Service Exposure
- In the cloud the agent service serves only `POST /trigger/pubsub` (and its `/apps/adk_agent/trigger/pubsub` alias), which verifies the Pub/Sub OIDC token. The ADK web UI, `/run`, session, builder and A2A APIs, and the OpenAPI docs are not routed, because they would run investigations as the agent SA without that check.
- `enable_adk_dev_ui = true` (Terraform) sets `ADK_DEV_UI=true` and turns them back on for a supervised demo. Cloud Run IAM still limits callers to the deployer, the push identity and, only while the flag is on, `soc-console-access` (so analysts can open it through the impersonated-token proxy). The playground's tool calls still go through the MCP tool service. Locally (`LOCAL_MODE=true`) they are on by default.

### 4F. Build Identity and Container Image
- Cloud Build runs as the Compute Engine default service account. It holds `roles/storage.objectViewer` on the build source bucket (`<project>_cloudbuild`) only, not project-wide, so it cannot read tickets, screenshots or Terraform state.
- The image runs as an unprivileged user (uid 10001) that can write only `local_demo_data/`, contains runtime dependencies only (`uv sync --no-dev`), copies only the runtime packages, and pins its base images by digest. `.dockerignore` keeps Terraform state, tfvars and `.env` files out of local builds.

### CLI Setup for Scoped Workloads:
```bash
# 1. Create Continuous Query Service Account
gcloud iam service-accounts create bq-continuous-query-sa \
    --project="${PROJECT_ID}" \
    --display-name="Cymbal Cyber Continuous Query SA"

CQ_SA="bq-continuous-query-sa@${PROJECT_ID}.iam.gserviceaccount.com"
gcloud projects add-iam-policy-binding "${PROJECT_ID}" --member="serviceAccount:${CQ_SA}" --role="roles/bigquery.jobUser"
gcloud pubsub topics add-iam-policy-binding "cymbal_cyber_alerts" --project="${PROJECT_ID}" --member="serviceAccount:${CQ_SA}" --role="roles/pubsub.publisher"

# 2. Create ADK Agent Runtime Service Account (agents + webhook; no evidence or ticket access)
gcloud iam service-accounts create cymbal-adk-agent-sa \
    --project="${PROJECT_ID}" \
    --display-name="Cymbal Cyber ADK Agent SA"

AGENT_SA="cymbal-adk-agent-sa@${PROJECT_ID}.iam.gserviceaccount.com"
AGENT_ROLES=("roles/bigquery.jobUser" "roles/aiplatform.user" "roles/logging.logWriter")
for role in "${AGENT_ROLES[@]}"; do
  gcloud projects add-iam-policy-binding "${PROJECT_ID}" --member="serviceAccount:${AGENT_SA}" --role="$role"
done
for table in alerts agent_events; do
  bq add-iam-policy-binding --member="serviceAccount:${AGENT_SA}" --role="roles/bigquery.dataEditor" "${PROJECT_ID}:Cymbal_Cyber.${table}"
done

# 2b. Create MCP Tool Service Account (identity behind every tool)
gcloud iam service-accounts create cymbal-mcp-tools-sa \
    --project="${PROJECT_ID}" \
    --display-name="Cymbal Cyber MCP Tool Server SA"

MCP_SA="cymbal-mcp-tools-sa@${PROJECT_ID}.iam.gserviceaccount.com"
MCP_ROLES=("roles/bigquery.jobUser" "roles/aiplatform.user" "roles/logging.logWriter")
for role in "${MCP_ROLES[@]}"; do
  gcloud projects add-iam-policy-binding "${PROJECT_ID}" --member="serviceAccount:${MCP_SA}" --role="$role"
done

# BigQuery: dataset READER plus table-level dataEditor on the ticket tables
bq show --format=prettyjson "${PROJECT_ID}:Cymbal_Cyber" > /tmp/cymbal_dataset.json
jq --arg sa "${MCP_SA}" '.access += [{"role": "READER", "userByEmail": $sa}]' /tmp/cymbal_dataset.json > /tmp/cymbal_dataset_new.json
bq update --source /tmp/cymbal_dataset_new.json "${PROJECT_ID}:Cymbal_Cyber"
for table in soc_tickets adk_threat_assessment; do
  bq add-iam-policy-binding --member="serviceAccount:${MCP_SA}" --role="roles/bigquery.dataEditor" "${PROJECT_ID}:Cymbal_Cyber.${table}"
done

# Resource-level bucket bindings for the MCP SA
gcloud storage buckets add-iam-policy-binding "gs://cymbal-cyber-screenshots_${PROJECT_ID}" --member="serviceAccount:${MCP_SA}" --role="roles/storage.objectViewer"
gcloud storage buckets add-iam-policy-binding "gs://cymbal-cyber-adk-escalations-bucket_${PROJECT_ID}" --member="serviceAccount:${MCP_SA}" --role="roles/storage.objectUser"

# Resource-level self-impersonation for keyless V4 signed URLs
gcloud iam service-accounts add-iam-policy-binding "${MCP_SA}" \
    --project="${PROJECT_ID}" \
    --member="serviceAccount:${MCP_SA}" \
    --role="roles/iam.serviceAccountTokenCreator"

# The agent may invoke the MCP tool service, and nothing else may
gcloud run services add-iam-policy-binding cymbal-cyber-mcp \
    --project="${PROJECT_ID}" --region="${REGION}" \
    --member="serviceAccount:${AGENT_SA}" --role="roles/run.invoker"

# 3. Create Pub/Sub Push Invoker Service Account
gcloud iam service-accounts create pubsub-invoker-sa \
    --project="${PROJECT_ID}" \
    --display-name="Cymbal Cyber Pub/Sub Push Invoker SA"

# 4. Create the Scheduler Service Account (starts the threat-detector job)
gcloud iam service-accounts create threat-detector-scheduler-sa \
    --project="${PROJECT_ID}" \
    --display-name="Cymbal Cyber Threat Detector Scheduler SA"
```

---

## 5. Automated Setup via Terraform

The security architecture and IAM role bindings outlined above are codified in Terraform (`src/demo/terraform/`):

* **API Enablement:** `src/demo/terraform/main.tf`
* **BigQuery Datasets & Partitioned Tables:** `src/demo/terraform/bigquery.tf`
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

# 2. Verify Local MCP Server unit tests and security gates
uv run pytest src/demo/tests/unit/test_mcp_server.py

# 3. Verify Workload Service Account bindings (ensure no Project IAM Admin or broad owner roles exist)
gcloud projects get-iam-policy "${PROJECT_ID}" \
    --flatten="bindings[].members" \
    --format="table(bindings.role)" \
    --filter="bindings.members:cymbal-adk-agent-sa"

# 4. Verify Day-2 Analyst account lacks administrative roles
gcloud projects get-iam-policy "${PROJECT_ID}" \
    --flatten="bindings[].members" \
    --format="table(bindings.role)" \
    --filter="bindings.members:${ANALYST_EMAIL}"
```
