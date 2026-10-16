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
│    - Elevated: Project IAM Admin, Service Account/Run/BQ/PubSub/Storage     │
├─────────────────────────────────────────────────────────────────────────────┤
│ 2. Day-2 Operator & SOC Analyst Identity (Human Incident Responder)         │
│    - Daily operations: Open Streamlit console proxy, review tickets, query  │
│    - Least-Privilege: BigQuery JobUser & DataViewer, Storage ObjectViewer,  │
│      Vertex AI User, plus TokenCreator on `soc-console-access`              │
│    - ZERO administrative, IAM mutation, or storage deletion permissions     │
├─────────────────────────────────────────────────────────────────────────────┤
│ 3. Scheduled Threat Detector Identity (`threat-detector-job-sa`)            │
│    - Default micro-batch Cloud Run Job evaluating 2-min tumbling windows    │
│    - Scoped: BigQuery jobUser, dataset READER, table-level dataEditor on    │
│      alerts and soc_tickets (DLQ recovery), publisher on alerts topic       │
│    - ZERO storage access, ZERO Vertex AI access, ZERO token creation        │
├─────────────────────────────────────────────────────────────────────────────┤
│ 3a. Continuous Query Workload Identity (`bq-continuous-query-sa`)           │
│    - Created only when enable_continuous_query = true                       │
│    - Headless BigQuery Continuous Query stream processing                   │
│    - Least-Privilege: BigQuery jobUser, dataset READER, publisher on alerts │
│    - ZERO storage access, ZERO Vertex AI access, ZERO token creation        │
├─────────────────────────────────────────────────────────────────────────────┤
│ 3b. Dataflow Streaming Workload Identity (`cymbal-dataflow-pipeline-sa`)    │
│    - Created only when enable_dataflow_streaming = true                     │
│    - Scoped: dataflow.worker, BigQuery jobUser, dataset READER, table-level │
│      dataEditor on user_access_events & network_events, staging objectAdmin │
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
├─────────────────────────────────────────────────────────────────────────────┤
│ 7. Privacy Safeguards & Automated PII Sanitization                          │
│    - Deterministic Google Search Privacy Gate intercepts outbound queries   │
│    - Blocks leakage of user IDs, device hostnames, private RFC-1918 IPs, PII │
│    - Automated PII redaction (SSNs, cards, emails, phones) in OCR & reports │
│    - Strict preservation of Threat Intelligence IOCs (public IPs, hashes)   │
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

Terraform (`src/demo/terraform/main.tf`) and `deploy_cloud.sh` enable the required Google Cloud APIs for data ingestion, serverless compute, container builds, and AI reasoning:

| API Service Name | Identifier | Purpose |
|---|---|---|
| **BigQuery & Storage APIs** | `bigquery.googleapis.com`, `bigqueryunified.googleapis.com`, `bigquerystorage.googleapis.com`, `bigquerydatatransfer.googleapis.com` | Event tables, streaming subscriptions, and analytical queries |
| **BigQuery Connection API** | `bigqueryconnection.googleapis.com` | Required for the `cymbal_screenshots` BigLake Object Table over the screenshots bucket |
| **Vertex AI API** | `aiplatform.googleapis.com` | Gemini model endpoints for ADK agents and multimodal vision |
| **Cloud Run API** | `run.googleapis.com` | Serverless container services (`adk-agent`, `mcp`, `soc-console`) and jobs (`threat-detector`) |
| **Cloud Pub/Sub API** | `pubsub.googleapis.com` | Streaming event bus for raw logs, alerts, and dead-letter queues |
| **Cloud Scheduler API** | `cloudscheduler.googleapis.com` | Cron trigger executing the `threat-detector` job every 5 minutes |
| **Cloud Storage API** | `storage.googleapis.com` | Storing desktop screenshots, raw logs, escalation files, and Terraform state |
| **Artifact Registry & Cloud Build** | `artifactregistry.googleapis.com`, `cloudbuild.googleapis.com`, `compute.googleapis.com` | Building and storing the unified container image |
| **IAM & Resource Manager APIs** | `iamcredentials.googleapis.com`, `cloudresourcemanager.googleapis.com` | Short-lived OIDC/V4 signed URL tokens and IAM policy bindings |
| **Observability & FinOps APIs** | `logging.googleapis.com`, `billingbudgets.googleapis.com`, `dataflow.googleapis.com` | Structured Cloud Logging, budget alerts, and optional Dataflow pipelines |

### Enable via CLI:
```bash
gcloud services enable \
    bigquery.googleapis.com \
    bigqueryunified.googleapis.com \
    bigquerystorage.googleapis.com \
    bigqueryconnection.googleapis.com \
    bigquerydatatransfer.googleapis.com \
    aiplatform.googleapis.com \
    run.googleapis.com \
    pubsub.googleapis.com \
    cloudscheduler.googleapis.com \
    storage.googleapis.com \
    artifactregistry.googleapis.com \
    cloudbuild.googleapis.com \
    compute.googleapis.com \
    iamcredentials.googleapis.com \
    cloudresourcemanager.googleapis.com \
    logging.googleapis.com \
    billingbudgets.googleapis.com \
    dataflow.googleapis.com \
    --project="${PROJECT_ID}"
```

---

## 2. Human Identity Access Control: Provisioning vs. Day-2 Operations

To demonstrate rigorous security engineering, human identities must not share monolithic administrative permissions. Initial bootstrapping is separated from day-to-day operational analysis.

### 2A. Day-2 Operator & SOC Analyst (Least-Privilege Human Baseline)

Human analysts investigating alerts, reviewing desktop screenshots, and opening the Cloud Run Streamlit SOC console require **4 project-level least-privilege roles** plus **service-account-level `roles/iam.serviceAccountTokenCreator` on `soc-console-access`** (automatically wired by `deploy_cloud.sh` when `ANALYST_EMAIL` is set). They do not have rights to alter IAM policies, delete buckets, or modify infrastructure.

| Role Name | Scope | IAM Role ID | Purpose |
|---|---|---|---|
| **BigQuery Job User** | Project | `roles/bigquery.jobUser` | Run read-only diagnostic and investigative queries |
| **BigQuery Data Viewer** | Project | `roles/bigquery.dataViewer` | View event logs, alerts, and ticket tables |
| **Storage Object Viewer** | Project | `roles/storage.objectViewer` | View desktop screenshots and escalation metadata in GCS |
| **Vertex AI User** | Project | `roles/aiplatform.user` | Query Gemini models for assisted threat triage |
| **Service Account Token Creator** | `soc-console-access` SA | `roles/iam.serviceAccountTokenCreator` | Mint impersonated ID tokens to open the private Cloud Run SOC console via `gcloud run services proxy` |

#### Grant Day-2 Analyst Roles via CLI:
```bash
ANALYST_ROLES=(
  "roles/bigquery.jobUser"
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

# Grant token creator on soc-console-access so the analyst can open the Cloud Run console proxy
# (deploy_cloud.sh also passes ANALYST_EMAIL to Terraform's console_access_members automatically)
gcloud iam service-accounts add-iam-policy-binding \
  "soc-console-access@${PROJECT_ID}.iam.gserviceaccount.com" \
  --project="${PROJECT_ID}" \
  --member="user:${ANALYST_EMAIL}" \
  --role="roles/iam.serviceAccountTokenCreator"
```

---

### 2B. Bootstrap / Provisioning Identity (Admin / Terraform CI/CD Only)

During initial project provisioning, a deployment identity (such as a Terraform service account in CI/CD or a designated cloud administrator) requires elevated permissions to enable APIs, create datasets, connections, service accounts, Cloud Run services/jobs, and bind least-privilege resource IAM policies.

> ⚠️ **Production Security Note:** In enterprise environments, these elevated roles should be assigned to an automated CI/CD pipeline or granted via Privileged Access Management (PAM) / Just-In-Time (JIT) access with an expiration window, rather than held permanently by personal user accounts.

| Role Name | IAM Role ID | Provisioning Purpose |
|---|---|---|
| **Project IAM Admin** | `roles/resourcemanager.projectIamAdmin` | Bind scoped project roles to workload service accounts |
| **Service Usage Admin** | `roles/serviceusage.serviceUsageAdmin` | Enable required Google Cloud APIs (`gcloud services enable`) |
| **Service Account Admin & User** | `roles/iam.serviceAccountAdmin`, `roles/iam.serviceAccountUser` | Provision workload SAs and attach them to Cloud Run services/jobs |
| **BigQuery Admin** | `roles/bigquery.admin` | Create dataset `Cymbal_Cyber`, tables, routines, BigLake connection, and table-level IAM policies |
| **Cloud Run Admin** | `roles/run.admin` | Deploy Cloud Run services (`adk-agent`, `mcp`, `soc-console`), jobs (`threat-detector`), and invoker bindings |
| **Pub/Sub Admin** | `roles/pubsub.admin` | Create topics, BigQuery/push subscriptions, DLQs, and topic/subscription IAM bindings |
| **Storage Admin** | `roles/storage.admin` | Create screenshots, escalations, raw-logs, and state buckets and set bucket-level IAM policies |
| **Artifact Registry Admin** | `roles/artifactregistry.admin` | Provision Docker repository `cymbal-cyber` and repository IAM bindings |
| **Cloud Build Editor** | `roles/cloudbuild.builds.editor` | Submit remote container builds (`gcloud builds submit`) |
| **Cloud Scheduler Admin** | `roles/cloudscheduler.admin` | Provision the 5-minute `threat-detector-trigger` cron job |
| **Billing Viewer** | `roles/billing.viewer` | Verify active project billing during pre-flight checks |

#### Grant Bootstrap Roles (or run `source ./src/demo/scripts/pre_flight.sh`):
```bash
BOOTSTRAP_ROLES=(
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

for role in "${BOOTSTRAP_ROLES[@]}"; do
  echo "Granting $role to ${ADMIN_EMAIL} for initial provisioning..."
  gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
    --member="user:${ADMIN_EMAIL}" \
    --role="$role" \
    --condition=None \
    --quiet
done
```

---

## 3. Decoupled Tool Execution via the Model Context Protocol (MCP) Tool Service

In earlier iterations, BigQuery invoked remote Gemini models directly inside SQL via `ML.GENERATE_TEXT` over a Vertex AI external connection (`continuous-query-vertex-ai-connection`).

### Why SQL `ML.GENERATE_TEXT` Vertex AI Connections Were Replaced:
1. **Brittle Cross-Service Coupling:** Running generative AI calls inside BigQuery SQL tightly coupled database queries to foundation model availability, complicating error handling, rate limiting, and multi-step forensic reasoning.
2. **Decoupled AI & Tool Architecture:** All Gemini reasoning and multimodal vision calls now execute in the **ADK Agents** and **MCP Tool Service** via the Python Vertex AI SDK under Workload Identity (`roles/aiplatform.user`), while BigQuery is used strictly for structured telemetry and ticket persistence.
3. **Scoped BigLake Connection for Screenshot Indexing Only:** BigQuery retains a single read-only Cloud Resource connection (`cymbal_screenshots` in `src/demo/terraform/bigquery.tf`) solely to back the `user_screenshots_objects` BigLake Object Table over `gs://cymbal-cyber-screenshots_${PROJECT_ID}/*.png`. Its Google-managed service account (`bqcx-...`) holds only `roles/storage.objectViewer` on the `screenshots` bucket (`iam.tf`) and has zero Vertex AI or project-level permissions.

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
- **What a compromised agent can do:** ask for the nine operations below with model-chosen arguments, each validated server-side. It cannot run SQL, read a table, list a bucket, sign a URL outside `SCREENSHOTS_BUCKET` (`_is_allowed_screenshot_uri`), or write a ticket outside these tools, because its credentials and server-side validators do not allow it.
- **Default-deny included:** when the model resolves nothing, the guardrail files its escalation through the platform-only MCP tool `auto_escalate_unresolved_alert`, so even that write uses the tool identity. No agent's `tool_filter` lists the tool, and its ticket decision is fixed server-side.
- **Stateless transport:** the server runs Streamable HTTP with stateless JSON responses, so any instance can serve any request and the service scales horizontally. The agent caches its ID token until it nears expiry, so MCP sessions are reused rather than reopened per call.
- **Locally** (`MCP_SERVER_URL` unset) the agent starts the same server over `stdio` as a child process, with no network or token involved.

### MCP Security Controls:
- **Least-Privilege Tool Scoping:** Sub-agents only connect to tools explicitly bound to their role via `create_mcp_toolset([...])` / `ScopedMcpToolset`: one MCP connection per sub-agent, with a `tool_filter` allow-list of that agent's tools. The BigQuery agent cannot access GCS signed URLs, and the Vision agent cannot modify ticket queues.
- **No Free-Form SQL Surface:** The server exposes no `execute_sql` or schema-discovery tool. Agents and any other MCP client can only call fixed, parameterized investigation and ticketing operations, with entity values validated against an allow-list pattern before they reach a query.
- **Scan Ceilings:** Every BigQuery query job issued by the investigation tools sets `maximum_bytes_billed` (1 GB default, configurable via `BQ_MAX_BYTES_BILLED`), so a query that would scan more fails instead of running. The event tables are day-partitioned for pruning but do not set `require_partition_filter`; the byte ceiling is the cost guardrail.
- **Native Grounding Preservation:** `google_search_agent` retains the native ADK `google_search` tool for search-grounded OSINT without proxying external queries through third-party protocols.

---

## 4. Scoped Workload Identities & Resource-Level Bindings

To enforce the principle of least privilege, background automation is split into **dedicated service accounts**, one per trust path, rather than relying on a single monolithic identity:

### 4A. Scheduled Threat Detector Identity (`threat-detector-job-sa`)
- **Purpose:** Executes the default micro-batch `threat-detector` Cloud Run Job every 5 minutes, evaluating closed 2-minute windows in BigQuery, recovering dead-lettered alerts, and publishing newly detected alerts to Pub/Sub.
- **Project Roles:** `roles/bigquery.jobUser` (run queries and MERGE jobs).
- **Resource Bindings (Least-Privilege Scoped):**
  - `READER` access on BigQuery dataset `Cymbal_Cyber` (reads `user_access_events`, `network_events`, and `alerts_dead_letter`).
  - Table-level `roles/bigquery.dataEditor` on `alerts` (idempotent alert deduplication and status transitions) and `soc_tickets` (auto-escalation ticket recovery for dead-lettered alerts).
  - `roles/pubsub.publisher` scoped strictly to Pub/Sub topic `cymbal_cyber_alerts`.
- **Zero Access:** No access to GCS buckets, Vertex AI, or token creation.

### 4A-1. Continuous Query Workload Identity (`bq-continuous-query-sa`)
- **Purpose:** Executes headless BigQuery continuous streaming queries and writes alerts to Pub/Sub. Terraform creates it, with its bindings, only when `enable_continuous_query = true`.
- **Project Roles:** `roles/bigquery.jobUser` (run jobs), `roles/logging.logWriter`, `roles/serviceusage.serviceUsageConsumer`.
- **Resource Bindings:**
  - `READER` access on BigQuery dataset `Cymbal_Cyber`
  - `roles/pubsub.publisher` scoped strictly to Pub/Sub topic `cymbal_cyber_alerts`
- **Zero Access:** No access to GCS, Vertex AI, or token creation.

### 4A-2. Dataflow Streaming Workload Identity (`cymbal-dataflow-pipeline-sa`) & Pub/Sub Service Agent
- **Dataflow Identity (`cymbal-dataflow-pipeline-sa`):** Created only when `enable_dataflow_streaming = true`. Holds `roles/dataflow.worker`, `roles/bigquery.jobUser`, `roles/logging.logWriter`, `roles/serviceusage.serviceUsageConsumer`, dataset `READER` on `Cymbal_Cyber`, table-level `roles/bigquery.dataEditor` strictly on `user_access_events` and `network_events`, `roles/pubsub.subscriber` on `raw_logs_dataflow_sub`, and `roles/storage.objectAdmin` on the `adk_staging` bucket.
- **Google-Managed Pub/Sub Service Agent (`service-<project-number>@gcp-sa-pubsub.iam.gserviceaccount.com`):** Powers the default zero-compute BigQuery subscriptions (`raw_access_to_bq`, `raw_network_to_bq`, `alerts_dlq_to_bq`) and DLQ forwarding. Granted table-level `roles/bigquery.dataEditor` strictly on `user_access_events`, `network_events`, and `alerts_dead_letter` (never dataset-wide write access).

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
- In the cloud (`enable_adk_dev_ui = false` by default in `src/demo/terraform/variables.tf`) the agent service serves only `POST /trigger/pubsub` (and its `/apps/adk_agent/trigger/pubsub` alias), which verifies the Pub/Sub OIDC token. The ADK web UI, `/run`, session, builder and A2A APIs, and the OpenAPI docs are not routed, because they would run investigations as the agent SA without that check.
- `enable_adk_dev_ui = true` (Terraform) sets `ADK_DEV_UI=true` and turns them back on for a supervised demo. Cloud Run IAM still limits callers to the deployer, the push identity and, only while the flag is on, `soc-console-access` (so analysts can open it through the impersonated-token proxy). The playground's tool calls still go through the MCP tool service. Locally (`LOCAL_MODE=true`) they are on by default.

### 4F. Build Identity and Container Image
- Cloud Build runs as the Compute Engine default service account. It holds `roles/storage.objectViewer` on the build source bucket (`<project>_cloudbuild`) only, not project-wide, so it cannot read tickets, screenshots or Terraform state.
- The image runs as an unprivileged user (uid 10001) that can write only `local_demo_data/`, contains runtime dependencies only (`uv sync --frozen --no-dev --no-install-project`), copies only the runtime packages, and pins its base images by digest. `.dockerignore` keeps Terraform state, tfvars and `.env` files out of local builds.

### CLI Setup Reference for Scoped Workloads (Automated by Terraform in `iam.tf`):
```bash
# 1. Create Scheduled Threat Detector Job Service Account (default detection path)
gcloud iam service-accounts create threat-detector-job-sa \
    --project="${PROJECT_ID}" \
    --display-name="Cymbal Cyber Scheduled Threat Detector Job SA"

DETECTOR_SA="threat-detector-job-sa@${PROJECT_ID}.iam.gserviceaccount.com"
gcloud projects add-iam-policy-binding "${PROJECT_ID}" --member="serviceAccount:${DETECTOR_SA}" --role="roles/bigquery.jobUser"
gcloud pubsub topics add-iam-policy-binding "cymbal_cyber_alerts" --project="${PROJECT_ID}" --member="serviceAccount:${DETECTOR_SA}" --role="roles/pubsub.publisher"
for table in alerts soc_tickets; do
  bq add-iam-policy-binding --member="serviceAccount:${DETECTOR_SA}" --role="roles/bigquery.dataEditor" "${PROJECT_ID}:Cymbal_Cyber.${table}"
done

# 2. Create ADK Agent Runtime Service Account (agents + webhook; no evidence or ticket access)
gcloud iam service-accounts create cymbal-adk-agent-sa \
    --project="${PROJECT_ID}" \
    --display-name="Cymbal Cyber ADK Multi-Agent Runtime SA"

AGENT_SA="cymbal-adk-agent-sa@${PROJECT_ID}.iam.gserviceaccount.com"
for role in "roles/bigquery.jobUser" "roles/aiplatform.user" "roles/logging.logWriter" "roles/serviceusage.serviceUsageConsumer"; do
  gcloud projects add-iam-policy-binding "${PROJECT_ID}" --member="serviceAccount:${AGENT_SA}" --role="$role"
done
for table in alerts agent_events; do
  bq add-iam-policy-binding --member="serviceAccount:${AGENT_SA}" --role="roles/bigquery.dataEditor" "${PROJECT_ID}:Cymbal_Cyber.${table}"
done

# 2a. Create MCP Tool Service Account (identity behind every tool)
gcloud iam service-accounts create cymbal-mcp-tools-sa \
    --project="${PROJECT_ID}" \
    --display-name="Cymbal Cyber MCP Tool Server SA"

MCP_SA="cymbal-mcp-tools-sa@${PROJECT_ID}.iam.gserviceaccount.com"
for role in "roles/bigquery.jobUser" "roles/aiplatform.user" "roles/logging.logWriter" "roles/serviceusage.serviceUsageConsumer"; do
  gcloud projects add-iam-policy-binding "${PROJECT_ID}" --member="serviceAccount:${MCP_SA}" --role="$role"
done
for table in soc_tickets adk_threat_assessment; do
  bq add-iam-policy-binding --member="serviceAccount:${MCP_SA}" --role="roles/bigquery.dataEditor" "${PROJECT_ID}:Cymbal_Cyber.${table}"
done
gcloud storage buckets add-iam-policy-binding "gs://cymbal-cyber-screenshots_${PROJECT_ID}" --member="serviceAccount:${MCP_SA}" --role="roles/storage.objectViewer"
gcloud storage buckets add-iam-policy-binding "gs://cymbal-cyber-adk-escalations-bucket_${PROJECT_ID}" --member="serviceAccount:${MCP_SA}" --role="roles/storage.objectUser"
gcloud iam service-accounts add-iam-policy-binding "${MCP_SA}" \
    --project="${PROJECT_ID}" \
    --member="serviceAccount:${MCP_SA}" \
    --role="roles/iam.serviceAccountTokenCreator"
gcloud run services add-iam-policy-binding cymbal-cyber-mcp \
    --project="${PROJECT_ID}" --region="${REGION}" \
    --member="serviceAccount:${AGENT_SA}" --role="roles/run.invoker"

# 2b. Create SOC Console Service Account (Streamlit dashboard + raw log injection)
gcloud iam service-accounts create cymbal-soc-console-sa \
    --project="${PROJECT_ID}" \
    --display-name="Cymbal Cyber SOC Console SA"

CONSOLE_SA="cymbal-soc-console-sa@${PROJECT_ID}.iam.gserviceaccount.com"
for role in "roles/bigquery.jobUser" "roles/aiplatform.user" "roles/logging.logWriter" "roles/serviceusage.serviceUsageConsumer"; do
  gcloud projects add-iam-policy-binding "${PROJECT_ID}" --member="serviceAccount:${CONSOLE_SA}" --role="$role"
done
for table in soc_tickets adk_threat_assessment; do
  bq add-iam-policy-binding --member="serviceAccount:${CONSOLE_SA}" --role="roles/bigquery.dataEditor" "${PROJECT_ID}:Cymbal_Cyber.${table}"
done
gcloud storage buckets add-iam-policy-binding "gs://cymbal-cyber-adk-escalations-bucket_${PROJECT_ID}" --member="serviceAccount:${CONSOLE_SA}" --role="roles/storage.objectUser"
gcloud pubsub topics add-iam-policy-binding "cymbal_cyber_raw_logs" --project="${PROJECT_ID}" --member="serviceAccount:${CONSOLE_SA}" --role="roles/pubsub.publisher"

# Grant BigQuery dataset READER to Detector, MCP, and Console SAs
bq show --format=prettyjson "${PROJECT_ID}:Cymbal_Cyber" > /tmp/cymbal_dataset.json
jq --arg det "${DETECTOR_SA}" --arg mcp "${MCP_SA}" --arg con "${CONSOLE_SA}" \
  '.access += [{"role": "READER", "userByEmail": $det}, {"role": "READER", "userByEmail": $mcp}, {"role": "READER", "userByEmail": $con}]' \
  /tmp/cymbal_dataset.json > /tmp/cymbal_dataset_new.json
bq update --source /tmp/cymbal_dataset_new.json "${PROJECT_ID}:Cymbal_Cyber"

# 3. Create Pub/Sub Push Invoker, Scheduler, and Console Access Service Accounts
gcloud iam service-accounts create pubsub-invoker-sa --project="${PROJECT_ID}" --display-name="Cymbal Cyber Pub/Sub Push Invoker SA"
gcloud run services add-iam-policy-binding cymbal-cyber-adk-agent \
    --project="${PROJECT_ID}" --region="${REGION}" \
    --member="serviceAccount:pubsub-invoker-sa@${PROJECT_ID}.iam.gserviceaccount.com" --role="roles/run.invoker"

gcloud iam service-accounts create threat-detector-scheduler-sa --project="${PROJECT_ID}" --display-name="Cymbal Cyber Threat Detector Scheduler SA"
gcloud run jobs add-iam-policy-binding threat-detector \
    --project="${PROJECT_ID}" --region="${REGION}" \
    --member="serviceAccount:threat-detector-scheduler-sa@${PROJECT_ID}.iam.gserviceaccount.com" --role="roles/run.invoker"

gcloud iam service-accounts create soc-console-access --project="${PROJECT_ID}" --display-name="SOC console access (humans)"
gcloud run services add-iam-policy-binding cymbal-cyber-soc-console \
    --project="${PROJECT_ID}" --region="${REGION}" \
    --member="serviceAccount:soc-console-access@${PROJECT_ID}.iam.gserviceaccount.com" --role="roles/run.invoker"
```

---

## 5. Automated Setup via Terraform

The security architecture and IAM role bindings outlined above are codified in Terraform (`src/demo/terraform/`):

* **API Enablement:** `src/demo/terraform/main.tf`
* **BigQuery Datasets, Object Table & Partitioned Tables:** `src/demo/terraform/bigquery.tf`
* **Workload Identity & Scoped Role Bindings:** `src/demo/terraform/iam.tf`
* **Cloud Run Services, Jobs & OIDC/Caller Env Configuration:** `src/demo/terraform/cloud_run.tf`

### Apply via Terraform:
```bash
cd src/demo/terraform

# 1. Initialize Terraform with the versioned GCS remote state backend
terraform init -backend-config="bucket=${PROJECT_ID}-tfstate"

# 2. Preview changes
terraform plan -var="project_id=${PROJECT_ID}" -var="region=${REGION}"

# 3. Apply changes with strict IAM boundaries
terraform apply -var="project_id=${PROJECT_ID}" -var="region=${REGION}" -auto-approve
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

# 5. Verify Privacy Guard and PII Sanitization unit tests
uv run pytest src/demo/tests/unit/test_privacy_guard.py -v
```

---

## 7. Privacy Safeguards & Automated PII Sanitization Architecture

The multi-agent framework implements deterministic privacy guardrails to protect corporate employee privacy, prevent data exfiltration, and sanitize personal data without compromising cybersecurity threat investigation:

### 1. Deterministic Google Search Privacy Gate (`before_tool_callback`)
* **Location:** [`adk_agent/agent.py`](file:///workspaces/Google/adk_agent/agent.py) via `google_search_privacy_gate_callback`.
* **Problem Addressed:** In standard LLM agent patterns, privacy constraints rely solely on system prompt instructions (e.g. *"do not search internal names"*). An adversarial prompt or model hallucination can easily cause the agent to send corporate usernames, internal device hostnames, or private network topology to external search engines.
* **Architectural Defense:**
  * Implemented as an ADK `before_tool_callback` on `google_search_agent` that intercepts the search query before the tool executes.
  * **Fails Closed:** Programmatically validates queries against investigated session identities (`user_id`, `device_id`), generic internal workstation patterns (`ws-*`, `srv-*`), private RFC-1918 IPv4 ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.1`), internal domain namespaces (`.internal`, `.corp`), and personal PII.
  * If a violation is detected, the callback immediately returns `status: "BLOCKED"` with error `PRIVACY_GATE_VIOLATION`. The search query is **never transmitted across the network**.

### 2. Automated PII Sanitization Engine
* **Location:** [`adk_agent/privacy_guard.py`](file:///workspaces/Google/adk_agent/privacy_guard.py) via `mask_pii()`.
* **Zero-Cloud & High Performance:** Executes locally with zero cloud dependencies or external latency, applying deterministic pattern matchers and algorithmic validators (including Luhn checksum validation for payment card PANs).
* **Redaction Coverage:**
  * Personal Email Addresses (`[REDACTED_EMAIL]`)
  * US Social Security Numbers (`[REDACTED_SSN]`)
  * Payment Card Numbers with Luhn Check (`[REDACTED_CREDIT_CARD]`)
  * Phone Numbers (`[REDACTED_PHONE]`)
  * Internal RFC-1918 IPv4 Addresses (`[REDACTED_INTERNAL_IP]`)
  * Embedded API Keys, Bearer Tokens, and Passwords (`[REDACTED_SECRET]`)
* **Targeted Ingress/Egress Masking Touchpoints:**
  * **Desktop OCR Forensics ([`adk_agent/tools.py`](file:///workspaces/Google/adk_agent/tools.py)):** Screen captures analyzed via Gemini Vision or local OCR are sanitized before text enters sub-agent prompt memory or session state, ensuring sensitive personal information in background user applications is neutralized.
  * **Incident Reports & Escalations ([`adk_agent/tools.py`](file:///workspaces/Google/adk_agent/tools.py)):** Structured reports passed to `dispatch_to_soc_ticketing_system`, `escalate_to_human`, and `auto_escalate_unresolved_alert` are sanitized before persistence in BigQuery or dispatch to the analyst queue.
* **Enterprise Google Cloud DLP Extension:** In enterprise production, the engine can be paired with Google Cloud Sensitive Data Protection (DLP API) for automated classification across regional data governance policies.

### 3. Threat Intelligence Preservation Guarantee
To ensure the primary objective of investigating security alerts and malicious traffic is never degraded:
* **Public IPs & Threat IOCs:** Routable public IP addresses (e.g., `175.45.176.10`, `8.8.8.8`), external threat domains (`c2-server.ru`), malware family names (`mimikatz`), attack commands (`powershell -enc`), file hashes (SHA256, MD5), and MITRE ATT&CK techniques are explicitly whitelisted and **never masked or blocked**.

