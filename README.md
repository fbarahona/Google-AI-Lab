# Real-Time Cyber Security AI & Google ADK Multi-Agent Sandbox

A reference demo with production-style patterns demonstrating real-time cybersecurity threat detection, autonomous multi-agent AI forensic investigation, and human-in-the-loop Security Operations Center (SOC) triage built on **Google Cloud Platform (project `<project_name>`)**, **Google Agent Development Kit (ADK)**, and **Google Agents CLI (`agents-cli`)**.

---

## 🏛️ Architecture Overview

```
                                  ┌───────────────────────────┐
                                  │ Synthetic Log Generator   │
                                  │ CLI & Threat Injection    │
                                  │ event_family: access|net  │
                                  └─────────────┬─────────────┘
                                                │
                                                ▼
                                   ┌─────────────────────────┐
                                   │  Pub/Sub Raw Logs Topic │
                                   │  cymbal_cyber_raw_logs  │
                                   └───────┬─────────┬───────┘
                                           │         │
                 event_family="access"     │         │ event_family="network"
                 BigQuery Subscription     │         │ BigQuery Subscription
                                           ▼         ▼
                                    BigQuery Tables (Cymbal_Cyber)
                                    ├── user_access_events (DAY partition)
                                    ├── network_events     (DAY partition)
                                    ├── alerts             (DAY partition, clustered)
                                    ├── alerts_dead_letter (DLQ audit store)
                                    ├── adk_threat_assessment
                                    └── soc_tickets
                                                 │
                                                 │ Cloud Scheduler (every 5m)
                                                 ▼
                                    ┌─────────────────────────────┐
                                    │ Cloud Run Job: threat-detector
                                    │ (TIMESTAMP_BUCKET 2m + MERGE)
                                    └────────────┬────────────────┘
                                                 │ (Alert Contract JSON)
                                                 ▼
                                    ┌─────────────────────────────┐
                                    │ Topic: cymbal_cyber_alerts  │
                                    └──────┬───────────────┬──────┘
                                           │               │ Failed 5 times
                          Push Subscription│               ▼
                                           │  ┌─────────────────────────────┐
                                           │  │ Topic: cymbal_cyber_alerts_dlq
                                           │  │ Subscription -> DLQ Table   │
                                           │  └────────────┬────────────────┘
                                           │               ▼
                                           │  ┌─────────────────────────────┐
                                           │  │ Detector Next Run: Marks    │
                                           │  │ DEAD_LETTERED & Auto-Escalate
                                           │  └─────────────────────────────┘
                                           ▼
                                ┌─────────────────────────────────┐
                                │   ADK Multi-Agent Orchestrator  │
                                │   (Cloud Run Webhook: Fast API) │
                                │   - Checks alerts.status (!=DONE)
                                │   - Sets INVESTIGATING -> DONE   │
                                └────────────────┬────────────────┘
                                                 │
         ┌──────────────────────────────┬────────┴──────────────────────┬──────────────────────────────┐
         ▼                              ▼                               ▼                              ▼
┌──────────────────┐           ┌──────────────────┐           ┌──────────────────┐           ┌──────────────────┐
│google_search_    │           │bq_investigation_ │           │visual_analysis_  │           │soc_ticketing_    │
│agent             │           │agent             │           │agent             │           │agent             │
│                  │           │                  │           │                  │           │                  │
│Tool:             │           │Tools:            │           │Tools:            │           │Tools:            │
│google_search     │           │BigQueryToolset,  │           │Vision OCR,       │           │Dispatch Ticket,  │
│(OSINT IP Lookup) │           │behavioral queries│           │Signed GCS URL    │           │False Positive BQ │
└──────────────────┘           └──────────────────┘           └──────────────────┘           └─────────┬────────┘
                                                                                                       │
                                                                                                       ▼
                                                                                      ┌─────────────────────────────────┐
                                                                                      │      SOC Ticketing System       │
                                                                                      │  - Incident Queue & BigQuery    │
                                                                                      │  - Webhook Dispatcher           │
                                                                                      │  - Streamlit Analyst Console    │
                                                                                      └─────────────────────────────────┘
```

---

### 🏗️ Deployment Architecture: Cloud Run vs. Agent Runtime (Vertex AI Reasoning Engine)

This project deploys the ADK Multi-Agent Team to **Google Cloud Run** rather than Vertex AI Agent Runtime (Reasoning Engine). This is a deliberate architectural decision:
- **Native Pub/Sub Push Authentication:** Cloud Run natively accepts Google Cloud Pub/Sub push subscriptions authenticated with OpenID Connect (OIDC) identity tokens (`roles/run.invoker`), requiring **zero** token-exchange relays or intermediary proxy microservices.
- **FastAPI Ingestion & A2A Protocols:** Hosting the agent container on Cloud Run provides full control over FastAPI routes, enabling direct continuous query alert webhook ingestion (`/apps/adk_agent/trigger/pubsub`), message deduplication, and Google A2A inter-agent communication.
- **Execution Lifecycle & Timeouts:** Forensic investigations across 4 specialized agents can run up to several minutes. Cloud Run supports configurable request timeouts up to 600s matching the Pub/Sub acknowledgement deadline, avoiding premature execution kills.

*Alternative (Vertex AI Agent Runtime):* If deploying to Vertex AI Reasoning Engine / Agent Runtime (`agents-cli deploy --target agent_runtime`), Pub/Sub push cannot authenticate directly to the Reasoning Engine API endpoint; a dedicated Cloud Run or Cloud Function relay must be deployed in front to unwrap the Pub/Sub push envelope and call the Reasoning Engine SDK.

---

## 🚀 Key Features

1. **Google ADK Multi-Agent Team (`adk_agent/`)**:
   - **`google_search_agent`**: Autonomous OSINT IP reputation investigation on external public IP addresses.
   - **`bq_investigation_agent`**: 24-hour behavioral profiling querying BigQuery (`user_access_events` and `network_events`).
   - **`visual_analysis_agent`**: Multimodal Gemini vision analysis and OCR inspecting user desktop forensic screenshots.
   - **`soc_ticketing_agent`**: Consolidates forensic findings into a structured Security Incident Report and dispatches formal incident tickets.
2. **Scheduled Threat Detector (`adk_agent/threat_detector.py`) [Default]**:
   - Scheduled micro-batch detector running as a Cloud Run Job. Aggregates 2-minute tumbling windows in BigQuery via idempotent MERGE, publishes unified alert contract JSON to Pub/Sub, and auto-escalates dead-lettered alerts with $0 slot reservation cost.
3. **Synthetic Log Generator (`src/demo/data_generator/`)**:
   - High-fidelity synthetic event generator simulating access and network logs with ad-hoc threat injection (both APT attacks and benign administrative false positives).
4. **Data Engineering Pipelines (`src/demo/data_pipeline/`)**:
   - Ingestion and streaming pipelines: Direct Pub/Sub-to-BigQuery subscriptions **[Default]**, BigQuery Continuous Queries **[Optional / Benchmark Only]**, and an optional Dataflow Beam pipeline **[Optional / Benchmark Only]** (custom ETL alternative to direct subscriptions; do not run concurrently with direct subscriptions to avoid duplicate event rows).
5. **Interactive SOC Analyst Console (`src/demo/soc_ticketing/`)**:
   - Full-featured Streamlit console supporting queue management, visual screenshot preview, ADK forensic report inspection, and analyst triage.
6. **Zero-Cloud Local Runner (`src/demo/local_runner.py`)**:
   - Test and demonstrate the full cybersecurity pipeline locally without deploying any cloud resources.
7. **Terraform Infrastructure as Code (`src/demo/terraform/`)**:
   - Modular IaC templates provisioning BigQuery datasets, tables, Pub/Sub topics, subscriptions, and GCS buckets.

---

## 📂 Project Structure

```text
/workspaces/Google/
├── adk_agent/                      # Canonical ADK Multi-Agent package
│   ├── agent.py                    # Multi-agent orchestrator & 4 sub-agents
│   ├── tools.py                    # Tools (BigQuery, OSINT, Vision OCR, SOC ticketing)
│   ├── threat_detector.py          # Scheduled micro-batch detector (Cloud Run Job)
│   ├── threat_scanner.py           # [Legacy] Standalone anomaly scanning daemon
│   ├── logging_utils.py            # Structured logging utilities
│   ├── fast_api_app.py             # FastAPI backend server
│   └── app_utils/                  # A2A and service helpers
├── src/
│   └── demo/                       # Cybersecurity AI & Cloud Architecture demo
│       ├── data_generator/         # Synthetic log generator & threat scenarios
│       ├── data_pipeline/          # BigQuery Continuous Queries & Dataflow pipelines
│       ├── soc_ticketing/          # SOC ticketing service & Streamlit analyst console
│       ├── terraform/              # GCP Terraform IaC modules
│       ├── tests/                  # Demo unit tests (agent structure, tools, logs, SOC)
│       ├── user_screenshots/       # Forensic desktop screenshots for vision agent
│       ├── local_runner.py         # Zero-cloud end-to-end demo runner
│       └── other_code/             # Supporting SQL queries and analyst scripts
├── tests/
│   ├── unit/                       # Project unit tests (model config, dummy tests)
│   ├── integration/                # Agent integration tests
│   └── eval/                       # agents-cli evaluation datasets and configs
├── agents-cli-manifest.yaml        # agents-cli configuration (agent_directory: adk_agent)
├── pyproject.toml                  # Python package configuration & dependencies
├── pytest.ini                      # Pytest runner configuration
├── .env.example                    # Template environment variables
├── .env                            # Local environment variables (not committed)
├── GEMINI.md                       # Comprehensive agent development & lifecycle instructions
└── README.md                       # Workspace documentation & quickstart
```

---

## 🛠️ Quickstart: Running the Applications

### 1. Zero-Cloud Local Demo Pipeline
Run the end-to-end pipeline locally (generates synthetic logs, simulates Continuous Query correlation, activates ADK investigation, and dispatches the ticket):
```bash
# Scenario A: Malicious APT attack (User: u.lewis, Lazarus Group IP, Mimikatz)
python -m src.demo.local_runner --threat malicious

# Scenario B: Benign False Positive (User: l.taylor, Admin backup script)
python -m src.demo.local_runner --threat false_positive
```

### 2. Launch the Interactive SOC Analyst Console
Launch the Streamlit console to inspect tickets, view desktop evidence, and adjudicate alerts:
```bash
LOCAL_MODE=true streamlit run src/demo/soc_ticketing/streamlit_soc_console.py
```
Open `http://localhost:8501` in your browser.

### 3. Launch the ADK Agent Playground
Run the interactive web playground to chat with and debug the ADK agents:
```bash
LOCAL_MODE=true agents-cli playground
```

### 4. Run Automated Tests
```bash
# Run all unit and demo test suites
uv run pytest src/demo/tests/ tests/unit/
```

---

## 🔐 Configuration & Environment Variables

Copy `.env.example` to `.env` to configure your environment:

```bash
cp .env.example .env
```

| Variable | Description | Default |
|---|---|---|
| `GEMINI_MODEL` | Active Gemini model for agents and vision | `gemini-3.8-flash` |
| `GOOGLE_GENAI_USE_ENTERPRISE` | Route requests through Vertex AI | `true` |
| `GOOGLE_CLOUD_PROJECT` | GCP Project ID | `<project_name>` |
| `GOOGLE_CLOUD_LOCATION` | GCP location / region | `us-east1` (or `global`) |
| `BIGQUERY_DATASET` | Target BigQuery dataset | `Cymbal_Cyber` |
| `GEMINI_API_KEY` | Optional: Gemini Developer API key (if not using ADC) | `""` |

---

## 🤖 Google Agents CLI (`agents-cli`)

This project is configured with `agents-cli` for managing the agent development lifecycle:

| Command | Purpose |
|---|---|
| `agents-cli info` | Inspect project configuration and paths |
| `agents-cli playground` | Launch local ADK Web Playground |
| `agents-cli run "<prompt>"` | Smoke test agent behavior in terminal |
| `agents-cli eval run` | Run LLM-as-judge automated evaluation |
| `agents-cli deploy` | Deploy agent to configured target |
| `agents-cli lint` | Run code quality checks |

---

## 🚀 Cloud Deployment (Cloud Run Service & Threat Detector Job)

After provisioning the infrastructure with Terraform (`terraform apply`), build and deploy the unified container image to both the ADK Agent Service and the scheduled Threat Detector Cloud Run Job:

```bash
# Option A: One-command deployment script
./src/demo/deploy_cloud.sh <PROJECT_ID> <REGION>

# Option B: Manual gcloud deployment
IMAGE_TAG="${GOOGLE_CLOUD_LOCATION}-docker.pkg.dev/${GOOGLE_CLOUD_PROJECT}/cymbal-cyber/cymbal-cyber-agent:latest"

# 1. Build & Push unified container image
gcloud builds submit --project="${GOOGLE_CLOUD_PROJECT}" --tag="${IMAGE_TAG}" .

# 2. Update Cloud Run Service (ADK Agent Webhook)
gcloud run deploy cymbal-cyber-adk-agent \
  --project="${GOOGLE_CLOUD_PROJECT}" \
  --region="${GOOGLE_CLOUD_LOCATION}" \
  --image="${IMAGE_TAG}"

# 3. Update Cloud Run Job (Threat Detector micro-batch job)
gcloud run jobs update threat-detector \
  --project="${GOOGLE_CLOUD_PROJECT}" \
  --region="${GOOGLE_CLOUD_LOCATION}" \
  --image="${IMAGE_TAG}"

# 4. (Optional) Manually execute a detection pass (Cloud-Only, requires GCP credentials)
gcloud run jobs execute threat-detector \
  --project="${GOOGLE_CLOUD_PROJECT}" \
  --region="${GOOGLE_CLOUD_LOCATION}"
# Or test locally against live cloud BigQuery/PubSub:
# python -m adk_agent.threat_detector --lookback 15 --min-score 100
```

---

## 💰 FinOps: Cost Control & Teardown

> **⚠️ Cloud Resource Billing Warning:**  
> The zero-cloud local runner (`python -m src.demo.local_runner`) is free and requires zero cloud infrastructure. For cloud deployment, Terraform defaults to a **zero-continuous-cost serverless baseline** by disabling Enterprise slot reservations and continuous Dataflow workers:
> - **Default Trigger Path ($0/mo continuous):** Cloud Scheduler triggers the `threat-detector` Cloud Run Job every 5 minutes via OAuth, evaluating 2-minute tumbling windows closed >60s ago via BigQuery MERGE and pushing detected alerts to the `cymbal_cyber_alerts` Pub/Sub topic without requiring slot reservations. With the 5-minute scheduler cadence and 60-second late-data allowance, alerts arrive ~5 to 7 minutes after event occurrence.
> - **BigQuery Continuous Queries (`enable_continuous_query = true`):** Requires a 100-slot Enterprise Edition reservation. Slot reservations bill 24/7 at **~$0.06/slot-hour = ~$6.00/hour (~$4,320/month) whether or not a query is running**. Canceling the continuous query job saves no money; only disabling the reservation in Terraform (`enable_continuous_query = false && terraform apply`) stops slot billing. When enabled, submit the query via:
>   ```bash
>   ./src/demo/data_pipeline/launch_continuous_query.sh <PROJECT_ID>
>   ```
> - **Dataflow Streaming Pipeline (`scripts/run_dataflow_demo.sh`):** An optional Apache Beam ETL ingestion pipeline from Pub/Sub into BigQuery event tables. Replaces direct Pub/Sub BigQuery subscriptions (do not run both concurrently to avoid duplicate events). Provisions continuous streaming worker VMs and throughput (**~$100–$300/month**). Gated off by default.
> - **Cloud Run & Vertex AI:** Billed on-demand per request execution duration and token usage.

### Automated Budget Alert
The Terraform configuration in `src/demo/terraform/deploy.tf` provisions an automated cost alert (`google_billing_budget.demo_budget`) with a $100 ceiling and 50% / 90% threshold notifications when supplied with your Billing Account ID:
```bash
cd src/demo/terraform
terraform apply -var="project_id=<PROJECT_ID>" -var="billing_account_id=<YOUR_BILLING_ACCOUNT_ID>"
```

### Complete Cloud Teardown
To avoid continuous billing, tear down cloud infrastructure immediately when finished testing:
```bash
cd src/demo/terraform
terraform destroy -var="project_id=<PROJECT_ID>"
```
*(All BigQuery datasets and GCS buckets are configured with `delete_contents_on_destroy` and `force_destroy` so teardown succeeds cleanly even if populated).*

