# Real-Time Cyber Security AI & Google ADK Multi-Agent Platform

[![Google Cloud](https://img.shields.io/badge/Google_Cloud-4285F4?style=for-the-badge&logo=google-cloud&logoColor=white)](https://cloud.google.com/)
[![Google ADK](https://img.shields.io/badge/Google_ADK-Multi--Agent-34A853?style=for-the-badge&logo=google&logoColor=white)](https://adk.dev/)
[![Gemini 3.8 Flash](https://img.shields.io/badge/Gemini_3.8_Flash-Multimodal-FBBC04?style=for-the-badge&logo=google-gemini&logoColor=black)](https://ai.google.dev/)
[![Model Context Protocol](https://img.shields.io/badge/MCP-Local_Tool_Server-7B1FA2?style=for-the-badge&logo=protocol&logoColor=white)](https://modelcontextprotocol.io/)
[![BigQuery](https://img.shields.io/badge/BigQuery-Single_Source_of_Truth-673AB7?style=for-the-badge&logo=google-bigquery&logoColor=white)](https://cloud.google.com/bigquery)

An enterprise reference architecture for real-time cybersecurity threat detection, autonomous multi-agent forensic investigation, and human-in-the-loop Security Operations Center (SOC) triage, built with the **Google Agent Development Kit (ADK)**, **Gemini 3.8 Flash**, the **Model Context Protocol (MCP)**, and **Google Cloud Platform**.

---

## 🎯 The Problem & the Solution

| The Challenge in Modern SOCs | The Autonomous Multi-Agent Solution |
| :--- | :--- |
| **Alert Fatigue:** Security analysts are bombarded with hundreds of daily alerts, 70%+ of which turn out to be benign administrative false positives. | **Automated Forensic Synthesis:** Autonomous agents triage alerts instantly, separating genuine APT attacks from benign scripts without human delay. |
| **Fragmented Evidence:** Investigating a single incident requires querying historical logs, checking external OSINT IP reputation, and examining desktop artifacts across disparate systems, taking **30 to 45 minutes per alert**. | **Multi-Specialist Agent Team:** Specialized ADK agents gather OSINT intelligence, profile 24-hour behavioral baselines in BigQuery, and perform multimodal OCR on desktop evidence in parallel, in **under 30 seconds**. |
| **Monolithic, Fragile Tooling:** Legacy AI tooling binds database connections and heavy dependencies directly into prompt loops, risking crashes and prompt injection. | **Decoupled Local MCP Server:** Tools run in an independent MCP server over `stdio`, with fixed parameterized queries (no free-form SQL), BigQuery scan ceilings, and least-privilege tool access per agent. |

---

## 🚀 Getting Started

The local quickstart runs the full pipeline as a **zero-cloud simulation**: no infrastructure is deployed and no cloud costs are incurred. For a real Google Cloud deployment, see the [Cloud Deployment Runbook](DEPLOYMENT.md).

### Prerequisites

- **Python 3.12** (the project requires `>=3.12,<3.13`)
- **[uv](https://docs.astral.sh/uv/)** for dependency management
- **`agents-cli`** (optional, for the ADK playground)
- **Google Cloud SDK** with Application Default Credentials (only for cloud mode and integration tests)

### 1. Install dependencies and configure the environment

```bash
uv sync
cp .env.example .env   # set GOOGLE_CLOUD_PROJECT, or GEMINI_API_KEY for Google AI Studio
```

`.env.example` documents the supported variables, including `GEMINI_MODEL` (default `gemini-3.8-flash`) and `ADK_ALLOW_CONFIG_STDIO_MCP_SERVERS=true`, which the ADK needs to launch the local MCP server.

### 2. Run the end-to-end forensic simulation

The local runner generates synthetic access and network logs, detects an anomaly, runs the multi-agent investigation, and writes the adjudicated ticket:

```bash
# Scenario A: Malicious APT attack (user u.lewis, Lazarus Group IP, Mimikatz in memory)
uv run python -m src.demo.local_runner --threat malicious

# Scenario B: Benign false positive (user l.taylor, admin running scheduled backup scripts)
uv run python -m src.demo.local_runner --threat false_positive

# Scenario C: Prompt injection (user c.wilson, screenshot text trying to coerce a false-positive closure)
uv run python -m src.demo.local_runner --threat injection
```

Use `--user <id>` to target a different user.

### 3. Launch the SOC Analyst Console

Inspect the incident queue, view desktop screenshot evidence, review the multi-agent investigative report, and adjudicate tickets:

```bash
LOCAL_MODE=true uv run streamlit run src/demo/soc_ticketing/streamlit_soc_console.py
```

Then open **http://localhost:8501** in your browser.

### 4. Launch the ADK Agent Playground

Chat interactively with the multi-agent team in the built-in web playground:

```bash
LOCAL_MODE=true agents-cli playground
```

---

## 🕵️ How the Multi-Agent Forensic Team Works

When an anomaly triggers, the ADK orchestrator (**`SecurityInvestigationOrchestrator`**, in [`adk_agent/agent.py`](adk_agent/agent.py)) runs the investigation in two phases:

1. **Parallel investigation:** the `InvestigationTeam` runs three specialist agents at the same time.
2. **Adjudication:** the `soc_ticketing_agent` synthesizes their findings and resolves or dispatches the incident.

```
                                ┌─────────────────────────────────┐
                                │   ADK Multi-Agent Orchestrator  │
                                │   (Cloud Run Webhook: FastAPI)  │
                                └────────────────┬────────────────┘
                                                 │
                                ┌────────────────┴─────────────────────────┐
                                ▼                                          ▼
   ┌──────────────────────────────────────────────────────────┐   ┌──────────────────┐
   │        InvestigationTeam (Phase 1: run in parallel)      │   │soc_ticketing_    │
   │                                                          │──▶│agent             │
   │ ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │   │(Phase 2)         │
   │ │google_search_│  │bq_investiga- │  │visual_analy- │     │   │Local MCP stdio:  │
   │ │agent         │  │tion_agent    │  │sis_agent     │     │   │Ticket Dispatch   │
   │ │Native search │  │Local MCP:    │  │Local MCP:    │     │   └────────┬─────────┘
   │ │grounding     │  │Behavior query│  │Vision OCR    │     │            │
   │ └──────────────┘  └──────────────┘  └──────────────┘     │            ▼
   └──────────────────────────────────────────────────────────┘   ┌──────────────────┐
                                                                  │SOC Analyst       │
                                                                  │Console (Streamlit│
                                                                  │+ BigQuery SSOT)  │
                                                                  └──────────────────┘
```

| Agent | Role | What it does |
| :--- | :--- | :--- |
| `google_search_agent` | External OSINT intelligence | Investigates external public IPs flagged in network telemetry, using native ADK Google Search grounding to correlate them with known threat actors (e.g., Lazarus Group, APT29) and Tor/VPN exit nodes. |
| `bq_investigation_agent` | Behavioral telemetry profiling | Queries historical access and network logs in BigQuery through the local MCP server, building a 24-hour baseline of login frequency, authentication failures, and privilege anomalies for the user and device. |
| `visual_analysis_agent` | Multimodal desktop forensics | Retrieves desktop screenshots from Cloud Storage and runs Gemini vision inspection and OCR to extract terminal commands, detecting malicious utilities (e.g., Mimikatz, PowerShell obfuscation, Netcat reverse shells) and prompt injection attempts. |
| `soc_ticketing_agent` | Synthesis & incident dispatch | Combines all findings into a structured **Security Incident Report**. Benign activity is resolved with audit notes (`log_false_positive`); confirmed malicious activity gets a ticket ID and is dispatched to BigQuery and the SOC queue. |

---

## 🔌 Local MCP Tool Server

Agent tools are decoupled from the orchestrator into an independent MCP server, `cymbal-cyber-mcp`, in [`adk_agent/mcp_server/`](adk_agent/mcp_server/). It runs over `stdio` by default and supports SSE with `--sse`.

### Why MCP?

- **Subprocess isolation:** Database SDKs, image processors, and network clients run in a separate process, so crashes or memory leaks cannot destabilize the orchestrator. Each MCP-backed sub-agent gets one server process (three in total), not one per tool.
- **Least-privilege tool scoping:** Each sub-agent connects through one `ScopedMcpToolset` whose `tool_filter` lists only the tools its role needs (e.g., the BigQuery agent cannot generate signed URLs, and the vision agent cannot modify ticket queues).
- **No free-form SQL:** The server exposes only fixed, parameterized operations. There is no `execute_sql` or schema-discovery tool, so a client that connects without a `tool_filter` still cannot run arbitrary queries. Every BigQuery job the tools run carries a `maximum_bytes_billed` ceiling (1 GB default, configurable with `BQ_MAX_BYTES_BILLED`).
- **Cross-client interoperability:** Because the server speaks standard MCP, other AI clients (Cursor, Windsurf, Claude Desktop, Gemini Enterprise) can use the same security tool catalog.

### Registered tools (8)

| Domain | Tool | Purpose & security enforcement |
| :--- | :--- | :--- |
| **BigQuery Telemetry** | `get_entity_behavioral_profile` | Aggregates a 24-hour behavioral baseline for a user or IP. |
| **Multimodal Vision** | `get_visual_analysis_for_user` | Runs Gemini multimodal OCR on desktop screenshot evidence. |
| | `get_gcs_uri_for_user` | Resolves the Cloud Storage URI (`gs://...`) for a user's desktop captures. |
| | `generate_signed_url` | Generates short-lived V4 signed URLs for analyst inspection without exposing public buckets. |
| **SOC Operations** | `dispatch_to_soc_ticketing_system` | Formats and dispatches high-confidence incidents to BigQuery `soc_tickets`. |
| | `log_false_positive` | Logs analyzed benign activity to BigQuery `alerts` with resolution notes. |
| | `create_rich_ticket_id` | Generates deterministic, auditable incident identifiers (`INC-...`). |
| | `escalate_to_human` | Writes raw forensic payloads to Cloud Storage for senior analyst escalation. |

See [Cloud Security & IAM Architecture](CLOUD_SECURITY.md#3-decoupled-tool-execution-via-local-model-context-protocol-mcp-server) for the security model behind the server.

---

## 🏛️ End-to-End System Architecture

A rendered diagram is also available at [`src/demo/system_architecture.png`](src/demo/system_architecture.png).

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
                                           │  └─────────────────────────────┘
                                           ▼
                                ┌─────────────────────────────────┐
                                │   ADK Multi-Agent Orchestrator  │
                                │   (Cloud Run Webhook: FastAPI)  │
                                └────────────────┬────────────────┘
                                                 │ stdio (JSON-RPC)
                                                 ▼
                                ┌─────────────────────────────────┐
                                │   Local MCP Server (`cymbal`)   │
                                │   (adk_agent/mcp_server/)       │
                                └────────────────┬────────────────┘
                                                 │
                                                 ▼
                                ┌─────────────────────────────────┐
                                │      SOC Ticketing System       │
                                │  - Incident Queue & BigQuery    │
                                │  - Streamlit Analyst Console    │
                                └─────────────────────────────────┘
```

### Architectural highlights

- **Serverless event bus:** Telemetry flows from Pub/Sub directly into day-partitioned BigQuery event tables through BigQuery subscriptions.
- **Zero-continuous-cost threat detector:** [`adk_agent/threat_detector.py`](adk_agent/threat_detector.py) runs as a Cloud Run Job every 5 minutes, evaluating 2-minute tumbling windows with idempotent BigQuery `MERGE` queries ($0 continuous slot cost).
- **Native Pub/Sub push webhook:** The orchestrator runs on Cloud Run with native OpenID Connect (OIDC) token validation (`roles/run.invoker`), with no proxy relays.
- **Dead-letter auto-escalation:** Alerts that fail 5 delivery attempts go to `cymbal_cyber_alerts_dlq`, are recorded in `alerts_dead_letter`, and are escalated to SOC tickets.
- **BigQuery as single source of truth (SSOT):** The ADK agent team and the Streamlit SOC console read and write the same dataset (`Cymbal_Cyber`), so every decision is auditable.

---

## 📂 Project Structure

```text
.
├── adk_agent/                      # ADK multi-agent package (agents-cli agent_directory)
│   ├── agent.py                    # Orchestrator, parallel investigation team & 4 sub-agents
│   ├── tools.py                    # Tool implementations & compatibility facade
│   ├── mcp_server/                 # Local MCP server ("cymbal-cyber-mcp")
│   │   ├── __main__.py             # stdio/SSE CLI entrypoint
│   │   ├── server.py               # Server definition & 8 registered tools
│   │   └── tools/                  # Tool providers (BigQuery, Vision, SOC)
│   ├── threat_detector.py          # Scheduled micro-batch detector (Cloud Run Job)
│   ├── threat_scanner.py           # Legacy standalone threat scanner
│   ├── fast_api_app.py             # FastAPI backend (Pub/Sub webhook + A2A)
│   ├── logging_utils.py            # Structured logging utilities
│   └── app_utils/                  # Service & A2A helpers
├── src/demo/                       # Cybersecurity AI & cloud architecture demo
│   ├── data_generator/             # Synthetic log generator & threat scenarios
│   ├── data_pipeline/              # Continuous Query, Dataflow & GCS loader pipelines
│   ├── scripts/                    # Deployment, Continuous Query & Dataflow launchers
│   ├── soc_ticketing/              # SOC ticketing service & Streamlit analyst console
│   ├── terraform/                  # GCP Terraform IaC modules (zero-cost baseline)
│   ├── tests/                      # unit/, integration/ and eval/ suites
│   ├── other_code/                 # Supporting SQL queries & analyst scripts
│   ├── local_runner.py             # Zero-cloud end-to-end demo runner
│   └── README.md                   # Demo deep dive (pipeline, detection, agents)
├── local_demo_data/
│   ├── user_screenshots/           # Forensic desktop screenshots for the vision agent
│   └── escalations/                # Local escalation output
├── .github/workflows/ci.yml        # CI: ruff, unit tests, Terraform validation & Checkov
├── Dockerfile                      # Container image for Cloud Run / Agent Runtime
├── agents-cli-manifest.yaml        # agents-cli configuration
├── pyproject.toml / uv.lock        # Python package configuration & locked dependencies
├── pytest.ini                      # Pytest configuration
├── .env.example                    # Template environment variables
├── DEPLOYMENT.md                   # Cloud deployment, operations & FinOps runbook
├── CLOUD_SECURITY.md               # IAM architecture & least-privilege baseline
├── SCAFFOLD.md                     # Vertex AI Agent Runtime scaffolding & deployment
└── GEMINI.md                       # Agent engineering & lifecycle guide
```

---

## 🧪 Testing & CI

```bash
# Unit tests (default pytest target, no cloud access needed)
uv run pytest src/demo/tests/unit/

# Integration tests (require Application Default Credentials)
uv run pytest src/demo/tests/integration/

# Lint
uv run --extra lint ruff check .
```

The [CI workflow](.github/workflows/ci.yml) runs on pushes and pull requests to `main`: Ruff linting and unit tests with `LOCAL_MODE=true`, plus Terraform format, validation, and Checkov static security analysis on `src/demo/terraform`.

---

## 📚 Documentation & Deep Dives

| Guide | Description | Target audience |
| :--- | :--- | :--- |
| 🚀 **[Cloud Deployment Runbook](DEPLOYMENT.md)** | Terraform provisioning, container builds, Cloud Run deployment, `gcloud` proxy console access, and FinOps teardown. | Cloud Engineers, DevOps, SREs |
| 🛡️ **[Cloud Security & IAM Architecture](CLOUD_SECURITY.md)** | Least-privilege identity tiers, service account bindings, Workload Identity, role assignment scripts, and security audit commands. | Security Architects, CISOs, IAM Admins |
| 🤖 **[Agent Engineering & Lifecycle Guide](GEMINI.md)** | ADK multi-agent architecture, `agents-cli` evaluation flywheel, prompt optimization, coding conventions, and test commands. | AI Engineers, Agent Developers |
| 🧱 **[Agent Runtime Scaffolding Guide](SCAFFOLD.md)** | Scaffolding and deploying the agent to Vertex AI Agent Runtime with `agents-cli`. | AI Engineers, Cloud Engineers |
| 🧭 **[Demo Deep Dive](src/demo/README.md)** | Data generation, ingestion, detection engines, alert contract, and the SOC console in detail. | Everyone exploring the demo |
| 🏗️ **[Terraform Modules](src/demo/terraform/README.md)** | Infrastructure-as-code modules and variables. | Cloud Engineers |

---

## License

Licensed under the [Apache License 2.0](LICENSE).
