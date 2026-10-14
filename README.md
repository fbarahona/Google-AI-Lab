# Real-Time Cyber Security AI & Google ADK Multi-Agent Platform

[![Google Cloud](https://img.shields.io/badge/Google_Cloud-4285F4?style=for-the-badge&logo=google-cloud&logoColor=white)](https://cloud.google.com/)
[![Google ADK](https://img.shields.io/badge/Google_ADK-Multi--Agent-34A853?style=for-the-badge&logo=google&logoColor=white)](https://adk.dev/)
[![Gemini 3.8 Flash](https://img.shields.io/badge/Gemini_3.8_Flash-Multimodal-FBBC04?style=for-the-badge&logo=google-gemini&logoColor=black)](https://ai.google.dev/)
[![Model Context Protocol](https://img.shields.io/badge/MCP-Local_Tool_Server-7B1FA2?style=for-the-badge&logo=protocol&logoColor=white)](https://modelcontextprotocol.io/)
[![BigQuery](https://img.shields.io/badge/BigQuery-Single_Source_of_Truth-673AB7?style=for-the-badge&logo=google-bigquery&logoColor=white)](https://cloud.google.com/bigquery)

An enterprise reference architecture demonstrating real-time cybersecurity threat detection, autonomous multi-agent forensic investigation, and human-in-the-loop Security Operations Center (SOC) triage built with the **Google Agent Development Kit (ADK)**, **Gemini 3.8 Flash**, **Model Context Protocol (MCP)**, and **Google Cloud Platform**.

---

## 🎯 The Core Problem & Solution

| The Challenge in Modern SOCs | The Autonomous Multi-Agent Solution |
| :--- | :--- |
| **Alert Fatigue:** Security analysts are bombarded with hundreds of daily alerts, 70%+ of which turn out to be benign administrative false positives. | **Automated Forensic Synthesis:** Autonomous agents triage alerts instantly, separating genuine APT attacks from benign scripts without human delay. |
| **Fragmented Evidence:** Investigating a single incident requires querying historical logs, checking external OSINT IP reputation, and examining desktop artifacts across disparate systems—taking **30 to 45 minutes per alert**. | **Multi-Specialist Agent Swarm:** Specialized ADK agents simultaneously gather OSINT intelligence, profile 24-hour behavioral baselines in BigQuery, and perform multimodal OCR on desktop evidence in **under 30 seconds**. |
| **Monolithic, Fragile Tooling:** Legacy AI tooling binds database connections and heavy dependencies directly into prompt loops, risking crashes and prompt injection. | **Decoupled Local MCP Server:** Tools are isolated in an independent Model Context Protocol server over `stdio`, enforcing AST-level SQL guardrails, query scan ceilings, and least-privilege tool access. |

---

## ⚡ 60-Second Quickstart (Zero-Cloud Simulation)

Experience the full cybersecurity pipeline locally without deploying any cloud infrastructure or incurring cloud costs.

### 1. Run the End-to-End Forensic Simulation
Execute the automated pipeline locally (generates synthetic access and network logs, detects an anomaly, triggers the ADK multi-agent investigation, and writes the adjudicated ticket):

```bash
# Scenario A: Malicious APT Attack (Lazarus Group IP, Mimikatz in memory)
python -m src.demo.local_runner --threat malicious

# Scenario B: Benign False Positive (Admin running scheduled backup scripts)
python -m src.demo.local_runner --threat false_positive
```

### 2. Launch the Interactive SOC Analyst Console
Launch the Streamlit console to inspect the incident queue, view desktop screenshot evidence, review the multi-agent investigative report, and adjudicate tickets:

```bash
LOCAL_MODE=true streamlit run src/demo/soc_ticketing/streamlit_soc_console.py
```
*Open **`http://localhost:8501`** in your browser.*

### 3. Launch the ADK Agent Playground
Inspect and interactively chat with the multi-agent team via the built-in web playground:

```bash
LOCAL_MODE=true agents-cli playground
```

### 4. Run Automated Test Suite
Run the comprehensive unit test suite with `uv`:

```bash
uv run pytest src/demo/tests/unit/
```

---

## 🕵️ How the Multi-Agent Forensic Team Works

When an anomaly triggers, the **ADK Orchestrator** assigns the investigation to four specialized sub-agents working in concert:

```
                                ┌─────────────────────────────────┐
                                │   ADK Multi-Agent Orchestrator  │
                                │   (Cloud Run Webhook: FastAPI)  │
                                └────────────────┬────────────────┘
                                                 │
         ┌──────────────────────────────┬────────┴──────────────────────┬──────────────────────────────┐
         ▼                              ▼                               ▼                              ▼
┌──────────────────┐           ┌──────────────────┐           ┌──────────────────┐           ┌──────────────────┐
│google_search_    │           │bq_investigation_ │           │visual_analysis_  │           │soc_ticketing_    │
│agent             │           │agent             │           │agent             │           │agent             │
│                  │           │                  │           │                  │           │                  │
│Native Grounding: │           │Local MCP stdio:  │           │Local MCP stdio:  │           │Local MCP stdio:  │
│google_search     │           │Behavioral Query  │           │Vision OCR & URLs │           │Ticket Dispatch   │
└──────────────────┘           └──────────────────┘           └──────────────────┘           └─────────┬────────┘
                                                                                                       │
                                                                                                       ▼
                                                                                       ┌─────────────────────────────────┐
                                                                                       │      SOC Analyst Console        │
                                                                                       │   (Streamlit + BigQuery SSOT)   │
                                                                                       └─────────────────────────────────┘
```

1. **`google_search_agent` (External OSINT Intelligence):**
   - Investigates external public IPs flagged in network telemetry.
   - Utilizes native ADK search grounding to correlate addresses against known threat actors (e.g., Lazarus Group, APT29) and Tor exit nodes.
2. **`bq_investigation_agent` (Behavioral Telemetry Profiling):**
   - Queries historical access and network logs in BigQuery via the Local MCP server.
   - Constructs a 24-hour baseline for the user and device to evaluate login frequency, authentication failures, and privilege anomalies.
3. **`visual_analysis_agent` (Multimodal Desktop Forensic OCR):**
   - Retrieves forensic desktop screenshots stored in Cloud Storage.
   - Performs multimodal Gemini vision inspection and OCR to extract active terminal commands, detecting malicious utilities (e.g., Mimikatz, PowerShell obfuscation, Netcat reverse shells).
4. **`soc_ticketing_agent` (Synthesis & Incident Dispatch):**
   - Synthesizes findings from all agents into a structured **Security Incident Report**.
   - If indicators are benign, automatically resolves the alert with audit notes (`log_false_positive`).
   - If malicious activity is confirmed, generates an immutable ticket ID and dispatches the incident to BigQuery and the SOC queue.

---

## 🔌 Decoupled Local Model Context Protocol (MCP) Server

The agent tooling layer is decoupled from the core orchestrator into an independent **Local Model Context Protocol (MCP)** server ([`adk_agent/mcp_server/`](file:///workspaces/Google/adk_agent/mcp_server/)). 

### Why MCP?
- **Subprocess Isolation:** Heavy database SDKs, image processors, and network clients run in an isolated process over standard I/O (`stdio`), preventing crashes or memory leaks from destabilizing the orchestrator. Each MCP-backed sub-agent gets one server process (three in total), not one per tool.
- **Least-Privilege Tool Scoping:** Each sub-agent connects through one `ScopedMcpToolset` whose `tool_filter` lists only the tools authorized for its role (e.g., the BigQuery agent cannot access signed URL generators; the Vision agent cannot modify ticket queues).
- **No Free-Form SQL:** The server exposes only fixed, parameterized operations. There is no `execute_sql` or schema-discovery tool, so a client that connects without a `tool_filter` still cannot run arbitrary queries. Every BigQuery job the tools run carries a `maximum_bytes_billed` ceiling (1 GB default, `BQ_MAX_BYTES_BILLED`).
- **Cross-Client Interoperability:** Because the server implements standard MCP, external AI environments (Cursor, Windsurf, Claude Desktop, Gemini Enterprise) can query the exact same security tool catalog directly.

### Registered Tool Domains (8 Tools)

| Domain | Tool Name | Purpose & Security Enforcement |
| :--- | :--- | :--- |
| **BigQuery Telemetry** | `get_entity_behavioral_profile` | Aggregates 24-hour behavioral baseline for user/IP. |
| **Multimodal Vision** | `get_visual_analysis_for_user` | Runs Gemini multimodal OCR on desktop screenshot evidence. |
| | `get_gcs_uri_for_user` | Resolves Cloud Storage URI (`gs://...`) for user desktop captures. |
| | `generate_signed_url` | Generates short-lived V4 signed URLs for analyst inspection without exposing public buckets. |
| **SOC Operations** | `dispatch_to_soc_ticketing_system` | Formats and dispatches high-confidence security incidents to BigQuery `soc_tickets`. |
| | `log_false_positive` | Logs analyzed benign activities to BigQuery `alerts` with resolution notes. |
| | `create_rich_ticket_id` | Generates deterministic, auditable incident identifiers (`INC-...`). |
| | `escalate_to_human` | Writes raw forensic payloads to Cloud Storage for senior analyst escalation. |

---

## 🏛️ End-to-End System Architecture

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
                                │   (adk_agent/mcp_server)        │
                                └────────────────┬────────────────┘
                                                 │
                                                 ▼
                                ┌─────────────────────────────────┐
                                │      SOC Ticketing System       │
                                │  - Incident Queue & BigQuery    │
                                │  - Streamlit Analyst Console    │
                                └─────────────────────────────────┘
```

### Architectural Highlights
- **Serverless Event Bus:** Telemetry flows from Pub/Sub directly into day-partitioned BigQuery event tables via streaming write subscriptions.
- **Zero-Continuous-Cost Threat Detector:** Runs as a scheduled micro-batch Cloud Run Job every 5 minutes. Evaluates 2-minute tumbling windows via idempotent BigQuery MERGE queries ($0 continuous slot cost).
- **Native Pub/Sub Push Webhook:** Deployed to Cloud Run with native OpenID Connect (OIDC) token validation (`roles/run.invoker`), requiring zero proxy relays.
- **BigQuery as Single Source of Truth (SSOT):** Both the ADK agent team and the Streamlit SOC analyst console read and write to the same BigQuery dataset (`Cymbal_Cyber`), ensuring complete auditability.

---

## 📂 Project Structure

```text
/workspaces/Google/
├── adk_agent/                      # Canonical ADK Multi-Agent package
│   ├── agent.py                    # Multi-agent orchestrator & 4 sub-agents
│   ├── tools.py                    # Legacy tool implementations & compatibility facade
│   ├── mcp_server/                 # Local Model Context Protocol (MCP) Server
│   │   ├── __init__.py             # Package initialization & factory
│   │   ├── __main__.py             # stdio/SSE CLI execution entrypoint
│   │   ├── server.py               # MCPServer("cymbal-cyber-mcp") & 8 security tools
│   │   └── tools/                  # Modular tool providers (BigQuery, Vision, SOC)
│   ├── threat_detector.py          # Scheduled micro-batch detector (Cloud Run Job)
│   ├── logging_utils.py            # Structured logging utilities
│   ├── fast_api_app.py             # FastAPI backend server (webhook + A2A)
│   └── app_utils/                  # Service & A2A helpers
├── src/
│   └── demo/                       # Cybersecurity AI & Cloud Architecture demo
│       ├── data_generator/         # Synthetic log generator & threat scenarios
│       ├── data_pipeline/          # BigQuery Continuous Queries & Dataflow pipelines
│       ├── scripts/                # Deployment, Continuous Query, & Dataflow launcher scripts
│       ├── soc_ticketing/          # SOC ticketing service & Streamlit analyst console
│       ├── terraform/              # GCP Terraform IaC modules (zero-cost baseline)
│       ├── tests/                  # Consolidated test suites (unit, integration, eval datasets)
│       │   ├── unit/               # Unit tests (agent structure, tools, logs, security, detector)
│       │   ├── integration/        # Agent and server integration tests
│       │   └── eval/               # agents-cli evaluation datasets and configs
│       ├── user_screenshots/       # Forensic desktop screenshots for vision agent
│       ├── local_runner.py         # Zero-cloud end-to-end demo runner
│       └── other_code/             # Supporting SQL queries and analyst scripts
├── agents-cli-manifest.yaml        # agents-cli configuration (agent_directory: adk_agent)
├── pyproject.toml                  # Python package configuration & dependencies
├── pytest.ini                      # Pytest runner configuration
├── .env.example                    # Template environment variables
├── .env                            # Local environment variables (not committed)
├── DEPLOYMENT.md                   # Cloud Deployment, Operations, and FinOps Runbook
├── CLOUD_SECURITY.md               # IAM Architecture, Identity Tiers, and Least-Privilege Baseline
├── GEMINI.md                       # Comprehensive Agent Engineering & Lifecycle Guide
└── README.md                       # Main project introduction & overview
```

---

## 📚 Documentation & Deep Dives

To keep this overview focused and accessible, in-depth architectural and operational guides have been organized into specialized reference documents:

| Guide | Description | Target Audience |
| :--- | :--- | :--- |
| 🚀 **[Cloud Deployment Runbook](file:///workspaces/Google/DEPLOYMENT.md)** | Step-by-step Terraform provisioning, container compilation, Cloud Run deployment, `gcloud` proxy console access, and FinOps teardown. | Cloud Engineers, DevOps, SREs |
| 🛡️ **[Cloud Security & IAM Architecture](file:///workspaces/Google/CLOUD_SECURITY.md)** | Least-privilege identity tiers, service account bindings, Workload Identity, automated role assignment scripts, and security audit commands. | Security Architects, CISOs, IAM Admins |
| 🤖 **[Agent Engineering & Lifecycle Guide](file:///workspaces/Google/GEMINI.md)** | ADK multi-agent architecture, `agents-cli` evaluation flywheel, prompt optimization, coding conventions, and automated testing commands. | AI Engineers, Agent Developers |
