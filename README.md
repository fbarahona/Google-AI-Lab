# Real-Time Cyber Security AI & Google ADK Multi-Agent Sandbox

An enterprise-grade platform demonstrating real-time cybersecurity threat detection, autonomous multi-agent AI forensic investigation, and human-in-the-loop Security Operations Center (SOC) triage built on **Google Cloud Platform (project `oso-ai-503519`)**, **Google Agent Development Kit (ADK)**, and **Google Agents CLI (`agents-cli`)**.

---

## 🏛️ Architecture Overview

```
                                  ┌───────────────────────────┐
                                  │ Synthetic Log Generator   │
                                  │ CLI & Threat Injection    │
                                  └─────────────┬─────────────┘
                                                │
                 ┌──────────────────────────────┼──────────────────────────────┐
                 ▼                              ▼                              ▼
    ┌─────────────────────────┐   ┌─────────────────────────┐   ┌─────────────────────────┐
    │  Google Cloud Storage   │   │     Cloud Pub/Sub       │   │  Direct BQ Streaming    │
    │  gs://cymbal-cyber-     │   │  cymbal_cyber_raw_logs  │   │     Storage Write API   │
    │  raw-logs_oso-ai-503519 │   └─────────────┬───────────┘   └─────────────┬───────────┘
    └────────────┬────────────┘                 │                             │
                 │ (GCS Loader)                 │ (Dataflow Streaming)        │
                 └──────────────────────┐       ▼                             │
                                        ▼─────────────────────────────────────┘
                                   BigQuery Tables (Cymbal_Cyber)
                                   ├── user_access_events
                                   ├── network_events
                                   ├── adk_threat_assessment
                                   └── soc_tickets
                                                │
                         ┌──────────────────────┴──────────────────────┐
                         ▼                                             ▼
            BigQuery Continuous Query                      BigQuery Threat Scanner
            (Exports alerts >= 100 to Pub/Sub)             (Active daemon reading BQ)
                         │                                             │
                         └──────────────────────┬──────────────────────┘
                                                ▼
                               ┌─────────────────────────────────┐
                               │   ADK Multi-Agent Orchestrator  │
                               │           (adk_agent/)          │
                               └────────────────┬────────────────┘
                                                │
         ┌──────────────────────────────┬───────┴──────────────────────┬──────────────────────────────┐
         ▼                              ▼                              ▼                              ▼
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

## 🚀 Key Features

1. **Google ADK Multi-Agent Team (`adk_agent/`)**:
   - **`google_search_agent`**: Autonomous OSINT IP reputation investigation on external public IP addresses.
   - **`bq_investigation_agent`**: 24-hour behavioral profiling querying BigQuery (`user_access_events` and `network_events`).
   - **`visual_analysis_agent`**: Multimodal Gemini vision analysis and OCR inspecting user desktop forensic screenshots.
   - **`soc_ticketing_agent`**: Consolidates forensic findings into a structured Security Incident Report and dispatches formal incident tickets.
2. **BigQuery Threat Scanner (`adk_agent/threat_scanner.py`)**:
   - Background daemon monitoring the BigQuery dataset for anomalous security alerts and activating the ADK orchestrator.
3. **Synthetic Log Generator (`src/demo/data_generator/`)**:
   - High-fidelity synthetic event generator simulating access and network logs with ad-hoc threat injection (both APT attacks and benign administrative false positives).
4. **Data Engineering Pipelines (`src/demo/data_pipeline/`)**:
   - Stream and batch ingestion pathways via BigQuery Continuous Queries, Pub/Sub to Dataflow, and GCS batch loading.
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
│   ├── threat_scanner.py           # BigQuery active anomaly scanning daemon
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
├── requirements.txt                # System Python dependencies
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

### 4. Run the BigQuery Threat Scanner
```bash
# Run a single scan pass:
python -m adk_agent.threat_scanner --once

# Run continuous background daemon:
python -m adk_agent.threat_scanner --daemon --interval 30
```

### 5. Run Automated Tests
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
| `GOOGLE_CLOUD_PROJECT` | GCP Project ID | `oso-ai-503519` |
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
