# Google AI Labs Sandbox — Project Guidance & Coding Agent Guide

## Project Overview

**Google AI Labs Sandbox** is a development environment for architecting, prototyping, evaluating, and deploying AI agents on Google Cloud. It combines the **Google Agent Development Kit (ADK)** and **Google Agents CLI (`agents-cli`)** with **Gemini models on Vertex AI / Gemini API**, containerized inside an enterprise devcontainer.

### Featured Demonstration: Real-Time Cyber Security AI
The project features an end-to-end near real-time cybersecurity threat detection, multi-agent AI investigation, and SOC response system:
- **ADK Multi-Agent Team (`adk_agent/`):** Autonomous multi-agent orchestrator coordinating 4 specialized agents:
  1. `google_search_agent`: OSINT threat intel on external public IPs (native ADK tool).
  2. `bq_investigation_agent`: 24-hour behavioral profile queries in BigQuery (via Local MCP).
  3. `visual_analysis_agent`: Gemini multimodal vision OCR on user desktop screenshots (via Local MCP).
  4. `soc_ticketing_agent`: Incident synthesis and dispatch to SOC ticketing (via Local MCP).
- **Local MCP Server (`adk_agent/mcp_server/`):** Decoupled Model Context Protocol tool server exposing 10 security, vision, and ticketing tools over standard I/O (`stdio`) to ADK sub-agents and external clients.
- **Threat Detector (`adk_agent/threat_detector.py`):** Scheduled micro-batch Cloud Run Job scanning BigQuery for newly emerging threat events and triggering agent investigations.
- **Synthetic Log Generator (`src/demo/data_generator/`):** Generates access and network logs with ad-hoc threat injection.
- **Data Engineering Pipelines (`src/demo/data_pipeline/`):** Ingestion pipelines, GCS loader, and BigQuery Continuous Queries.
- **SOC Ticketing System & Console (`src/demo/soc_ticketing/`):** Persistent incident queue and interactive Streamlit console for analyst triage.
- **Zero-Cloud Local Runner (`src/demo/local_runner.py`):** End-to-end local simulation without requiring cloud infrastructure.
- **Terraform IaC (`src/demo/terraform/`):** Infrastructure templates for Google Cloud (project `<project_name>`).

---

## Project Structure

```
/workspaces/Google/
├── adk_agent/                      # Canonical ADK Multi-Agent package
│   ├── agent.py                    # Multi-agent orchestrator & 4 sub-agents
│   ├── tools.py                    # Legacy tool implementations & compatibility facade
│   ├── mcp_server/                 # Local Model Context Protocol (MCP) server
│   │   ├── __init__.py             # Package init and server factory
│   │   ├── __main__.py             # stdio/SSE execution entrypoint
│   │   ├── server.py               # MCPServer instance & tool registrations
│   │   └── tools/                  # Modular tool providers (BigQuery, Vision, SOC)
│   ├── threat_detector.py          # Scheduled micro-batch detector Cloud Run Job
│   ├── logging_utils.py            # Structured logging utilities
│   ├── fast_api_app.py             # FastAPI backend server (webhook + A2A)
│   └── app_utils/                  # A2A and service helpers
├── src/
│   └── demo/                       # Cybersecurity AI & Cloud Architecture demo
│       ├── data_generator/         # Synthetic log generator & threat scenarios
│       ├── data_pipeline/          # BigQuery Continuous Queries & Dataflow pipelines
│       ├── scripts/                # Deployment, Continuous Query, & Dataflow demo launcher scripts
│       ├── soc_ticketing/          # SOC ticketing service & Streamlit analyst console
│       ├── terraform/              # GCP Terraform IaC modules (zero-cost default)
│       ├── tests/                  # Test suites (unit, integration, eval datasets)
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
├── DEPLOYMENT.md                   # Cloud deployment, operations, and FinOps runbook
├── CLOUD_SECURITY.md               # IAM architecture and least-privilege security baseline
├── GEMINI.md                       # Workspace guidance and agent instructions
└── README.md                       # Project documentation
```

---

## Environment Setup & Model Configuration

### 1. Environment Variables & Credentials (`.env`)
Environment variables are loaded automatically at startup via `python-dotenv`:
- `GOOGLE_GENAI_USE_ENTERPRISE=true`: Uses Vertex AI endpoint.
- `GOOGLE_CLOUD_PROJECT=<project_name>`: Target GCP project.
- `GOOGLE_CLOUD_LOCATION=us-east1` (or `global`): Model and service region.
- `GEMINI_MODEL=gemini-3.8-flash`: Configures the Gemini model.

### 2. Model Configuration
- **Model Setting:** The agent dynamically reads `os.getenv("GEMINI_MODEL", "gemini-3.8-flash")`.
- **Default Model:** `gemini-3.8-flash` is the standard active model across all agents and tools.
- **Model Override:** Change `GEMINI_MODEL` in `.env` to switch models without modifying agent source code.

---

## Development & Testing Commands

### 1. Automated Tests
Run unit tests, agent structure tests, and demo tests with `uv`:
```bash
# Run all unit tests
uv run pytest src/demo/tests/unit/

# Run integration tests (requires cloud credentials/ADC)
uv run pytest src/demo/tests/integration/
```

### 2. Interactive Agent Testing (agents-cli)
```bash
# Inspect agents-cli project configuration
agents-cli info

# Launch local ADK Web Playground
LOCAL_MODE=true agents-cli playground

# Run single prompt evaluation in terminal
agents-cli run "Investigate security alert for user u.lewis"
```

### 3. Zero-Cloud Local Demo Pipeline
Run the complete end-to-end cybersecurity pipeline locally (synthetic log generation, BigQuery Continuous Query simulation, multi-agent triage, and local SOC dispatch):
```bash
# Malicious APT attack scenario (User: u.lewis, Lazarus Group IP, Mimikatz)
python -m src.demo.local_runner --threat malicious

# Benign False Positive scenario (User: l.taylor, Admin backup script)
python -m src.demo.local_runner --threat false_positive
```

### 4. Interactive SOC Analyst Console (Streamlit)
```bash
LOCAL_MODE=true streamlit run src/demo/soc_ticketing/streamlit_soc_console.py
```
Open `http://localhost:8501` to view incident queues, inspect desktop screenshot evidence, review ADK investigative reports, and adjudicate tickets.

### 5. Scheduled Micro-Batch Threat Detector Job
```bash
# Note: Streaming to cloud sinks or running detector locally requires Application Default Credentials (ADC):
# gcloud auth application-default login

# Run single detection cycle:
python -m adk_agent.threat_detector --lookback 15 --min-score 100

# Note: When testing live Pub/Sub telemetry, wait 60s for BigQuery Storage Write API buffer ingestion:
# echo "Allowing 60s for BigQuery streaming buffer ingestion..." && sleep 60
```

---

## Agent Development Lifecycle (`agents-cli`)

1. **Understand Requirements:** Identify tools, constraints, and success criteria.
2. **Build and Implement:** Implement agent logic in `adk_agent/`. Use `agents-cli playground` for interactive validation.
3. **Evaluation Loop:** Run `agents-cli eval run` against datasets in `src/demo/tests/eval/`. Inspect cluster failures with `agents-cli eval analyze` and auto-tune with `agents-cli eval optimize`.
4. **Pre-Deployment Tests:** Run `uv run pytest src/demo/tests/unit/`.
5. **Deploy:** Deploy container image to Cloud Run service and threat detector job with `./src/demo/scripts/deploy_cloud.sh` (or `gcloud run jobs update threat-detector --image <image>`).

---

## Operational Guidelines for Coding Agents

- **Canonical Agent Location:** Always work within `adk_agent/` at repository root. Do not re-create subfolder duplicates or nested agent packages.
- **Code Preservation:** Only modify code directly targeted by the request. Preserve surrounding functions, comments, and configurations.
- **Model Configuration:** Read the model from `os.getenv("GEMINI_MODEL", "gemini-3.8-flash")` and load environment variables with `dotenv.load_dotenv()`. NEVER hardcode deprecated models.
- **Tool Imports:** Import tool instances rather than modules (e.g., `from google.adk.tools import google_search`).
- **Python Execution:** Always execute Python commands and tests with `uv run` (e.g., `uv run pytest`).
- **Verify All Changes:** Always run `uv run pytest src/demo/tests/unit/` after modifying code to confirm zero regressions.
