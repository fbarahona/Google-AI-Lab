# Cymbal Cyber SOC — Project Guidance & Coding Agent Guide

## Project Overview

**Cymbal Cyber SOC** is a technical portfolio demonstration and reference architecture showcasing advanced patterns in architecting, securing, and operating an autonomous multi-agent AI system on Google Cloud. It combines the **Google Agent Development Kit (ADK)** and **Gemini models on Vertex AI** with serverless data engineering on **BigQuery** and **Cloud Pub/Sub**, decoupled tool execution via the **Model Context Protocol (MCP)**, least-privilege IAM separation of duties, and deterministic security guardrails that the LLM cannot bypass.

> **Portfolio Demonstration:** This repository is an evaluative prototype and architectural showcase; it is designed to run at near-zero continuous idle cost (~$0/month baseline) while demonstrating production-grade cybersecurity engineering standards.

### Core Demonstration: Real-Time Cyber Security AI
The platform demonstrates an end-to-end autonomous threat detection, multi-agent AI investigation, and SOC response workflow:
1. **Telemetry & Contract:** Synthetic access and network events validated against a Protobuf contract (`raw_security_event.proto`) at publish time, streaming directly into BigQuery via zero-compute Pub/Sub subscriptions.
2. **Micro-Batch Detection:** A scheduled Cloud Run Job (`threat-detector`) scans 2-minute closed tumbling windows in BigQuery using SQL UDFs and an idempotent `MERGE`, grouping correlated events into unified incidents and publishing alerts to Pub/Sub.
3. **ADK Multi-Agent Team (`adk_agent/`):** An orchestrator receives Pub/Sub push alerts via FastAPI and coordinates 4 specialized agents:
   - `google_search_agent`: OSINT threat intel on external public IPs via Gemini built-in search grounding. Protected by preventive input minimization (`before_model_callback`) and detective query auditing (`after_model_callback`).
   - `bq_investigation_agent`: Analyzes 24-hour behavioral telemetry profiles in BigQuery via parameterized MCP tools (enforcing a 1 GB scan ceiling).
   - `visual_analysis_agent`: Multimodal vision and OCR forensic inspection of desktop screenshots via MCP tools, scanning raw OCR for prompt injection before PII masking.
   - `soc_ticketing_agent`: Synthesizes evidence, generates a structured incident report, and invokes SOC ticketing tools (dispatch incident, log false positive, or escalate to human).
4. **Decoupled MCP Tool Service (`adk_agent/mcp_server/`):** A standalone Model Context Protocol server running in Cloud Run (`cymbal-cyber-mcp`) as its own service account (`cymbal-mcp-tools-sa`). The agent runtime holds zero direct evidence read or ticket write privileges and interacts solely over authenticated Streamable HTTP (or `stdio` locally).
5. **Deterministic Guardrails & PII Sanitization (`adk_agent/guardrails/`, `adk_agent/privacy_guard.py`):** Deterministic Python callbacks enforce fail-closed evidence gathering, block false-positive closures on malicious indicators or prompt injection attempts, force default-deny human escalation on unhandled alerts, and automatically redact PII (SSNs, cards, emails, phones, credentials) while preserving threat IOCs.
6. **SOC Analyst Console (`src/demo/soc_ticketing/`):** An interactive Streamlit console providing live queue triage, multimodal evidence viewing via signed URLs, KPI analytics, and ticket adjudication.

---

## Documentation Map

Detailed system documentation is organized under [`docs/`](docs/):

| Document | Description |
| :--- | :--- |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Comprehensive system architecture, end-to-end lifecycle, data contracts, multi-agent design, and key trade-offs. |
| [`docs/LOCAL.md`](docs/LOCAL.md) | Guide for running zero-cloud local scenario simulations, the Streamlit console, ADK playground, and test suites. |
| [`docs/CLOUD.md`](docs/CLOUD.md) | Cloud deployment runbook (`deploy_cloud.sh`), IAM setup, live verification workflow, console proxy access, and FinOps teardown. |
| [`docs/SECURITY_ARCHITECTURE.md`](docs/SECURITY_ARCHITECTURE.md) | Detailed least-privilege IAM baseline, workload identity boundaries, MCP privilege separation, PII engine, and agent guardrails. |
| [`docs/HISTORY.md`](docs/HISTORY.md) | Chronological evolution of architectural decisions from continuous queries and Dataflow to serverless micro-batch and decoupled MCP. |
| [`src/demo/terraform/README.md`](src/demo/terraform/README.md) | Infrastructure as Code (IaC) configuration and remote state backend reference. |

---

## Project Structure

```text
/workspaces/Google-AI-Lab/
├── adk_agent/                      # Canonical ADK Multi-Agent package
│   ├── agent.py                    # Multi-agent orchestrator, parallel team & retry configuration
│   ├── guardrails/                 # Guardrail callbacks (security gate, evidence state, search privacy, lifecycle)
│   ├── prompts.py                  # Sub-agent instructions
│   ├── mcp_client.py               # Scoped MCP toolsets
│   ├── detection_rules.py          # Python parity twin of BigQuery threat detection UDFs
│   ├── fast_api_app.py             # FastAPI backend server (Pub/Sub webhook + optional A2A/dev UI)
│   ├── logging_utils.py            # Structured logging utilities (Cloud Run JSON & plain text)
│   ├── privacy_guard.py            # Deterministic PII masking engine & search privacy audit
│   ├── threat_detector.py          # Scheduled micro-batch detector Cloud Run Job
│   ├── settings.py                 # Shared project, dataset and model settings
│   ├── tools/                      # Investigation, vision, and ticketing tool implementations
│   ├── app_utils/                  # Service initialization, alert status, and webhook helpers
│   └── mcp_server/                 # Model Context Protocol (MCP) tool server ("cymbal-cyber-mcp")
│       ├── __init__.py             # Package init and server factory
│       ├── __main__.py             # stdio/SSE execution entrypoint
│       └── server.py               # FastMCP instance, 9 tool registrations, and CallerAuthMiddleware
├── docs/                           # Architecture, local running, cloud deployment, and security guides
│   ├── ARCHITECTURE.md             # End-to-end data flow and architectural design
│   ├── CLOUD.md                    # Cloud deployment and operations guide
│   ├── HISTORY.md                  # Evolution of design decisions and cost trade-offs
│   ├── LOCAL.md                    # Local runner, scenario simulations, and testing guide
│   └── SECURITY_ARCHITECTURE.md    # IAM roles, security tiers, and guardrails reference
├── local_demo_data/                # Local test artifacts (desktop screenshots, ticket queue, escalations)
├── src/
│   └── demo/                       # Cybersecurity AI & Cloud Architecture demo application
│       ├── generate_architecture_diagram.py # Diagram generator script
│       ├── local_runner.py         # Zero-cloud end-to-end demo runner (scripted or live model)
│       ├── scripted_model.py       # Deterministic model stand-in for repeatable local tests
│       ├── data_generator/         # Synthetic log generator & threat injection scenarios
│       ├── data_pipeline/          # Continuous queries, GCS loader, and optional Dataflow pipeline
│       ├── other_code/             # Supporting analytical SQL queries and notebook helpers
│       ├── scripts/                # Pre-flight, deployment, and pipeline launcher scripts
│       ├── soc_ticketing/          # SOC ticketing service, models, and Streamlit analyst console
│       │   ├── console/            # Modular Streamlit page modules (overview, triage, ticket_detail, archive)
│       │   ├── service/            # Core ticketing service implementation (queries, writes, metrics)
│       │   ├── dashboard_charts.py # Chart and KPI visualizations
│       │   ├── demo_actions.py     # Local scenario injection triggers
│       │   ├── models.py           # Ticket and threat assessment data models
│       │   ├── report_parser.py    # Structured report parsing utilities
│       │   ├── streamlit_soc_console.py # Streamlit web application entrypoint
│       │   ├── ticket_assistant.py # Interactive ticket assistant ADK agent
│       │   └── ticketing_service.py # Backward-compatible facade for SOC ticketing operations
│       ├── terraform/              # GCP Terraform IaC modules (BigQuery, Pub/Sub, Cloud Run, IAM)
│       │   └── schemas/            # raw_security_event.proto data contract
│       └── tests/                  # Test suites (unit, e2e, integration, eval datasets)
│           ├── conftest.py         # Pytest shared fixtures and mock environments
│           ├── e2e/                # End-to-end tests with real agents, MCP, and scripted model
│           ├── eval/               # agents-cli evaluation datasets and trajectory configs
│           ├── integration/        # Live cloud integration tests (requires ADC)
│           └── unit/               # Unit tests (agent structure, tools, MCP, privacy, detector)
├── agents-cli-manifest.yaml        # agents-cli configuration (agent_directory: adk_agent)
├── pyproject.toml                  # Python package configuration (Python 3.12, uv, ruff, ty)
├── pytest.ini                      # Pytest runner configuration
├── Dockerfile                      # Unified multi-stage, non-root Cloud Run container image
├── .env.example                    # Template environment variables
├── .env                            # Local environment variables (gitignored)
├── GEMINI.md                       # Coding agent workspace guide (this file)
└── README.md                       # Project front page and quickstart overview
```

---

## Identity Tiers & Least-Privilege Architecture

The platform enforces strict separation of duties across dedicated service accounts:

| Identity | Workload / Purpose | Key Permissions & Resource Scoping |
| :--- | :--- | :--- |
| **`cymbal-deployer`** | Provisioning & Terraform CI/CD | Elevated bootstrap roles. Humans only impersonate it via `serviceAccountTokenCreator`. |
| **`soc-console-access`** | Human SOC Analyst Access | `roles/run.invoker` on SOC Console service only. **ZERO project roles** (no BQ, GCS, or Vertex access). |
| **`threat-detector-job-sa`** | Micro-Batch Detector Job | BQ `jobUser`, dataset `READER`, table `dataEditor` on `alerts` & `soc_tickets`, publisher on `cymbal_cyber_alerts`. |
| **`cymbal-adk-agent-sa`** | ADK Agent Runtime & Webhook | Vertex AI `aiplatform.user`, BQ `jobUser`, `logging.logWriter`, `telemetry.tracesWriter`, `monitoring.metricWriter`, table `dataEditor` on `alerts` & `agent_events`, `run.invoker` on MCP tool service. **ZERO evidence reads or ticket writes.** |
| **`cymbal-mcp-tools-sa`** | MCP Tool Service (`cymbal-cyber-mcp`) | BQ dataset `READER`, table `dataEditor` on `soc_tickets` & `adk_threat_assessment`, GCS `objectViewer` on screenshots, `objectUser` on escalations, self `serviceAccountTokenCreator` (signing). Invocable only by Agent SA. |
| **`cymbal-soc-console-sa`** | Streamlit Analyst Console | BQ dataset `READER`, table `dataEditor` on `soc_tickets` & `adk_threat_assessment`, GCS `objectUser` on escalations, publisher on `cymbal_cyber_raw_logs`. |
| **`pubsub-invoker-sa`** | Pub/Sub Push Authentication | `roles/run.invoker` on ADK Agent service only. Webhook strictly verifies OIDC token. |
| **`threat-detector-scheduler-sa`** | Cloud Scheduler Cron Trigger | `roles/run.invoker` on `threat-detector` Cloud Run Job only. |

---

## Environment Setup & Model Configuration

### 1. Environment Variables (`.env`)
Environment variables are loaded automatically at startup via `python-dotenv`:
- `GOOGLE_GENAI_USE_ENTERPRISE=true`: Uses Vertex AI enterprise endpoints.
- `GOOGLE_CLOUD_PROJECT=<project_name>`: Target GCP project ID.
- `GOOGLE_CLOUD_LOCATION=us-east1` (or `global`): Model region.
- `GEMINI_MODEL=gemini-3.8-flash`: Dynamic model configuration.
- `GEMINI_RETRY_ATTEMPTS=5`: Maximum retry attempts with exponential backoff and jitter for Vertex AI 429 (`RESOURCE_EXHAUSTED`), 408, and 5xx transient errors.
- `ADK_ALLOW_CONFIG_STDIO_MCP_SERVERS=true`: Enables local stdio MCP subprocess execution.
- `LOCAL_MODE=true`: Disables Cloud Trace and GCP-dependent authentication for zero-cloud runs.
- `ENABLE_CLOUD_LOGGING=false`: Optional Google Cloud Logging API direct client export (Cloud Run automatically captures structured stdout logs via `StructuredLogHandler`).
- `MCP_SERVER_URL`: Unset for local `stdio`; set to `https://<service-url>/mcp` for Cloud Run Streamable HTTP.
- `MCP_TOOL_TIMEOUT_SECONDS=90`: MCP per-request execution timeout.

### 2. Model Configuration & Resilience
- The codebase dynamically reads `os.getenv("GEMINI_MODEL", "gemini-3.8-flash")`.
- Default model: `gemini-3.8-flash` across all agents and tools.
- Never hardcode model identifiers in agent code or prompt loops.
- **Exponential Backoff & 429 Retry:** Agents configure `Gemini(model=MODEL_NAME, retry_options=types.HttpRetryOptions(attempts=GEMINI_RETRY_ATTEMPTS, initial_delay=2.0, max_delay=30.0, exp_base=2.0, jitter=1.0, http_status_codes=[408, 429, 500, 502, 503, 504]))` across all sub-agents to absorb capacity bursts.
- **Pub/Sub Rate Limit Handshake:** If Vertex AI model capacity remains exhausted after retries, the webhook returns HTTP 429 `RATE_LIMITED` (logged at `WARNING` severity). This instructs Pub/Sub to back off and redeliver without emitting 500 alert noise, while resetting alert state to `RETRY_PENDING` to prevent premature republishing.
- **Cloud Run Structured Logging:** `setup_logging()` detects Cloud Run (`K_SERVICE`) and emits single-line JSON with severity levels via `StructuredLogHandler`, consolidating stack traces into single entries and enabling Log Explorer severity filtering.

---

## Development, Testing & Verification Commands

All Python commands and test runners must be executed using **`uv`**:

### 1. Automated Test Suites
```bash
# Run all unit tests (310 tests, zero cloud credentials required)
uv run pytest src/demo/tests/unit/

# Run end-to-end pipeline tests (validates real agents, MCP tools, and security gate with scripted model)
LOCAL_MODE=true uv run pytest src/demo/tests/e2e/

# Run integration tests against real Google Cloud services (requires ADC)
uv run pytest src/demo/tests/integration/
```

### 2. Code Quality & Formatting
```bash
# Lint codebase using Ruff
uv run --extra lint ruff check .

# Automatically apply Ruff lint fixes
uv run --extra lint ruff check --fix .

# Format code with Ruff
uv run ruff format .

# Check Terraform configuration and formatting
terraform -chdir=src/demo/terraform init -backend=false
terraform -chdir=src/demo/terraform fmt -check
terraform -chdir=src/demo/terraform validate
```

### 3. Zero-Cloud Local Runner
Run complete end-to-end scenario simulations without cloud dependencies:
```bash
# Scenario A: Malicious APT attack (u.lewis, Mimikatz, C2 DNS beaconing) -> Incident Dispatched
uv run python -m src.demo.local_runner --threat malicious

# Scenario B: Benign administrative script (l.taylor, backup automation) -> Closed as False Positive
uv run python -m src.demo.local_runner --threat false_positive

# Scenario C: Prompt injection (c.wilson, adversarial OCR text) -> Gate Blocks Closure, Escalates CRITICAL
uv run python -m src.demo.local_runner --threat injection

# Use a live Gemini model instead of the deterministic scripted model
uv run python -m src.demo.local_runner --threat malicious --live-model
```

### 4. Interactive SOC Analyst Console (Streamlit)
```bash
LOCAL_MODE=true uv run python -m streamlit run src/demo/soc_ticketing/streamlit_soc_console.py
```
Open `http://localhost:8501` to view incident queues, review evidence dossiers, inspect screenshot artifacts, and adjudicate tickets.

### 5. Interactive Agent Testing (`agents-cli`)
```bash
# Inspect agent configuration
agents-cli info

# Launch local ADK Web Playground (stdio MCP)
LOCAL_MODE=true agents-cli playground

# Run single prompt evaluation in CLI
agents-cli run "Investigate security alert for user u.lewis"
```

### 6. Cloud Deployment & Verification
```bash
# 1. Interactive pre-flight validation and deployer SA role binding
source ./src/demo/scripts/pre_flight.sh

# 2. Automated Cloud Run, BigQuery, Pub/Sub, and Scheduler deployment
./src/demo/scripts/deploy_cloud.sh "${PROJECT_ID}" "${REGION}"

# 3. Proxied SOC Console access for human analysts
CONSOLE_SA="soc-console-access@${PROJECT_ID}.iam.gserviceaccount.com"
CONSOLE_URL="$(gcloud run services describe cymbal-cyber-soc-console --project="${PROJECT_ID}" --region="${REGION}" --format="value(status.url)")"

gcloud run services proxy cymbal-cyber-soc-console \
  --project="${PROJECT_ID}" \
  --region="${REGION}" \
  --port=8501 \
  --token="$(gcloud auth print-identity-token --impersonate-service-account="${CONSOLE_SA}" --audiences="${CONSOLE_URL}")"
```

---

## Operational Guidelines for Coding Agents

- **Strict Pull Request Workflow (No Direct Commits to Main):**
  Never commit, push, or deploy directly to the `main` branch under any circumstances. All changes—including feature development, bug fixes, configuration adjustments, and documentation modifications—must be performed on an isolated feature or fix branch and submitted through a GitHub Pull Request (PR) with comprehensive descriptions and test verification.
- **Python Execution via `uv`:**
  Always execute Python commands, utilities, and tests using `uv run` (e.g., `uv run pytest`, `uv run python -m ...`). Never invoke system Python directly.
- **Canonical Agent Location:**
  All agent logic must reside within `adk_agent/` at the repository root. Do not introduce duplicate agent modules, nested packages, or legacy scaffolding folders.
- **MCP Privilege Boundary Invariance:**
  Maintain strict decoupling between `cymbal-adk-agent-sa` (orchestrator/reasoning) and `cymbal-mcp-tools-sa` (MCP tool server). Never grant the agent service account direct BigQuery dataset `READER` rights, raw event table access, Cloud Storage bucket permissions, or ticket write permissions. All evidence queries, vision OCR, signed URL generation, and ticketing operations MUST execute inside the MCP tool service.
- **No Free-Form SQL Surface:**
  Never introduce arbitrary SQL execution tools (such as `execute_sql`) or schema discovery tools in the MCP tool service. Tools must remain fixed, parameterized, and validated.
- **Deterministic Guardrail Invariance:**
  Never alter guardrail callbacks to trust LLM output over deterministic checks. The security gate (`security_gate_callback`), fail-closed evidence tracking (`sync_mcp_security_state_callback`), default-deny escalation (`default_deny_soc_callback`), public-IP input minimization (`search_input_minimization_callback`), and raw OCR prompt injection scanning must remain intact and fail closed.
- **PII Redaction & IOC Preservation:**
  Modifications to reporting or OCR pipelines must route through `mask_pii()` in `adk_agent/privacy_guard.py`. Personal identifiers (SSNs, payment cards, emails, phone numbers, API keys) must be sanitized while strictly preserving routable public IPs, file hashes, external domains, and attack commands.
- **Linting & Code Formatting:**
  Adhere strictly to the workspace formatting baseline (line length 88, Python 3.12 target). Run `uv run --extra lint ruff check .` and `uv run ruff format .` before submitting changes.
- **Mandatory Test Verification:**
  Always run `uv run pytest src/demo/tests/unit/` and `LOCAL_MODE=true uv run pytest src/demo/tests/e2e/` after modifying code to verify that all 310 unit tests and end-to-end pipeline tests pass with zero regressions.
