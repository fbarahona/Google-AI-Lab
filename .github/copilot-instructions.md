# Copilot instructions

## Development commands

- Run the unit and demo suites: `uv run pytest src/demo/tests/ tests/unit/`
- Run one test: `uv run pytest path/to/test_file.py::test_name` (for example, `uv run pytest tests/unit/test_model_config.py::test_dynamic_model_name`)
- Run integration tests separately with cloud credentials/ADC: `uv run pytest tests/integration/`
- Lint Python: `uv run --extra lint ruff check .`
- Validate Terraform as in CI:
  `terraform -chdir=src/demo/terraform init -backend=false`,
  `terraform -chdir=src/demo/terraform fmt -check`, and
  `terraform -chdir=src/demo/terraform validate`
- Run the zero-cloud end-to-end demo with `uv run python -m src.demo.local_runner --threat malicious` or `--threat false_positive`.

## Architecture

- The canonical ADK agent package is the root-level `adk_agent/`. `agent.py` defines the orchestrator and four investigation/ticketing agents; `tools.py` contains their integrations; `fast_api_app.py` exposes the FastAPI webhook and A2A service; and `threat_detector.py` runs scheduled BigQuery detection.
- The cybersecurity demo under `src/demo/` supplies synthetic logs, ingestion and detection pipelines, SOC ticketing/Streamlit console, and Terraform infrastructure. The local runner exercises the pipeline without provisioning cloud resources.
- The default cloud ingestion path uses direct Pub/Sub-to-BigQuery subscriptions. Continuous Queries and Dataflow are optional alternatives; do not run Dataflow alongside direct subscriptions because that duplicates event rows. Terraform disables costly continuous-query reservations and Dataflow workers by default.
- Cloud Run hosts the agent webhook service, while the threat detector runs as a Cloud Run Job. The README documents deployment and the cost implications of optional cloud components.

## Repository-specific conventions

- Keep agent implementation in root `adk_agent/`; do not create a duplicate or nested agent package.
- Load environment configuration with `dotenv.load_dotenv()`. Read the model from `GEMINI_MODEL` with the existing `gemini-3.8-flash` default; do not hardcode another model. Project and dataset settings are environment-configurable as shown in `adk_agent/agent.py` and `adk_agent/tools.py`.
- Import ADK tool instances from `google.adk.tools` (for example, `google_search`), rather than importing tool modules.
- Preserve safe local execution: `LOCAL_MODE=true` is used by the playground, SOC console, and CI tests. The standard unit/demo CI suite should not require live cloud credentials; integration tests do.
- For agent prompt/tool changes, use the eval datasets in `tests/eval/` and the `agents-cli eval` commands documented in `GEMINI.md`.
- Python support is `>=3.12,<3.13`; use `uv` for Python commands and dependency management.
