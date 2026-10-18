#!/usr/bin/env bash
# Runs once when the container is created. Safe to re-run: bash .devcontainer/post-create.sh
set -euo pipefail

echo "Preparing package caches..."
sudo mkdir -p /home/vscode/.cache/uv /home/vscode/.cache/npm
sudo chown -R vscode:vscode /home/vscode/.cache

echo "Syncing Python dependencies from uv.lock into .venv..."
uv sync --frozen --extra lint

echo "Configuring Google Agents CLI..."
# Non-fatal: the demo, tests and deploy scripts do not need it.
uvx google-agents-cli setup || echo "agents-cli setup skipped; rerun: uvx google-agents-cli setup"

cat <<'MSG'

Dev container ready. Sign in to Google Cloud when you need it:
  gcloud auth application-default login
  gcloud auth application-default set-quota-project <your-project-id>
Local demo, no Google Cloud needed:
  LOCAL_MODE=true uv run python -m streamlit run src/demo/soc_ticketing/streamlit_soc_console.py
MSG
