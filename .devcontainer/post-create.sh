#!/usr/bin/env bash

set -euo pipefail

export UV_LINK_MODE=copy

echo "Preparing persistent package caches..."

sudo mkdir -p \
    /home/vscode/.cache/pip \
    /home/vscode/.cache/uv \
    /home/vscode/.cache/npm

sudo chown -R vscode:vscode /home/vscode/.cache

echo "Syncing Python dependencies..."

if [[ -f requirements.txt ]]; then
    uv pip install \
        --system \
        --system-certs \
        --requirement requirements.txt
else
    echo "No requirements.txt found. Skipping Python dependencies."
fi

echo "Registering Jupyter kernel for VS Code..."

python -m ipykernel install \
    --user \
    --name "google-ai-sandbox" \
    --display-name "Python 3.12 (Google AI Sandbox)"

echo "Validating Python dependencies..."

python -m pip check

echo "Configuring Google Agents CLI..."

uvx --system-certs google-agents-cli setup

echo "Development container setup completed successfully."
