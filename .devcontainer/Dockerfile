FROM mcr.microsoft.com/devcontainers/python:3.12-bookworm

ARG UV_VERSION=0.12.23
ARG NODE_MAJOR=22
ARG GEMINI_CLI_VERSION=latest

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    UV_SYSTEM_CERTS=true \
    UV_LINK_MODE=copy \
    SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \
    REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt \
    PATH="/home/vscode/.local/bin:${PATH}"

USER root

# -------------------------------------------------------------------
# 1. Install the Kyndryl corporate CA certificate
# -------------------------------------------------------------------
COPY .devcontainer/Kyndryl-SSL-Inspection.cer \
    /usr/local/share/ca-certificates/Kyndryl-SSL-Inspection.crt

RUN chmod 0644 \
        /usr/local/share/ca-certificates/Kyndryl-SSL-Inspection.crt \
    && update-ca-certificates \
    && openssl x509 \
        -in /usr/local/share/ca-certificates/Kyndryl-SSL-Inspection.crt \
        -noout \
        -subject \
        -issuer

ENV NODE_EXTRA_CA_CERTS=/usr/local/share/ca-certificates/Kyndryl-SSL-Inspection.crt

# -------------------------------------------------------------------
# 2. Install pinned uv and uvx standalone binaries (multi-arch)
# -------------------------------------------------------------------
COPY --from=ghcr.io/astral-sh/uv:0.12.23 /uv /uvx /usr/local/bin/

# -------------------------------------------------------------------
# 3. Install system dependencies and configure repositories
# -------------------------------------------------------------------
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        apt-transport-https \
        build-essential \
        ca-certificates \
        curl \
        git \
        gnupg \
        jq \
        lsb-release \
        unzip \
        vim \
        wget \
        zip; \
    install -d -m 0755 /etc/apt/keyrings /usr/share/keyrings; \
    \
    curl -fsSL "https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key" \
        | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg; \
    chmod 0644 /etc/apt/keyrings/nodesource.gpg; \
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_${NODE_MAJOR}.x nodistro main" \
        > /etc/apt/sources.list.d/nodesource.list; \
    \
    curl -fsSL "https://packages.cloud.google.com/apt/doc/apt-key.gpg" \
        | gpg --dearmor -o /usr/share/keyrings/cloud.google.gpg; \
    chmod 0644 /usr/share/keyrings/cloud.google.gpg; \
    echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" \
        > /etc/apt/sources.list.d/google-cloud-sdk.list; \
    \
    curl -fsSL "https://apt.releases.hashicorp.com/gpg" \
        | gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg; \
    chmod 0644 /usr/share/keyrings/hashicorp-archive-keyring.gpg; \
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com bookworm main" \
        > /etc/apt/sources.list.d/hashicorp.list; \
    \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        google-cloud-cli \
        nodejs \
        terraform; \
    apt-get clean; \
    rm -rf /var/lib/apt/lists/*

# -------------------------------------------------------------------
# 4. Install global Node.js CLI tools
# -------------------------------------------------------------------
RUN npm install --global --no-audit --no-fund \
        "@google/gemini-cli@${GEMINI_CLI_VERSION}" \
    && npm cache clean --force \
    && gemini --version

# -------------------------------------------------------------------
# 5. Install baseline Python dependencies via uv (fast build)
# -------------------------------------------------------------------
COPY requirements.txt /tmp/requirements.txt

RUN uv pip install --system --system-certs -r /tmp/requirements.txt \
    && python -m pip check \
    && rm -f /tmp/requirements.txt

# -------------------------------------------------------------------
# 6. Grant non-root user ownership of /usr/local
# Allows vscode user to run `uv pip install --system` without sudo
# -------------------------------------------------------------------
RUN chown -R vscode:vscode /usr/local

USER vscode

WORKDIR /workspaces/Google
