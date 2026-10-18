# Dev container image for GitHub Codespaces and VS Code Dev Containers (Docker Desktop).
# Tools only: project dependencies come from uv.lock via post-create.sh, into .venv.
FROM mcr.microsoft.com/devcontainers/python:3.12-bookworm

ARG UV_VERSION=0.12.23
ARG NODE_MAJOR=22
# Same Terraform as CI (.github/workflows/ci.yml).
ARG TERRAFORM_VERSION=1.16.5
ARG GEMINI_CLI_VERSION=latest

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \
    REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt \
    NODE_EXTRA_CA_CERTS=/etc/ssl/certs/ca-certificates.crt \
    GRPC_DEFAULT_SSL_ROOTS_FILE_PATH=/etc/ssl/certs/ca-certificates.crt

USER root

# 1. Optional extra CA certificates (TLS-inspecting proxies). Codespaces needs none.
COPY .devcontainer/certs/ /tmp/extra-certs/
RUN set -eux; \
    for f in /tmp/extra-certs/*.crt /tmp/extra-certs/*.cer; do \
        [ -f "$f" ] || continue; \
        out="/usr/local/share/ca-certificates/$(basename "${f%.*}").crt"; \
        openssl x509 -in "$f" -out "$out" 2>/dev/null \
            || openssl x509 -inform der -in "$f" -out "$out"; \
        chmod 0644 "$out"; \
        openssl x509 -in "$out" -noout -subject -issuer; \
    done; \
    update-ca-certificates; \
    rm -rf /tmp/extra-certs

# 2. Pinned uv and uvx.
RUN python -m pip install "uv==${UV_VERSION}" && uv --version && uvx --version

# 3. Google Cloud CLI (with the Cloud Run proxy component), Node.js and Terraform from
#    their vendors' signed apt repositories.
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        apt-transport-https build-essential ca-certificates curl git gnupg jq \
        lsb-release unzip vim wget zip; \
    install -d -m 0755 /etc/apt/keyrings /usr/share/keyrings; \
    curl -fsSL "https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key" \
        | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg; \
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_${NODE_MAJOR}.x nodistro main" \
        > /etc/apt/sources.list.d/nodesource.list; \
    curl -fsSL "https://packages.cloud.google.com/apt/doc/apt-key.gpg" \
        | gpg --dearmor -o /usr/share/keyrings/cloud.google.gpg; \
    echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" \
        > /etc/apt/sources.list.d/google-cloud-sdk.list; \
    curl -fsSL "https://apt.releases.hashicorp.com/gpg" \
        | gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg; \
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com bookworm main" \
        > /etc/apt/sources.list.d/hashicorp.list; \
    chmod 0644 /etc/apt/keyrings/nodesource.gpg /usr/share/keyrings/cloud.google.gpg \
        /usr/share/keyrings/hashicorp-archive-keyring.gpg; \
    apt-get update; \
    tf_pkg="$(apt-cache madison terraform | awk -v v="${TERRAFORM_VERSION}" '$3 ~ "^"v"-" {print $3; exit}')"; \
    test -n "$tf_pkg"; \
    apt-get install -y --no-install-recommends \
        google-cloud-cli google-cloud-cli-cloud-run-proxy nodejs "terraform=${tf_pkg}"; \
    apt-get clean; \
    rm -rf /var/lib/apt/lists/*; \
    terraform version

# 4. Gemini CLI.
RUN npm install --global --no-audit --no-fund "@google/gemini-cli@${GEMINI_CLI_VERSION}" \
    && npm cache clean --force \
    && gemini --version

USER vscode
