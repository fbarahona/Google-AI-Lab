# Google AI Labs Sandbox

**Google AI Labs Sandbox** is an enterprise-grade development environment built for architecting, prototyping, evaluating, and deploying AI agents on Google Cloud. It integrates the **Google Agent Development Kit (ADK)** and **Google Agents CLI (`agents-cli`)** with the **Google Gen AI SDK / Vertex AI**, preconfigured in a Debian-based Visual Studio Code Dev Container.

---

## 🚀 Key Features & Tech Stack

- **Python Runtime:** Python 3.12 (Debian Bookworm) with high-performance dependency management via [uv](https://docs.astral.sh/uv/).
- **Google Agent Development Kit (`google-adk`):** Framework for multi-agent systems, tool integration, orchestration patterns, and state/memory management.
- **Google Agents CLI (`google-agents-cli`):** Unified lifecycle CLI (`agents-cli`) for scaffolding, playground debugging, LLM-as-judge evaluations, deployment, and Gemini Enterprise publishing.
- **Google Gen AI SDK (`google-genai`):** Next-generation Python SDK for Gemini models on Google Cloud Vertex AI and Gemini Developer API.
- **Jupyter Notebooks in VS Code:** Preconfigured `ipykernel` and `ipywidgets` with auto-registered kernel `Python 3.12 (Google AI Sandbox)`.
- **Testing Suite:** `pytest` for deterministic schema/tool testing alongside `agents-cli eval run` for LLM behavioral evaluations.
- **Cloud & IaC Tooling:** Google Cloud SDK (`gcloud`), Terraform (v1.16+), Node.js (v22), and `@google/gemini-cli`.
- **Enterprise Network Security:** Corporate Root CA SSL inspection integration across OS, Python, `uv`, and Node.js.

---

## 🛠️ Getting Started

### 1. Prerequisites
- **Docker Desktop** (or Rancher Desktop / Podman) running on host or WSL2.
- **Visual Studio Code** with the **Dev Containers** (`ms-vscode-remote.remote-containers`) extension.
- Google Cloud credentials on host (`gcloud`) or a Gemini API key.

### 2. Opening in Dev Container
1. Open this repository in Visual Studio Code.
2. When prompted, click **Reopen in Container** (or run `Dev Containers: Reopen in Container` from the Command Palette `F1` / `Ctrl+Shift+P`).
3. The container will build and run `post-create.sh` to initialize persistent caches, sync dependencies, register the Jupyter kernel, and configure `agents-cli`.

---

## 🔐 Authentication & Configuration

The container is configured to bind-mount host credentials into the container with path guards:

### Google Cloud (Vertex AI)
To refresh credentials or authenticate inside the container:
```bash
# Authenticate with Google Cloud
gcloud auth login
gcloud auth application-default login

# Set your target project
gcloud config set project <PROJECT_ID>
```

### Gemini Developer API
Set your API key in `.env` (or pass it via host environment variable `GEMINI_API_KEY`):
```bash
export GEMINI_API_KEY="your-api-key-here"
```

---

## 📓 Working with Jupyter Notebooks

Jupyter support is enabled out-of-the-box:

1. Create or open any `.ipynb` notebook file in VS Code.
2. In the top right corner of the notebook editor, click **Select Kernel** -> **Python Environments...**
3. Choose **`Python 3.12 (Google AI Sandbox)`** (or `/usr/local/bin/python`).
4. Interactive outputs, `ipywidgets`, and progress bars will render natively in VS Code.

If you ever need to re-register the kernel:
```bash
python -m ipykernel install --user --name "google-ai-sandbox" --display-name "Python 3.12 (Google AI Sandbox)"
```

---

## 📦 Dependency Management (`uv`)

Dependencies are managed using `uv` for ultra-fast, deterministic resolution:

```bash
# Install / sync requirements to container environment
uv pip install --system --system-certs -r requirements.txt

# Run Python scripts with uv
uv run python my_script.py

# Run unit tests
uv run pytest
```

---

## 🤖 Google Agents CLI Workflow

Use `agents-cli` for the end-to-end agent development lifecycle:

| Action | Command | Purpose |
|---|---|---|
| **Inspect Environment** | `agents-cli info` | Displays CLI version, active paths, and registered skills |
| **Scaffold Agent** | `agents-cli scaffold create <name>` | Bootstraps a new agent with ADK patterns and eval configs |
| **Enhance Project** | `agents-cli scaffold enhance .` | Adds CI/CD and deployment targets to existing projects |
| **Interactive Test** | `agents-cli playground` | Launches a local web playground for chat and prompt testing |
| **Terminal Test** | `agents-cli run "Prompt"` | Runs a prompt through the local agent in terminal |
| **Evaluate** | `agents-cli eval run` | Runs LLM-as-judge automated evaluations against test cases |
| **Deploy** | `agents-cli deploy` | Deploys agent to Agent Runtime, Cloud Run, or GKE |
| **Publish** | `agents-cli publish gemini-enterprise` | Registers the agent with Gemini Enterprise |

---

## 🏗️ Dev Container Architecture & Optimizations

The container incorporates several enterprise optimizations:
- **Fast Build via Standalone uv:** Binaries are copied directly from Astral's official container image (`ghcr.io/astral-sh/uv`), eliminating `pip` bootstrap overhead.
- **Cross-Filesystem Cache:** Named volume `vscode-ai-pkg-cache` caches packages at `/home/vscode/.cache`. `UV_LINK_MODE=copy` is enabled to eliminate filesystem hardlink warnings.
- **Non-Root Permissions:** `/usr/local` is owned by `vscode:vscode`, allowing developers to run `uv pip install --system` without `sudo`.
- **Host Mount Safety:** Dev container `initializeCommand` ensures host `.config/gcloud`, `.gemini`, and `.gitconfig` files exist prior to Docker bind mounting, preventing Docker from mistakenly creating `.gitconfig` as a directory.

---

## 📂 Project Structure

```text
/workspaces/Google/
├── .devcontainer/                  # Dev container configuration
│   ├── Dockerfile                  # Python 3.12, Node 22, Terraform, gcloud, certificates
│   ├── devcontainer.json           # Extensions, mounts, environment variables, settings
│   ├── post-create.sh              # Container initialization hook
│   └── Kyndryl-SSL-Inspection.cer  # Enterprise CA certificate
├── .env                            # Local environment variables (git-ignored)
├── .gitignore                      # Git ignore patterns
├── requirements.txt                # Python dependencies (ADK, agents-cli, Jupyter, pytest)
├── GEMINI.md                       # Comprehensive agent development & lifecycle instructions
└── README.md                       # Workspace documentation & quickstart
```
