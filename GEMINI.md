# Google AI Labs Sandbox — Project Guidance & Instructions

## Project Overview

**Google AI Labs Sandbox** is a dedicated development environment built for architecting, prototyping, evaluating, and deploying AI agents on Google Cloud. It combines the **Google Agent Development Kit (ADK)** and **Google Agents CLI (`agents-cli`)** with **Gemini API / Vertex AI**, containerized inside a Debian-based devcontainer preconfigured for enterprise environments.

### Core Technologies
- **Python Runtime:** Python 3.12 (Debian Bookworm) managed via `uv` (v0.12+)
- **Google Agent Development Kit (`google-adk` >= 2.11.0):** Framework for defining multi-agent systems, tools, memory, and orchestration workflows.
- **Google Agents CLI (`google-agents-cli` ~= 1.9.0):** CLI (`agents-cli`) supporting the full agent lifecycle (scaffolding, testing, LLM-as-judge evaluation, deployment, and publishing).
- **Google Gen AI SDK (`google-genai` >= 2.23.0):** Next-gen client for Gemini models on Google Cloud Vertex AI and Gemini Developer API.
- **Google Auth (`google-auth` >= 2.58.0):** Application Default Credentials (ADC) and IAM integration.
- **Interactive Notebooks & Jupyter:** `ipykernel` (>= 6.29.0) and `ipywidgets` (>= 8.1.0) with preconfigured VS Code Jupyter integration and pre-registered kernel spec (`Python 3.12 (Google AI Sandbox)`).
- **Unit Testing Framework:** `pytest` (>= 8.0.0) for deterministic tool and schema testing.
- **Infrastructure & Cloud Tooling:** `terraform` (v1.16+), `gcloud` (Google Cloud SDK), `nodejs` (v22), `@google/gemini-cli`.
- **Enterprise Network Support:** Kyndryl corporate root CA integration for SSL inspection across OS, Node.js, Python, and `uv`.

---

## Environment Setup & Authentication

The project runs within a Visual Studio Code Dev Container (`.devcontainer/devcontainer.json`).

### 1. Credentials & Authentication
The devcontainer automatically mounts host credentials into the container with host-safety protections (`initializeCommand` prevents directory creation for missing files):
- **Google Cloud ADC:** `${HOME}/.config/gcloud` mounted to `/home/vscode/.config/gcloud`
- **Gemini CLI Config:** `${HOME}/.gemini` mounted to `/home/vscode/.gemini`
- **Git Config:** `${HOME}/.gitconfig` mounted read-only

If credentials need refreshing or initial authentication:
```bash
# Authenticate Google Cloud and generate Application Default Credentials
gcloud auth login
gcloud auth application-default login

# Set default GCP project
gcloud config set project <PROJECT_ID>
```

Ensure `GEMINI_API_KEY` is exported if calling the Gemini Developer API directly outside Vertex AI:
```bash
export GEMINI_API_KEY="<your-api-key>"
```

### 2. Corporate CA Certificate Handling & Performance
Enterprise SSL inspection uses `/usr/local/share/ca-certificates/Kyndryl-SSL-Inspection.crt`.
- `UV_SYSTEM_CERTS=true` is set in the container environment.
- `UV_LINK_MODE=copy` is configured to ensure optimal package copying across the cache volume and container filesystem boundaries.
- Non-root user `vscode` owns `/usr/local`, allowing passwordless `uv pip install --system`.
- Always include `--system-certs` when invoking standalone `uvx` commands:
  ```bash
  uvx --system-certs google-agents-cli setup
  ```

---

## Common Development Commands

### Dependency Management (uv & pip)
Always use `uv` for fast, deterministic dependency resolution:
```bash
# Install dependencies from requirements.txt to system environment
uv pip install --system --system-certs -r requirements.txt

# Run Python scripts with uv
uv run python <script.py>

# Verify Python package integrity
python -m pip check
```

### Interactive Notebooks (Jupyter in VS Code)
The container includes complete out-of-the-box support for Jupyter notebooks (`.ipynb`):
- **Kernel Selection:** When opening a notebook in VS Code, select the kernel named **`Python 3.12 (Google AI Sandbox)`** (or `/usr/local/bin/python`).
- **Interactive Widgets:** `ipywidgets` is pre-installed for rich progress bars (`tqdm`), interactive parameter widgets, and ADK tool visualization.
- **Re-registering Kernel (if needed):**
  ```bash
  python -m ipykernel install --user --name "google-ai-sandbox" --display-name "Python 3.12 (Google AI Sandbox)"
  ```

### Unit Testing
Run deterministic tests via `pytest`:
```bash
uv run pytest
# or
pytest
```

### Google Agents CLI (`agents-cli`) Workflow

The primary development interface for ADK agents is `agents-cli`:

| Task | Command | Description |
|------|---------|-------------|
| **Inspect Setup** | `agents-cli info` | Shows CLI version, install path, and active configuration |
| **Scaffold Project** | `agents-cli scaffold create <agent_name>` | Generates a new agent project with eval and deployment scaffolding |
| **Enhance Code** | `agents-cli scaffold enhance .` | Adds agents-cli config, eval boilerplate, or deployment targets to an existing folder |
| **Smoke Test** | `agents-cli run "Your test prompt"` | Executes a prompt through the local agent in terminal |
| **Interactive Test** | `agents-cli playground` | Launches a local web playground for interactive chat and debugging |
| **Evaluate Behavior**| `agents-cli eval run` | Runs LLM-as-judge evaluation against test datasets |
| **Deploy Agent** | `agents-cli deploy` | Deploys agent to configured target (Agent Runtime, Cloud Run, GKE) |
| **Publish Agent** | `agents-cli publish gemini-enterprise` | Registers agent with Gemini Enterprise |

### Infrastructure as Code (Terraform)
For recipes and agents utilizing custom Google Cloud infrastructure (e.g., Cloud SQL, Cloud Storage, Agent Platform):
```bash
terraform init
terraform plan
terraform apply
```

---

## Agent Development Lifecycle & Architecture Guidelines

When developing agents in this workspace, follow the standardized 7-phase lifecycle:

### Phase 0: Design & Specification
- Define core agent goals, required external APIs/tools, and safety guardrails.
- Write or inspect `.agents-cli-spec.md` before generating code.

### Phase 1: Reference Recipes
- Before implementing custom features (retrieval/RAG, isolated sandboxes, cross-session memory, human-in-the-loop approval gates), inspect ADK recipes. Avoid reinventing complex patterns already available in ADK reference implementations.

### Phase 2: Scaffolding
- Always use `agents-cli scaffold create <name>` or `agents-cli scaffold enhance .` before writing custom agent files. Scaffolding sets up standard configs, evaluation suites, and CI/CD targets.

### Phase 3: Building (ADK Patterns)
- Use `google-adk` agents, tools, and callbacks.
- **Code Preservation:** Surgically modify only the targeted functions or prompts requested by the user. Do not alter surrounding configurations, model names, or comments unintentionally.
- **Model Selection:**
  - Never alter existing agent model specifications unless requested.
  - When querying model availability on Vertex AI:
    ```bash
    uv run --with google-genai python -c "
    from google import genai
    client = genai.Client(vertexai=True, location='global')
    for m in client.models.list(): print(m.name)
    "
    ```

### Phase 4: Evaluation vs. Unit Testing
- **Unit Tests (`pytest`):** Strictly test deterministic code (tools, helper functions, schemas, API contracts, data parsing).
  ```bash
  uv run pytest
  ```
- **Agent Behavioral Testing (`agents-cli eval`):** Never write unit tests that assert non-deterministic LLM strings or phrasing. Behavioral checks, safety boundaries, persona stability, and tool trajectories belong in evaluation datasets graded by `agents-cli eval run`.

### Phase 5 & Beyond: Deployment & Observability
- Configure deployment targets (Agent Runtime, Cloud Run, GKE) using `agents-cli scaffold enhance . --deployment-target <target>`.
- Use Cloud Trace and BigQuery Agent Analytics for production observability.

---

## Directory Structure

```
/workspaces/Google/
├── .devcontainer/              # Dev container definition & provisioning
│   ├── Dockerfile              # Python 3.12, Node 22, Terraform, gcloud, certificates
│   ├── devcontainer.json       # Extensions, mounts, environment variables
│   ├── post-create.sh          # Post-creation setup (caches, pip install, agents-cli)
│   └── Kyndryl-SSL-Inspection.cer # Enterprise CA certificate
├── .env                        # Local environment variables (ignored by git)
├── .gitignore                  # Git ignore rules
├── requirements.txt            # Base Python dependencies (ADK, agents-cli, Jupyter, pytest)
├── GEMINI.md                   # Agent and project context instructions
└── README.md                   # Project documentation
```
