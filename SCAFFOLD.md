# Google Cloud Agent Runtime — Scaffolding & Deployment Guide

This guide details the step-by-step workflow to scaffold and deploy the **Cymbal Cyber ADK Multi-Agent** to **Vertex AI Agent Runtime** (formerly Agent Engine) using **Google Agents CLI (`agents-cli`)**.

---

## 📋 Overview

**Vertex AI Agent Runtime** is a managed Google Cloud environment designed for running containerized AI agents built with the Google Agent Development Kit (ADK).

- **Deployment Model:** Container-based. `agents-cli deploy` packages the repository and builds the container using the root **`Dockerfile`**.
- **Backend Service:** Runs `adk_agent.fast_api_app:app` over Uvicorn on port `8080`, exposing standard ADK streaming endpoints and the A2A protocol.
- **Orchestration:** Managed autoscaling, session storage, and security governed by Google Cloud IAM.

---

## 🔧 Prerequisites

1. **Google Agents CLI (`agents-cli`):**
   ```bash
   uv tool install "google-agents-cli~=1.9.0"
   agents-cli info
   ```

2. **Google Cloud Authentication & Project Setup:**
   ```bash
   # Log in to Google Cloud
   gcloud auth login
   gcloud auth application-default login

   # Set active project
   export PROJECT_ID="<your_project_name>"
   gcloud config set project ${PROJECT_ID}
   ```

---

## 🚀 Step-by-Step Deployment Workflow

### Step 1: Enable Google Cloud APIs

Ensure all required services are enabled for Agent Runtime, container builds, and security:

```bash
gcloud services enable \
    aiplatform.googleapis.com \
    cloudbuild.googleapis.com \
    secretmanager.googleapis.com \
    storage.googleapis.com \
    bigquery.googleapis.com \
    --project=${PROJECT_ID}
```

---

### Step 2: Scaffold the Project for Agent Runtime

Enhance the current project to configure **Agent Runtime** as the deployment target:

```bash
agents-cli scaffold enhance . --deployment-target agent_runtime
```

#### What this command does:
- Updates `agents-cli-manifest.yaml` to record:
  ```yaml
  create_params:
    deployment_target: agent_runtime
  ```
- Generates required deployment metadata and configuration files.
- **Code Preservation:** Strictly preserves all existing agent code inside `adk_agent/` and tools.

---

### Step 3: (Optional) Configure Secrets in Secret Manager

If using API keys or sensitive credentials instead of Application Default Credentials (ADC):

```bash
# Store API Key in Secret Manager
echo -n "YOUR_API_KEY_VALUE" | gcloud secrets create GEMINI_API_KEY \
    --data-file=- \
    --project=${PROJECT_ID}

# Grant access to the Vertex AI Agent Runtime platform service account
PROJECT_NUMBER=$(gcloud projects describe ${PROJECT_ID} --format="value(projectNumber)")
gcloud secrets add-iam-policy-binding GEMINI_API_KEY \
    --member="serviceAccount:service-${PROJECT_NUMBER}@gcp-sa-aiplatform-re.iam.gserviceaccount.com" \
    --role="roles/secretmanager.secretAccessor" \
    --project=${PROJECT_ID}
```

---

### Step 4: Deploy to Agent Runtime

Deploy the containerized agent using `agents-cli deploy`.

#### Option A: Asynchronous Deployment (Recommended)
Agent Runtime deployments typically take **5–10 minutes** as the platform provisions infrastructure and builds the container image. Running with `--no-wait` allows background progress:

```bash
# 1. Start the deployment in the background
agents-cli deploy \
    --project=${PROJECT_ID} \
    --region=us-east1 \
    --service-name=cymbal-cyber-agent \
    --update-env-vars="GEMINI_MODEL=gemini-3.8-flash,BIGQUERY_DATASET=Cymbal_Cyber,GOOGLE_GENAI_USE_ENTERPRISE=true" \
    --no-wait

# 2. Check deployment status (poll until complete)
agents-cli deploy --status
```

#### Option B: Synchronous Deployment (Blocking)
```bash
agents-cli deploy \
    --project=${PROJECT_ID} \
    --region=us-east1 \
    --service-name=cymbal-cyber-agent \
    --update-env-vars="GEMINI_MODEL=gemini-3.8-flash,BIGQUERY_DATASET=Cymbal_Cyber,GOOGLE_GENAI_USE_ENTERPRISE=true"
```

#### Option C: Production Sizing & Secrets
```bash
agents-cli deploy \
    --project=${PROJECT_ID} \
    --region=us-east1 \
    --service-name=cymbal-cyber-agent \
    --cpu=1 \
    --memory=4Gi \
    --min-instances=1 \
    --max-instances=5 \
    --concurrency=8 \
    --secrets="GEMINI_API_KEY=GEMINI_API_KEY:latest" \
    --update-env-vars="GEMINI_MODEL=gemini-3.8-flash,BIGQUERY_DATASET=Cymbal_Cyber"
```

#### Preview Without Executing (`--dry-run`):
```bash
agents-cli deploy \
    --project=${PROJECT_ID} \
    --region=us-east1 \
    --service-name=cymbal-cyber-agent \
    --dry-run
```

---

### Step 5: Verify the Deployed Agent

Once deployment completes, verify the service and query the remote agent:

```bash
# 1. List all active deployments in the project
agents-cli deploy --list --project=${PROJECT_ID} --region=us-east1

# 2. Query the deployed agent endpoint using the ADK streaming protocol
agents-cli run \
    --url="<DEPLOYED_SERVICE_URL>" \
    --mode=adk \
    "Investigate security alert for user u.lewis"

# 3. Query using the A2A (Agent-to-Agent) protocol
agents-cli run \
    --url="<DEPLOYED_SERVICE_URL>" \
    --mode=a2a \
    "Run threat analysis on IP 175.45.176.10"
```

---

## 🔍 Troubleshooting & Operational Tips

| Issue | Cause | Solution |
|---|---|---|
| **Deployment Timeout** | Agent Runtime provisioning took > 10 minutes | Do not restart deploy. Run `agents-cli deploy --status` to reconnect to the ongoing server-side operation. |
| **Missing Module `src`** | Container missing tool dependencies | Ensure the root `Dockerfile` includes `COPY ./src ./src` along with `COPY ./adk_agent ./adk_agent`. |
| **Model 404 Error** | Unsupported region for model endpoint | Set `GOOGLE_CLOUD_LOCATION=global` or verify model availability via `gcloud` / Vertex AI console. |
| **Permission Denied (403)** | Missing IAM roles on service account | Ensure caller has `roles/aiplatform.admin` and `roles/cloudbuild.builds.editor`. |
| **Secret Access Denied** | Agent Runtime identity cannot read Secret | Grant `roles/secretmanager.secretAccessor` to `service-<PROJECT_NUMBER>@gcp-sa-aiplatform-re.iam.gserviceaccount.com`. |

---

## 🛠️ Rollback & Management

- **View Logs in Cloud Logging:**
  ```bash
  gcloud logging read 'resource.type="aiplatform.googleapis.com/ReasoningEngine"' \
      --project=${PROJECT_ID} \
      --limit=50 \
      --format="table(timestamp,severity,textPayload)"
  ```
- **Redeploy / Update Configuration:**
  Re-run `agents-cli deploy` with updated `--update-env-vars` or flags. The CLI will apply rolling updates in-place.
