# Cymbal Cyber Security AI — Infrastructure as Code (Terraform)

This Terraform module provisions the complete enterprise infrastructure for the Cymbal Cyber Security AI platform:

- **BigQuery Analytical Lakehouse**: Datasets (`Cymbal_Cyber`), scalar SQL UDFs (`calculate_threat_score`, `is_malicious_*`), partitioned tables (`user_access_events`, `network_events`, `alerts`, `soc_tickets`), views (`soc_tickets_current`, `incidents`), a BigLake object table over the screenshots bucket (`user_screenshots_objects`) and a protobuf data contract on the raw telemetry topic.
- **Pub/Sub Telemetry Streaming**: Event ingestion topics, BigQuery direct-write subscriptions, dead-letter queues (DLQ), and agent push subscriptions.
- **Multi-Agent Cloud Run Services**: Containerized ADK multi-agent orchestrator (`cymbal-cyber-adk-agent`), the MCP tool service it calls (`cymbal-cyber-mcp`, its own identity), and interactive SOC console (`cymbal-cyber-soc-console`).
- **Scheduled Micro-Batch Threat Detector**: Cloud Run Job (`threat-detector`) invoked on a cron schedule via Cloud Scheduler.
- **Cloud Storage Evidence Buckets**: Raw logs, staging, multimodal desktop screenshots, and human escalation queues.
- **Granular Least-Privilege IAM**: Service accounts for the ADK Agent (no evidence or ticket access), the MCP tool service (evidence reads and ticket writes; invocable only by the agent), SOC console, Continuous Query, Pub/Sub Invoker, and Threat Detector.

---

## State Management: GCS Remote Backend

State lives in a versioned Cloud Storage bucket (`backend.tf`), so it survives devcontainer rebuilds and is shared by every machine that deploys. `backend.tf` holds no project ID; the bucket is passed at init:

```bash
terraform init -backend-config="bucket=<PROJECT_ID>-tfstate"
```

`./src/demo/scripts/deploy_cloud.sh` creates the bucket (versioning, uniform access, public access prevention) and runs this init on every deploy. Terraform authenticates with Application Default Credentials (`gcloud auth application-default login`), never a static access token.

### One-time migration from local state
If `terraform.tfstate` still exists in this directory:

```bash
terraform init -migrate-state -backend-config="bucket=<PROJECT_ID>-tfstate"
mv terraform.tfstate terraform.tfstate.migrated
```

If local state was already lost and resources exist in GCP, run `./src/demo/scripts/tf_adopt_existing.sh <PROJECT_ID> [REGION]` once instead. The deploy script never imports resources.

---

## 🔐 Deployer Prerequisites

The deploying identity needs Project IAM Admin plus the service-specific admin roles; `roles/editor` is not enough because it cannot set IAM policy. The role list and the reasoning are in [SECURITY_ARCHITECTURE.md §2B](../../../docs/SECURITY_ARCHITECTURE.md#2b-bootstrap--provisioning-identity-admin--terraform-cicd-only), and the commands that grant them are in [CLOUD.md §2](../../../docs/CLOUD.md#2-environment--iam-role-setup).

---

## Deployment & Teardown

### Full Pipeline Automated Rollout
```bash
./src/demo/scripts/deploy_cloud.sh <PROJECT_ID> <REGION>
```

### Manual Terraform Workflow
```bash
terraform init -backend-config="bucket=<PROJECT_ID>-tfstate"
terraform plan -var="project_id=<PROJECT_ID>"
terraform apply -var="project_id=<PROJECT_ID>"
```

### Infrastructure Teardown
```bash
terraform destroy -var="project_id=<PROJECT_ID>"
```

> [!NOTE]
> By default, destroying this module preserves Google Cloud APIs (`disable_on_destroy = false`) and non-force-destroyed Cloud Storage buckets containing historical data.
