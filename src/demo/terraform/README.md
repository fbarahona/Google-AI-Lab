# Cymbal Cyber Security AI — Infrastructure as Code (Terraform)

This Terraform module provisions the complete enterprise infrastructure for the Cymbal Cyber Security AI platform:

- **BigQuery Analytical Lakehouse**: Datasets (`Cymbal_Cyber`), scalar SQL UDFs (`calculate_threat_score`, `is_malicious_*`), partitioned tables (`user_access_events`, `network_events`, `alerts`, `soc_tickets`), and BigLake object tables (`user_screenshots_view`).
- **Pub/Sub Telemetry Streaming**: Event ingestion topics, BigQuery direct-write subscriptions, dead-letter queues (DLQ), and agent push subscriptions.
- **Multi-Agent Cloud Run Services**: Containerized ADK multi-agent orchestrator (`cymbal-cyber-adk-agent`) and interactive SOC console (`cymbal-cyber-soc-console`).
- **Scheduled Micro-Batch Threat Detector**: Cloud Run Job (`threat-detector`) invoked on a cron schedule via Cloud Scheduler.
- **Cloud Storage Evidence Buckets**: Raw logs, staging, multimodal desktop screenshots, and human escalation queues.
- **Granular Least-Privilege IAM**: Service accounts for ADK Agent, Continuous Query, Pub/Sub Invoker, and Threat Detector.

---

## State Management: Enterprise Remote Backend vs. Brownfield Discovery

### 1. Enterprise Remote State Backend (Recommended)
To prevent "split-brain" state desynchronization across developer devcontainers, Cloud Shell, and CI/CD runners, configure a dedicated Cloud Storage backend with distributed state locking:

```bash
# 1. Create the dedicated state bucket with object versioning enabled (run once):
gcloud storage buckets create gs://<PROJECT_ID>-tfstate --project=<PROJECT_ID> --location=us-east1
gcloud storage buckets update gs://<PROJECT_ID>-tfstate --versioning

# 2. Copy the template and insert your project ID:
cp backend.tf.example backend.tf
sed -i "s/<PROJECT_ID>/your-project-id/g" backend.tf

# 3. Initialize Terraform with state migration:
terraform init -migrate-state
```

### 2. Brownfield Import Loops (Transitional Discovery)
If deploying into an existing environment with unmanaged pre-existing resources, the automated deployment script (`./src/demo/scripts/deploy_cloud.sh`) includes idempotent import loops that probe GCP APIs and auto-adopt existing resources into state prior to `terraform apply`.

---

## Deployment & Teardown

### Full Pipeline Automated Rollout
```bash
./src/demo/scripts/deploy_cloud.sh <PROJECT_ID> <REGION>
```

### Manual Terraform Workflow
```bash
terraform init
terraform plan -var="project_id=<PROJECT_ID>"
terraform apply -var="project_id=<PROJECT_ID>"
```

### Infrastructure Teardown
```bash
terraform destroy -var="project_id=<PROJECT_ID>"
```

> [!NOTE]
> By default, destroying this module preserves Google Cloud APIs (`disable_on_destroy = false`) and non-force-destroyed Cloud Storage buckets containing historical data.