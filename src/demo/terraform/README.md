# Demo API Terraform

This module enables the APIs required by the demo:

- BigQuery Unified API
- Vertex AI API
- Pub/Sub API
- IAM Service Account Credentials API
- Cloud Resource Manager API

## Usage

1. Copy `terraform.tfvars.example` to `terraform.tfvars` and set `project_id`.
2. Authenticate Terraform with Google Cloud Application Default Credentials.
3. Initialize and review the plan:

```powershell
terraform init
terraform plan
```

4. Apply the plan when it is ready:

```powershell
terraform apply
```

By default, destroying this module does not disable the APIs. Set
`disable_on_destroy = true` only when that behavior is intentional.