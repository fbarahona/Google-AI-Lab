# ==============================================================================
# REMOTE STATE BACKEND (Google Cloud Storage)
# ==============================================================================
# State lives in a versioned GCS bucket so it survives devcontainer rebuilds and is
# shared by every machine that deploys. The bucket is supplied at init time so no
# project ID is committed:
#
#   terraform init -backend-config="bucket=<PROJECT_ID>-tfstate"
#
# scripts/deploy_cloud.sh creates the bucket (versioned, uniform access, public access
# prevention) and runs this init on every deploy. GCS provides state locking.

terraform {
  backend "gcs" {
    prefix = "cymbal-cyber/state"
  }
}
