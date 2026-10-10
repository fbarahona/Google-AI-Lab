"""
Cloud Storage to BigQuery Batch / Micro-Batch Ingestion Loader
==============================================================
Loads NDJSON log objects stored in Cloud Storage buckets directly into
BigQuery tables (user_access_events and network_events) using BigQuery Load Jobs.
"""

import os
import logging
import argparse
from typing import Optional
from google.cloud import bigquery

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s]: %(message)s")
logger = logging.getLogger("GcsToBigQueryLoader")


class GcsToBigQueryLoader:
    def __init__(self, project_id: Optional[str] = None, dataset_id: str = "Cymbal_Cyber"):
        self.project_id = project_id or os.getenv("GOOGLE_CLOUD_PROJECT", "local-demo")
        self.dataset_id = dataset_id
        self.client = bigquery.Client(project=project_id)

    def load_table_from_gcs(
        self,
        gcs_uri_pattern: str,
        table_name: str,
        source_format: bigquery.SourceFormat = bigquery.SourceFormat.NEWLINE_DELIMITED_JSON
    ) -> bool:
        """Executes a BigQuery load job from GCS."""
        table_ref = f"{self.project_id}.{self.dataset_id}.{table_name}"
        logger.info("Loading %s into %s...", gcs_uri_pattern, table_ref)

        job_config = bigquery.LoadJobConfig(
            source_format=source_format,
            write_disposition=bigquery.WriteDisposition.WRITE_APPEND,
            autodetect=False,
            ignore_unknown_values=True
        )

        try:
            load_job = self.client.load_table_from_uri(
                gcs_uri_pattern,
                table_ref,
                job_config=job_config
            )
            load_job.result()  # Wait for job to complete
            logger.info("Load job complete for table %s. Output rows: %s", table_name, load_job.output_rows)
            return True
        except Exception as e:
            logger.error("Failed to load %s into %s: %s", gcs_uri_pattern, table_ref, e)
            return False

    def load_all_pending_logs(self, bucket_name: str) -> None:
        """Loads both user_access_events and network_events from bucket."""
        access_uri = f"gs://{bucket_name}/raw_logs/user_access_events/*/*.jsonl"
        network_uri = f"gs://{bucket_name}/raw_logs/network_events/*/*.jsonl"

        self.load_table_from_gcs(access_uri, "user_access_events")
        self.load_table_from_gcs(network_uri, "network_events")


if __name__ == "__main__":
    _default_proj = os.getenv("GOOGLE_CLOUD_PROJECT", "local-demo")
    parser = argparse.ArgumentParser(description="Load raw logs from GCS into BigQuery tables.")
    parser.add_argument("--project-id", default=_default_proj)
    parser.add_argument("--dataset", default="Cymbal_Cyber")
    parser.add_argument("--bucket", default=os.getenv("RAW_LOGS_BUCKET", f"cymbal-cyber-raw-logs_{_default_proj}"))
    args = parser.parse_args()

    loader = GcsToBigQueryLoader(project_id=args.project_id, dataset_id=args.dataset)
    loader.load_all_pending_logs(bucket_name=args.bucket)

