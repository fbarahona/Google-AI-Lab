"""
Storage sinks for synthetic log output (GCS, Pub/Sub, BigQuery, Local).
"""
import abc
import json
import logging
from datetime import UTC, datetime
from typing import Any

logger = logging.getLogger(__name__)


class BaseSink(abc.ABC):
    """Abstract interface for log destinations."""

    @abc.abstractmethod
    def write_events(
        self,
        access_events: list[dict[str, Any]],
        network_events: list[dict[str, Any]]
    ) -> int:
        """Writes batches of access and network events. Returns total count written."""
        pass


class LocalSink(BaseSink):
    """Writes logs to local files (JSON/NDJSON) or stdout."""

    def __init__(self, output_dir: str | None = None, print_stdout: bool = False):
        self.output_dir = output_dir
        self.print_stdout = print_stdout

    def write_events(
        self,
        access_events: list[dict[str, Any]],
        network_events: list[dict[str, Any]]
    ) -> int:
        total = len(access_events) + len(network_events)
        if self.print_stdout:
            for ev in access_events:
                print(f"[ACCESS] {json.dumps(ev)}")
            for ev in network_events:
                print(f"[NETWORK] {json.dumps(ev)}")

        if self.output_dir:
            import os
            os.makedirs(self.output_dir, exist_ok=True)
            timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S_%f")
            if access_events:
                path = os.path.join(self.output_dir, f"access_events_{timestamp}.jsonl")
                with open(path, "w", encoding="utf-8") as f:
                    for ev in access_events:
                        f.write(json.dumps(ev) + "\n")
            if network_events:
                path = os.path.join(self.output_dir, f"network_events_{timestamp}.jsonl")
                with open(path, "w", encoding="utf-8") as f:
                    for ev in network_events:
                        f.write(json.dumps(ev) + "\n")

        return total


class GoogleCloudStorageSink(BaseSink):
    """Writes batches of logs to GCS as NDJSON objects."""

    def __init__(self, bucket_name: str, prefix: str = "raw_logs"):
        from google.cloud import storage
        self.bucket_name = bucket_name
        self.prefix = prefix
        try:
            self.client = storage.Client()
        except Exception as exc:
            logger.error(
                "Failed to initialize Storage Client. If running locally, ensure "
                "Application Default Credentials (ADC) are set via: "
                "'gcloud auth application-default login'. Error: %s", exc
            )
            raise
        self.bucket = self.client.bucket(bucket_name)

    def write_events(
        self,
        access_events: list[dict[str, Any]],
        network_events: list[dict[str, Any]]
    ) -> int:
        now = datetime.now(UTC)
        date_partition = now.strftime("%Y/%m/%d")
        ts_suffix = now.strftime("%H%M%S_%f")
        total = 0

        if access_events:
            blob_name = f"{self.prefix}/user_access_events/{date_partition}/access_{ts_suffix}.jsonl"
            blob = self.bucket.blob(blob_name)
            payload = "\n".join(json.dumps(ev) for ev in access_events) + "\n"
            blob.upload_from_string(payload, content_type="application/x-ndjson")
            total += len(access_events)
            logger.info("Uploaded %d access events to gs://%s/%s", len(access_events), self.bucket_name, blob_name)

        if network_events:
            blob_name = f"{self.prefix}/network_events/{date_partition}/network_{ts_suffix}.jsonl"
            blob = self.bucket.blob(blob_name)
            payload = "\n".join(json.dumps(ev) for ev in network_events) + "\n"
            blob.upload_from_string(payload, content_type="application/x-ndjson")
            total += len(network_events)
            logger.info("Uploaded %d network events to gs://%s/%s", len(network_events), self.bucket_name, blob_name)

        return total


class PubSubSink(BaseSink):
    """Publishes log records to Cloud Pub/Sub topics for streaming ingestion."""

    def __init__(self, project_id: str, topic_id: str):
        from google.cloud import pubsub_v1
        try:
            self.publisher = pubsub_v1.PublisherClient()
        except Exception as exc:
            logger.error(
                "Failed to initialize PubSub PublisherClient. If running locally, ensure "
                "Application Default Credentials (ADC) are set via: "
                "'gcloud auth application-default login'. Error: %s", exc
            )
            raise
        self.topic_path = self.publisher.topic_path(project_id, topic_id)

    def write_events(
        self,
        access_events: list[dict[str, Any]],
        network_events: list[dict[str, Any]]
    ) -> int:
        total = 0
        for ev in access_events:
            # For BigQuery subscription with use_table_schema=true, publish the event JSON directly
            message_data = json.dumps(ev).encode("utf-8")
            self.publisher.publish(
                self.topic_path,
                message_data,
                event_family="access",
                table="user_access_events"
            )
            total += 1
        for ev in network_events:
            message_data = json.dumps(ev).encode("utf-8")
            self.publisher.publish(
                self.topic_path,
                message_data,
                event_family="network",
                table="network_events"
            )
            total += 1
        return total


class BigQuerySink(BaseSink):
    """Streams rows directly into BigQuery tables."""

    def __init__(self, project_id: str, dataset_id: str = "Cymbal_Cyber"):
        from google.cloud import bigquery
        self.project_id = project_id
        self.dataset_id = dataset_id
        creds = None
        try:
            from ..soc_ticketing.ticketing_service import get_gcp_credentials
            creds = get_gcp_credentials()
        except Exception:
            try:
                from src.demo.soc_ticketing.ticketing_service import get_gcp_credentials
                creds = get_gcp_credentials()
            except Exception:
                pass

        try:
            if creds:
                self.client = bigquery.Client(project=project_id, credentials=creds)
            else:
                self.client = bigquery.Client(project=project_id)
        except Exception as exc:
            logger.error(
                "Failed to initialize BigQuery Client. If running locally, ensure "
                "Application Default Credentials (ADC) are set via: "
                "'gcloud auth application-default login'. Error: %s", exc
            )
            raise
        self.access_table = f"{project_id}.{dataset_id}.user_access_events"
        self.network_table = f"{project_id}.{dataset_id}.network_events"

    def write_events(
        self,
        access_events: list[dict[str, Any]],
        network_events: list[dict[str, Any]]
    ) -> int:
        total = 0
        if access_events:
            errors = self.client.insert_rows_json(self.access_table, access_events)
            if errors:
                logger.error("BigQuery insert error (user_access_events): %s", errors[:3])
            else:
                total += len(access_events)

        if network_events:
            errors = self.client.insert_rows_json(self.network_table, network_events)
            if errors:
                logger.error("BigQuery insert error (network_events): %s", errors[:3])
            else:
                total += len(network_events)

        return total

