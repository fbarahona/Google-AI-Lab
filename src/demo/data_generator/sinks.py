"""
Storage sinks for synthetic log output (GCS, Pub/Sub, BigQuery, Local).
"""

import abc
import json
import logging
from datetime import UTC, datetime
from typing import Any

logger = logging.getLogger(__name__)


def to_bq_subscription_row(event: dict[str, Any]) -> dict[str, Any]:
    """Returns a copy of the event with event_timestamp as epoch microseconds.

    Pub/Sub BigQuery subscriptions map a JSON integer to a TIMESTAMP column as
    microseconds since the epoch, which avoids depending on which string formats
    the subscription accepts.
    """
    row = dict(event)
    ts = row.get("event_timestamp")
    if isinstance(ts, str):
        ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    if isinstance(ts, datetime):
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=UTC)
        row["event_timestamp"] = int(ts.timestamp() * 1_000_000)
    return row


class BaseSink(abc.ABC):
    """Abstract interface for log destinations."""

    @abc.abstractmethod
    def write_events(
        self, access_events: list[dict[str, Any]], network_events: list[dict[str, Any]]
    ) -> int:
        """Writes batches of access and network events. Returns total count written."""
        pass


class LocalSink(BaseSink):
    """Writes logs to local files (JSON/NDJSON) or stdout."""

    def __init__(self, output_dir: str | None = None, print_stdout: bool = False):
        self.output_dir = output_dir
        self.print_stdout = print_stdout

    def write_events(
        self, access_events: list[dict[str, Any]], network_events: list[dict[str, Any]]
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
                path = os.path.join(
                    self.output_dir, f"network_events_{timestamp}.jsonl"
                )
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
                "'gcloud auth application-default login'. Error: %s",
                exc,
            )
            raise
        self.bucket = self.client.bucket(bucket_name)

    def write_events(
        self, access_events: list[dict[str, Any]], network_events: list[dict[str, Any]]
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
            logger.info(
                "Uploaded %d access events to gs://%s/%s",
                len(access_events),
                self.bucket_name,
                blob_name,
            )

        if network_events:
            blob_name = f"{self.prefix}/network_events/{date_partition}/network_{ts_suffix}.jsonl"
            blob = self.bucket.blob(blob_name)
            payload = "\n".join(json.dumps(ev) for ev in network_events) + "\n"
            blob.upload_from_string(payload, content_type="application/x-ndjson")
            total += len(network_events)
            logger.info(
                "Uploaded %d network events to gs://%s/%s",
                len(network_events),
                self.bucket_name,
                blob_name,
            )

        return total


class PubSubSink(BaseSink):
    """Publishes log records to Cloud Pub/Sub topics for streaming ingestion."""

    def __init__(self, project_id: str, topic_id: str, publish_timeout: float = 30.0):
        from google.cloud import pubsub_v1

        self.publish_timeout = publish_timeout

        try:
            self.publisher = pubsub_v1.PublisherClient()
        except Exception as exc:
            logger.error(
                "Failed to initialize PubSub PublisherClient. If running locally, ensure "
                "Application Default Credentials (ADC) are set via: "
                "'gcloud auth application-default login'. Error: %s",
                exc,
            )
            raise
        self.topic_path = self.publisher.topic_path(project_id, topic_id)

    def write_events(
        self, access_events: list[dict[str, Any]], network_events: list[dict[str, Any]]
    ) -> int:
        """Publishes every event and waits for Pub/Sub to accept it.

        Raises RuntimeError if any message is rejected (for example a missing
        pubsub.publisher grant), so callers never report a silent failure as success.
        """
        futures = []
        for family, table, events in (
            ("access", "user_access_events", access_events),
            ("network", "network_events", network_events),
        ):
            for ev in events:
                # The BigQuery subscriptions (use_table_schema=true) write the JSON
                # fields straight into the table columns.
                message_data = json.dumps(to_bq_subscription_row(ev)).encode("utf-8")
                futures.append(
                    self.publisher.publish(
                        self.topic_path,
                        message_data,
                        event_family=family,
                        table=table,
                    )
                )

        failures: list[Exception] = []
        for future in futures:
            try:
                future.result(timeout=self.publish_timeout)
            except Exception as exc:
                failures.append(exc)
        if failures:
            raise RuntimeError(
                f"{len(failures)} of {len(futures)} messages were not published to "
                f"{self.topic_path}: {failures[0]}"
            ) from failures[0]
        return len(futures)


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
                "'gcloud auth application-default login'. Error: %s",
                exc,
            )
            raise
        self.access_table = f"{project_id}.{dataset_id}.user_access_events"
        self.network_table = f"{project_id}.{dataset_id}.network_events"

    def write_events(
        self, access_events: list[dict[str, Any]], network_events: list[dict[str, Any]]
    ) -> int:
        total = 0
        if access_events:
            errors = self.client.insert_rows_json(self.access_table, access_events)
            if errors:
                logger.error(
                    "BigQuery insert error (user_access_events): %s", errors[:3]
                )
            else:
                total += len(access_events)

        if network_events:
            errors = self.client.insert_rows_json(self.network_table, network_events)
            if errors:
                logger.error("BigQuery insert error (network_events): %s", errors[:3])
            else:
                total += len(network_events)

        return total
