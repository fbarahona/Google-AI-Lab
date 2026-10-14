"""
Dataflow Streaming Pipeline: Pub/Sub to BigQuery
================================================
Consumes raw synthetic logs from Cloud Pub/Sub, validates the payload,
routes events dynamically, and writes streaming rows into BigQuery.

Pipeline Architecture:
  Pub/Sub (cymbal_cyber_raw_logs) -> Parse & Route DoFn -> BigQuery (user_access_events / network_events)
"""

import argparse
import json
import logging
import os
from datetime import UTC, datetime
from typing import Any

logger = logging.getLogger(__name__)


def parse_and_route_record(message_bytes: bytes) -> tuple[str, dict[str, Any]]:
    """
    Parses incoming Pub/Sub JSON message and determines destination table.
    Expects message structure: {"table": "user_access_events"|"network_events", "data": {...}}
    or auto-detects by schema keys.
    """
    try:
        payload = json.loads(message_bytes.decode("utf-8"))
    except Exception as e:
        logger.error("Failed to decode message: %s", e)
        return "deadletter", {"raw": str(message_bytes), "error": str(e)}

    table = payload.get("table")
    data = payload.get("data", payload)

    if not table:
        if "assigned_internal_ip" in data or "application_name" in data:
            table = "user_access_events"
        elif "destination_port" in data or "protocol" in data:
            table = "network_events"
        else:
            table = "user_access_events"

    # PubSubSink sends event_timestamp as epoch microseconds for the BigQuery
    # subscriptions; streaming inserts read a number as seconds, so send ISO-8601.
    ts = data.get("event_timestamp") if isinstance(data, dict) else None
    if isinstance(ts, int):
        data = {
            **data,
            "event_timestamp": datetime.fromtimestamp(ts / 1_000_000, UTC).isoformat(),
        }

    return table, data


def build_pipeline_runner(
    project_id: str | None = None,
    input_subscription: str | None = None,
    dataset_id: str = "Cymbal_Cyber",
    runner: str = "DirectRunner",
):
    """
    Configures and returns the Apache Beam pipeline definition.
    Compatible with DirectRunner (local development) and DataflowRunner (GCP managed).
    """
    project_id = project_id or os.getenv("GOOGLE_CLOUD_PROJECT", "local-demo")
    input_subscription = (
        input_subscription or f"projects/{project_id}/subscriptions/raw_logs_to_bq_sub"
    )
    try:
        import apache_beam as beam
        from apache_beam.options.pipeline_options import (
            GoogleCloudOptions,
            PipelineOptions,
            StandardOptions,
        )
    except ImportError:
        logger.warning(
            "apache-beam is not installed in the local environment. Returning None."
        )
        return None

    pipeline_options = PipelineOptions()
    pipeline_options.view_as(StandardOptions).streaming = True
    pipeline_options.view_as(StandardOptions).runner = runner

    google_cloud_options = pipeline_options.view_as(GoogleCloudOptions)
    google_cloud_options.project = project_id
    google_cloud_options.job_name = "pubsub-to-bigquery-stream"

    access_table_spec = f"{project_id}:{dataset_id}.user_access_events"
    network_table_spec = f"{project_id}:{dataset_id}.network_events"

    class RouteFn(beam.DoFn):
        OUTPUT_TAG_ACCESS = "access"
        OUTPUT_TAG_NETWORK = "network"

        def process(self, element):
            table, data = parse_and_route_record(element)
            if table == "user_access_events":
                yield beam.pvalue.TaggedOutput(self.OUTPUT_TAG_ACCESS, data)
            elif table == "network_events":
                yield beam.pvalue.TaggedOutput(self.OUTPUT_TAG_NETWORK, data)

    p = beam.Pipeline(options=pipeline_options)

    messages = (
        p
        | "ReadFromPubSub" >> beam.io.ReadFromPubSub(subscription=input_subscription)
        | "RouteEvents"
        >> beam.ParDo(RouteFn()).with_outputs(
            RouteFn.OUTPUT_TAG_ACCESS, RouteFn.OUTPUT_TAG_NETWORK
        )
    )

    (
        messages[RouteFn.OUTPUT_TAG_ACCESS]
        | "WriteAccessToBQ"
        >> beam.io.WriteToBigQuery(
            table=access_table_spec,
            write_disposition=beam.io.BigQueryDisposition.WRITE_APPEND,
            create_disposition=beam.io.BigQueryDisposition.CREATE_NEVER,
        )
    )

    (
        messages[RouteFn.OUTPUT_TAG_NETWORK]
        | "WriteNetworkToBQ"
        >> beam.io.WriteToBigQuery(
            table=network_table_spec,
            write_disposition=beam.io.BigQueryDisposition.WRITE_APPEND,
            create_disposition=beam.io.BigQueryDisposition.CREATE_NEVER,
        )
    )

    return p


if __name__ == "__main__":
    _default_proj = os.getenv("GOOGLE_CLOUD_PROJECT", "local-demo")
    parser = argparse.ArgumentParser(
        description="Pub/Sub to BigQuery Streaming Dataflow Job"
    )
    parser.add_argument("--project-id", default=_default_proj)
    parser.add_argument("--dataset", default="Cymbal_Cyber")
    parser.add_argument(
        "--subscription",
        default=f"projects/{_default_proj}/subscriptions/raw_logs_to_bq_sub",
    )
    parser.add_argument(
        "--runner", default="DirectRunner", choices=["DirectRunner", "DataflowRunner"]
    )
    args = parser.parse_args()

    pipeline = build_pipeline_runner(
        project_id=args.project_id,
        input_subscription=args.subscription,
        dataset_id=args.dataset,
        runner=args.runner,
    )
    if pipeline:
        result = pipeline.run()
        result.wait_until_finish()
