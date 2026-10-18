# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Durable alert lifecycle in the BigQuery alerts table (NEW, INVESTIGATING, DONE,
RETRY_PENDING), with parameterized queries and a scan ceiling. Skipped in LOCAL_MODE.
"""

import json
import logging
import os
from typing import Any

logger = logging.getLogger("CymbalCyberADK.Webhook")


def get_alert_status_info(alert_id: str) -> dict[str, Any] | None:
    """
    Checks BigQuery `alerts` table for the alert_id status.
    Returns dict with status, updated_at timestamp, or None if not found.
    """
    if os.getenv("LOCAL_MODE", "false").lower() == "true" or not alert_id:
        return None
    try:
        from google.cloud import bigquery

        from adk_agent.tools import DATASET_ID, PROJECT_ID, get_bq_client

        bq = get_bq_client()
        query = f"""
            SELECT status, updated_at
            FROM `{PROJECT_ID}.{DATASET_ID}.alerts`
            WHERE alert_id = @alert_id
            LIMIT 1
        """
        job_config = bigquery.QueryJobConfig(
            query_parameters=[
                bigquery.ScalarQueryParameter("alert_id", "STRING", alert_id),
            ],
            maximum_bytes_billed=100 * 1024 * 1024,
        )
        rows = list(bq.query(query, job_config=job_config).result())
        if rows:
            return {"status": rows[0]["status"], "updated_at": rows[0]["updated_at"]}
        return None
    except Exception as e:
        logger.warning("Could not query alerts.status for alert_id %s: %s", alert_id, e)
        return None


def update_alert_status(
    alert_id: str,
    new_status: str,
    alert_data: dict[str, Any] | None = None,
):
    """
    Updates alerts.status to INVESTIGATING, DONE, or NEW with timestamp audit.
    If alert_data is provided, uses MERGE to ensure Continuous Query and Dataflow
    alerts are inserted into the alerts table if they do not already exist.
    """
    if os.getenv("LOCAL_MODE", "false").lower() == "true" or not alert_id:
        return
    try:
        from google.cloud import bigquery

        from adk_agent.tools import DATASET_ID, PROJECT_ID, get_bq_client

        bq = get_bq_client()

        if alert_data:
            user_id = alert_data.get("user_id") or (
                alert_id.split("|")[0] if "|" in alert_id else "unknown"
            )
            engine = alert_data.get("engine") or "cq"
            device_id = alert_data.get("device_id") or "endpoint-unknown"
            source_ip = alert_data.get("source_ip") or "0.0.0.0"
            window_start = alert_data.get("window_start") or ""
            window_end = alert_data.get("window_end") or (
                alert_id.split("|")[1] if "|" in alert_id else ""
            )
            threat_score = int(
                alert_data.get("total_2_min_threat_score")
                or alert_data.get("threat_score")
                or 0
            )
            high_priv = alert_data.get("high_privilege_request_count")
            malicious_cmd = alert_data.get("malicious_command_count")
            malicious_dns = alert_data.get("malicious_dns_count")
            payload_str = json.dumps(alert_data)

            query = f"""
                MERGE `{PROJECT_ID}.{DATASET_ID}.alerts` T
                USING (SELECT @alert_id AS alert_id) S
                ON T.alert_id = S.alert_id
                WHEN MATCHED THEN
                  UPDATE SET status = @new_status, updated_at = CURRENT_TIMESTAMP()
                WHEN NOT MATCHED THEN
                  INSERT (
                    alert_id, engine, user_id, device_id, source_ip,
                    window_start, window_end, total_2_min_threat_score,
                    high_privilege_request_count, malicious_command_count, malicious_dns_count,
                    status, detected_at, updated_at, payload
                  )
                  VALUES (
                    @alert_id, @engine, @user_id, @device_id, @source_ip,
                    COALESCE(SAFE.PARSE_TIMESTAMP('%Y-%m-%dT%H:%M:%E*SZ', @window_start), TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 2 MINUTE)),
                    COALESCE(SAFE.PARSE_TIMESTAMP('%Y-%m-%dT%H:%M:%E*SZ', @window_end), CURRENT_TIMESTAMP()),
                    @threat_score,
                    @high_priv_count, @malicious_cmd_count, @malicious_dns_count,
                    @new_status, CURRENT_TIMESTAMP(), CURRENT_TIMESTAMP(), PARSE_JSON(@payload)
                  )
            """
            job_config = bigquery.QueryJobConfig(
                query_parameters=[
                    bigquery.ScalarQueryParameter("new_status", "STRING", new_status),
                    bigquery.ScalarQueryParameter("alert_id", "STRING", alert_id),
                    bigquery.ScalarQueryParameter("engine", "STRING", engine),
                    bigquery.ScalarQueryParameter("user_id", "STRING", user_id),
                    bigquery.ScalarQueryParameter("device_id", "STRING", device_id),
                    bigquery.ScalarQueryParameter("source_ip", "STRING", source_ip),
                    bigquery.ScalarQueryParameter(
                        "window_start", "STRING", window_start
                    ),
                    bigquery.ScalarQueryParameter("window_end", "STRING", window_end),
                    bigquery.ScalarQueryParameter(
                        "threat_score", "INT64", threat_score
                    ),
                    bigquery.ScalarQueryParameter(
                        "high_priv_count", "INT64", high_priv
                    ),
                    bigquery.ScalarQueryParameter(
                        "malicious_cmd_count", "INT64", malicious_cmd
                    ),
                    bigquery.ScalarQueryParameter(
                        "malicious_dns_count", "INT64", malicious_dns
                    ),
                    bigquery.ScalarQueryParameter("payload", "STRING", payload_str),
                ],
                maximum_bytes_billed=100 * 1024 * 1024,
            )
        else:
            query = f"""
                UPDATE `{PROJECT_ID}.{DATASET_ID}.alerts`
                SET status = @new_status, updated_at = CURRENT_TIMESTAMP()
                WHERE alert_id = @alert_id
            """
            job_config = bigquery.QueryJobConfig(
                query_parameters=[
                    bigquery.ScalarQueryParameter("new_status", "STRING", new_status),
                    bigquery.ScalarQueryParameter("alert_id", "STRING", alert_id),
                ],
                maximum_bytes_billed=100 * 1024 * 1024,
            )
        bq.query(query, job_config=job_config).result()
        logger.info(
            "Updated alert_id '%s' status to '%s' in BigQuery.", alert_id, new_status
        )
    except Exception as e:
        logger.warning(
            "Could not update alerts.status for alert_id %s: %s", alert_id, e
        )
