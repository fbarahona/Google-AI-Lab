"""
Scheduled Micro-Batch Threat Detector Job
=========================================
Runs every 2 minutes (via Cloud Scheduler -> Cloud Run Job):
1. Buckets events into 2-minute closed windows with TIMESTAMP_BUCKET.
2. Evaluates windows closed > 60s ago (late-data allowance), looking back 15 minutes.
3. Idempotently MERGEs scored windows into the `alerts` table on `alert_id`.
4. Publishes ONLY rows inserted by this run to the Pub/Sub topic `cymbal_cyber_alerts`
   matching the unified alert contract.
5. Inspects `alerts_dead_letter` for alerts that failed delivery 5 times:
   marks them `DEAD_LETTERED` in `alerts` and auto-escalates them to SOC ticketing.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import time
from datetime import UTC, datetime, timedelta
from typing import Any

from google.cloud import bigquery, pubsub_v1

logger = logging.getLogger("ThreatDetectorJob")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

PROJECT_ID = os.getenv("GOOGLE_CLOUD_PROJECT") or os.getenv("PROJECT_ID", "local-demo")
DATASET_ID = os.getenv("BIGQUERY_DATASET", "Cymbal_Cyber")
ALERTS_TOPIC = os.getenv("ALERTS_TOPIC", "cymbal_cyber_alerts")
DEFAULT_MAX_BYTES_BILLED = int(os.getenv("BQ_MAX_BYTES_BILLED", "524288000"))  # 500 MB scan ceiling


def format_utc_timestamp(dt: Any) -> str:
    """Ensures a datetime object or timestamp string is formatted as ISO-8601 UTC with trailing 'Z'."""
    if isinstance(dt, datetime):
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    return str(dt)


class ThreatDetector:
    def __init__(
        self,
        project_id: str = PROJECT_ID,
        dataset_id: str = DATASET_ID,
        topic_id: str = ALERTS_TOPIC,
        max_bytes_billed: int = DEFAULT_MAX_BYTES_BILLED,
        max_merge_attempts: int = 2,
        merge_retry_delay: float = 3.0,
    ):
        self.project_id = project_id
        self.dataset_id = dataset_id
        self.topic_id = topic_id
        self.max_bytes_billed = max_bytes_billed
        self.max_merge_attempts = max_merge_attempts
        self.merge_retry_delay = merge_retry_delay
        creds = None
        try:
            from src.demo.soc_ticketing.ticketing_service import get_gcp_credentials
            creds = get_gcp_credentials()
        except Exception:
            pass

        self.bq_client = bigquery.Client(project=project_id, credentials=creds) if creds else bigquery.Client(project=project_id)
        self.publisher = pubsub_v1.PublisherClient(credentials=creds) if creds else pubsub_v1.PublisherClient()
        self.topic_path = self.publisher.topic_path(project_id, topic_id)

    def run_detection_cycle(self, lookback_minutes: int = 15, min_score: int = 100) -> int:
        """
        Executes an idempotent micro-batch detection pass:
        1. MERGEs scored closed windows into `alerts`.
        2. Publishes newly created alerts to Pub/Sub.
        3. Processes DLQ failures and marks DEAD_LETTERED.
        """
        logger.info("Starting detection cycle for %s.%s (lookback: %d min, min_score: %d)...",
                    self.project_id, self.dataset_id, lookback_minutes, min_score)

        new_alerts = self._merge_and_fetch_new_alerts(lookback_minutes, min_score)
        published_count = self._publish_alerts(new_alerts)

        dlq_count = self._handle_dead_lettered_alerts()
        logger.info("Detection cycle complete: %d new alerts published, %d DLQ alerts handled.",
                    published_count, dlq_count)
        return published_count

    def _merge_and_fetch_new_alerts(
        self,
        lookback_minutes: int = 15,
        min_score: int = 100,
        cutoff_time: datetime | None = None,
    ) -> list[dict[str, Any]]:
        """
        Uses BigQuery MERGE to bucket 2-minute windows, scoring only windows that closed
        more than 60 seconds ago. Returns only rows inserted during this run.
        Uses parameterized @start_time and @min_score to eliminate SQL injection and
        guarantee UTC ISO-8601 timestamp resolution in BigQuery.
        """
        if cutoff_time is None:
            now_utc = datetime.now(UTC)
            cutoff_time = now_utc - timedelta(minutes=lookback_minutes)
        elif cutoff_time.tzinfo is None:
            cutoff_time = cutoff_time.replace(tzinfo=UTC)

        merge_query = f"""
        DECLARE current_run_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP();

        MERGE `{self.project_id}.{self.dataset_id}.alerts` T
        USING (
          WITH ActiveSessions AS (
            SELECT user_id, device_id, source_ip, assigned_internal_ip, user_agent
            FROM (
              SELECT
                user_id, device_id, source_ip, assigned_internal_ip, user_agent,
                ROW_NUMBER() OVER (PARTITION BY assigned_internal_ip ORDER BY event_timestamp DESC) AS rn
              FROM `{self.project_id}.{self.dataset_id}.user_access_events`
              WHERE DATE(event_timestamp) >= DATE_SUB(CURRENT_DATE(), INTERVAL 1 DAY)
                AND event_timestamp >= @start_time
                AND event_type = 'login_success'
                AND assigned_internal_ip IS NOT NULL
            )
            WHERE rn = 1
          ),
          ActiveNetworkEvents AS (
            SELECT
              source_ip,
              event_timestamp,
              event_type,
              permission_level_requested,
              file_type,
              command_line,
              network_domain
            FROM `{self.project_id}.{self.dataset_id}.network_events`
            WHERE DATE(event_timestamp) >= DATE_SUB(CURRENT_DATE(), INTERVAL 1 DAY)
              AND event_timestamp >= @start_time
              AND event_timestamp < TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 60 SECOND)
          ),
          BucketedEvents AS (
            SELECT
              access.user_id,
              access.device_id,
              access.source_ip,
              TIMESTAMP_BUCKET(network.event_timestamp, INTERVAL 2 MINUTE) AS window_start,
              TIMESTAMP_ADD(TIMESTAMP_BUCKET(network.event_timestamp, INTERVAL 2 MINUTE), INTERVAL 2 MINUTE) AS window_end,
              SUM(
                `{self.project_id}.{self.dataset_id}.calculate_threat_score`(
                  network.event_type,
                  network.permission_level_requested,
                  network.file_type,
                  network.command_line,
                  network.network_domain,
                  access.user_agent
                )
              ) AS total_2_min_threat_score,
              COUNTIF(network.permission_level_requested IN ('root', 'admin')) AS high_privilege_request_count,
              COUNTIF(`{self.project_id}.{self.dataset_id}.is_malicious_command`(network.command_line)) AS malicious_command_count,
              COUNTIF(`{self.project_id}.{self.dataset_id}.is_malicious_domain`(network.network_domain)) AS malicious_dns_count
            FROM ActiveSessions AS access
            INNER JOIN ActiveNetworkEvents AS network
              ON access.assigned_internal_ip = network.source_ip
            GROUP BY access.user_id, access.device_id, access.source_ip, window_start, window_end
            -- Only evaluate windows that closed more than 60s ago (late-data allowance)
            HAVING window_end <= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 60 SECOND)
               AND total_2_min_threat_score >= @min_score
          )
          SELECT
            CONCAT(user_id, '|', FORMAT_TIMESTAMP('%Y-%m-%dT%H:%M:%SZ', window_end)) AS alert_id,
            'scheduled' AS engine,
            user_id,
            device_id,
            source_ip,
            window_start,
            window_end,
            total_2_min_threat_score,
            high_privilege_request_count,
            malicious_command_count,
            malicious_dns_count,
            'NEW' AS status,
            current_run_time AS detected_at,
            current_run_time AS updated_at,
            TO_JSON(STRUCT(
              CONCAT(user_id, '|', FORMAT_TIMESTAMP('%Y-%m-%dT%H:%M:%SZ', window_end)) AS alert_id,
              1 AS schema_version,
              'scheduled' AS engine,
              user_id,
              device_id,
              source_ip,
              FORMAT_TIMESTAMP('%Y-%m-%dT%H:%M:%SZ', window_start) AS window_start,
              FORMAT_TIMESTAMP('%Y-%m-%dT%H:%M:%SZ', window_end) AS window_end,
              total_2_min_threat_score,
              high_privilege_request_count,
              malicious_command_count,
              malicious_dns_count,
              FORMAT_TIMESTAMP('%Y-%m-%dT%H:%M:%SZ', current_run_time) AS detected_at
            )) AS payload
          FROM BucketedEvents
        ) S
        ON T.alert_id = S.alert_id
        WHEN NOT MATCHED THEN
          INSERT (
            alert_id, engine, user_id, device_id, source_ip,
            window_start, window_end, total_2_min_threat_score,
            high_privilege_request_count, malicious_command_count, malicious_dns_count,
            status, detected_at, updated_at, payload
          )
          VALUES (
            S.alert_id, S.engine, S.user_id, S.device_id, S.source_ip,
            S.window_start, S.window_end, S.total_2_min_threat_score,
            S.high_privilege_request_count, S.malicious_command_count, S.malicious_dns_count,
            S.status, S.detected_at, S.updated_at, S.payload
          );
        """
        job_config = bigquery.QueryJobConfig(
            query_parameters=[
                bigquery.ScalarQueryParameter("start_time", "TIMESTAMP", cutoff_time),
                bigquery.ScalarQueryParameter("min_score", "INT64", min_score),
            ],
            maximum_bytes_billed=self.max_bytes_billed,
        )
        merge_success = False

        for attempt in range(1, self.max_merge_attempts + 1):
            try:
                logger.info(
                    "Executing MERGE query against alerts table (attempt %d/%d)...",
                    attempt,
                    self.max_merge_attempts,
                )
                merge_job = self.bq_client.query(merge_query, job_config=job_config)
                merge_job.result()
                merge_success = True
                break
            except Exception as e:
                err_msg = str(e).lower()
                is_conflict = (
                    "concurrent update" in err_msg
                    or "conflict with another transaction" in err_msg
                    or "concurrent" in err_msg
                )
                if attempt < self.max_merge_attempts:
                    delay = self.merge_retry_delay * (2 ** (attempt - 1))
                    if is_conflict:
                        logger.warning(
                            "Concurrent update conflict detected on MERGE query (attempt %d/%d): %s. Retrying in %.1fs...",
                            attempt,
                            self.max_merge_attempts,
                            e,
                            delay,
                        )
                    else:
                        logger.warning(
                            "Transient error executing MERGE query (attempt %d/%d): %s. Retrying in %.1fs...",
                            attempt,
                            self.max_merge_attempts,
                            e,
                            delay,
                        )
                    time.sleep(delay)
                else:
                    logger.error(
                        "Error executing MERGE query after %d attempts: %s",
                        self.max_merge_attempts,
                        e,
                    )
                    return []

        if not merge_success:
            return []

        # Fetch only alerts newly created by this run (status = 'NEW')
        fetch_query = f"""
        SELECT
          alert_id,
          engine,
          user_id,
          device_id,
          source_ip,
          FORMAT_TIMESTAMP('%Y-%m-%dT%H:%M:%SZ', window_start) AS window_start,
          FORMAT_TIMESTAMP('%Y-%m-%dT%H:%M:%SZ', window_end) AS window_end,
          total_2_min_threat_score,
          high_privilege_request_count,
          malicious_command_count,
          malicious_dns_count,
          FORMAT_TIMESTAMP('%Y-%m-%dT%H:%M:%SZ', detected_at) AS detected_at,
          TO_JSON_STRING(payload) AS payload_str
        FROM `{self.project_id}.{self.dataset_id}.alerts`
        WHERE status = 'NEW'
          AND DATE(window_end) >= DATE_SUB(CURRENT_DATE(), INTERVAL 7 DAY)
        ORDER BY window_start ASC;
        """
        fetch_config = bigquery.QueryJobConfig(maximum_bytes_billed=self.max_bytes_billed)
        try:
            query_job = self.bq_client.query(fetch_query, job_config=fetch_config)
            return [dict(row.items()) for row in query_job.result()]
        except Exception as e:
            logger.error("Error fetching newly created alerts: %s", e)
            return []

    def _update_alert_status(self, alert_id: str, new_status: str, expected_current_status: str | None = None):
        """Transitions alert status in BigQuery using parameterized query."""
        where_clause = "WHERE alert_id = @alert_id"
        query_params = [
            bigquery.ScalarQueryParameter("new_status", "STRING", new_status),
            bigquery.ScalarQueryParameter("alert_id", "STRING", alert_id),
        ]
        if expected_current_status:
            where_clause += " AND status = @expected_current_status"
            query_params.append(
                bigquery.ScalarQueryParameter("expected_current_status", "STRING", expected_current_status)
            )

        update_query = f"""
        UPDATE `{self.project_id}.{self.dataset_id}.alerts`
        SET status = @new_status, updated_at = CURRENT_TIMESTAMP()
        {where_clause};
        """
        job_config = bigquery.QueryJobConfig(
            query_parameters=query_params,
            maximum_bytes_billed=self.max_bytes_billed,
        )
        try:
            self.bq_client.query(update_query, job_config=job_config).result()
            logger.info("Updated alert '%s' status to %s.", alert_id, new_status)
        except Exception as e:
            logger.error("Failed to update status for alert %s to %s: %s", alert_id, new_status, e)

    def _publish_alerts(self, alerts: list[dict[str, Any]]) -> int:
        """
        Publishes alerts to cymbal_cyber_alerts matching the unified Alert Contract,
        and marks them as PUBLISHED in BigQuery to prevent duplication.
        """
        count = 0
        for alert in alerts:
            alert_id = alert["alert_id"]
            payload_str = alert.get("payload_str")
            if not payload_str:
                payload_dict = {
                    "alert_id": alert_id,
                    "schema_version": 1,
                    "engine": alert.get("engine", "scheduled"),
                    "user_id": alert["user_id"],
                    "device_id": alert["device_id"],
                    "source_ip": alert["source_ip"],
                    "window_start": format_utc_timestamp(alert["window_start"]),
                    "window_end": format_utc_timestamp(alert["window_end"]),
                    "total_2_min_threat_score": alert["total_2_min_threat_score"],
                    "high_privilege_request_count": alert.get("high_privilege_request_count", 0),
                    "malicious_command_count": alert.get("malicious_command_count", 0),
                    "malicious_dns_count": alert.get("malicious_dns_count", 0),
                    "detected_at": format_utc_timestamp(alert["detected_at"]),
                }
                payload_str = json.dumps(payload_dict)

            message_data = payload_str.encode("utf-8")
            future = self.publisher.publish(
                self.topic_path,
                message_data,
                alert_id=alert_id,
                engine=alert.get("engine", "scheduled"),
                schema_version="1"
            )
            future.result(timeout=10)
            logger.info("Published alert '%s' to %s", alert_id, self.topic_path)
            # Mark as PUBLISHED only if status is still NEW (prevents overwriting INVESTIGATING if webhook processed quickly)
            self._update_alert_status(alert_id, "PUBLISHED", expected_current_status="NEW")
            count += 1
        return count

    def _handle_dead_lettered_alerts(self) -> int:
        """
        Inspects alerts_dead_letter:
        1. Identifies alert_ids that landed on DLQ after 5 delivery failures.
        2. Updates alerts table status to DEAD_LETTERED.
        3. Dispatches auto-escalation ticket to SOC ticketing system.
        """
        dlq_query = f"""
        SELECT DISTINCT
          JSON_VALUE(dlq.attributes, '$.alert_id') AS alert_id,
          dlq.data AS payload,
          dlq.publish_time AS dead_lettered_at,
          a.user_id,
          a.device_id,
          a.source_ip,
          a.total_2_min_threat_score
        FROM `{self.project_id}.{self.dataset_id}.alerts_dead_letter` dlq
        INNER JOIN `{self.project_id}.{self.dataset_id}.alerts` a
          ON JSON_VALUE(dlq.attributes, '$.alert_id') = a.alert_id
        WHERE a.status != 'DEAD_LETTERED'
        LIMIT 20;
        """
        dlq_job_config = bigquery.QueryJobConfig(maximum_bytes_billed=self.max_bytes_billed)
        try:
            query_job = self.bq_client.query(dlq_query, job_config=dlq_job_config)
            dead_letters = [dict(row.items()) for row in query_job.result()]
        except Exception as e:
            logger.warning("DLQ inspection query failed (table may be empty or uncreated yet): %s", e)
            return 0

        handled = 0
        for dl in dead_letters:
            alert_id = dl["alert_id"]
            if not alert_id:
                continue

            target_user = dl.get("user_id") or (alert_id.split("|")[0] if "|" in alert_id else "unknown_user")
            target_device = dl.get("device_id") or "unknown_device"
            target_ip = dl.get("source_ip") or "0.0.0.0"
            threat_score = int(dl.get("total_2_min_threat_score") or 2000)

            # 1. Upsert auto-escalation ticket into soc_tickets FIRST via MERGE (idempotent)
            ticket_id = f"DLQ-AUTO-ESCALATE-{alert_id.replace('|', '-')}"
            report_text = f"### DLQ Auto-Escalation Report\n\nAlert `{alert_id}` exhausted all Pub/Sub delivery attempts. The automated webhook failed to respond. Immediate human intervention required."

            merge_ticket_sql = f"""
            MERGE `{self.project_id}.{self.dataset_id}.soc_tickets` T
            USING (SELECT @ticket_id AS ticket_id) S
            ON T.ticket_id = S.ticket_id
            WHEN NOT MATCHED THEN
              INSERT (
                ticket_id, created_at, user_id, device_id, source_ip,
                threat_score, severity, status, agent_decision, agent_reason,
                mitre_tactics, indicators_of_compromise, screenshot_url,
                structured_report, human_decision, human_comment, adjudicated_at
              )
              VALUES (
                @ticket_id,
                FORMAT_TIMESTAMP('%Y-%m-%dT%H:%M:%SZ', CURRENT_TIMESTAMP()),
                @user_id,
                @device_id,
                @source_ip,
                @threat_score,
                'CRITICAL',
                'ESCALATED',
                'DEAD_LETTER_AUTO_ESCALATION',
                'Alert failed max delivery attempts (5) to the ADK agent webhook and landed on DLQ. Auto-escalated for immediate human triage.',
                @mitre_tactics,
                @iocs,
                NULL,
                @report,
                NULL, NULL, NULL
              );
            """
            insert_cfg = bigquery.QueryJobConfig(
                query_parameters=[
                    bigquery.ScalarQueryParameter("ticket_id", "STRING", ticket_id),
                    bigquery.ScalarQueryParameter("user_id", "STRING", target_user),
                    bigquery.ScalarQueryParameter("device_id", "STRING", target_device),
                    bigquery.ScalarQueryParameter("source_ip", "STRING", target_ip),
                    bigquery.ScalarQueryParameter("threat_score", "INT64", threat_score),
                    bigquery.ArrayQueryParameter("mitre_tactics", "STRING", ["Execution", "Defense Evasion"]),
                    bigquery.ArrayQueryParameter("iocs", "STRING", ["DLQ Failure", alert_id]),
                    bigquery.ScalarQueryParameter("report", "STRING", report_text),
                ],
                maximum_bytes_billed=self.max_bytes_billed,
            )
            try:
                self.bq_client.query(merge_ticket_sql, job_config=insert_cfg).result()
                logger.warning("Auto-escalated DLQ alert '%s' to SOC tickets as '%s'", alert_id, ticket_id)
            except Exception as e:
                logger.error("Failed to insert auto-escalation ticket for %s: %s; will retry next cycle", alert_id, e)
                continue

            # 2. Update alerts table status to DEAD_LETTERED only after ticket insert succeeded
            update_query = f"""
            UPDATE `{self.project_id}.{self.dataset_id}.alerts`
            SET status = 'DEAD_LETTERED', updated_at = CURRENT_TIMESTAMP()
            WHERE alert_id = @alert_id;
            """
            update_cfg = bigquery.QueryJobConfig(
                query_parameters=[bigquery.ScalarQueryParameter("alert_id", "STRING", alert_id)],
                maximum_bytes_billed=self.max_bytes_billed,
            )
            try:
                self.bq_client.query(update_query, job_config=update_cfg).result()
                handled += 1
            except Exception as e:
                logger.error("Failed to update status for DEAD_LETTERED alert %s: %s", alert_id, e)

        # Log count of unmatched orphaned dead-letter records (e.g. malformed payloads)
        self._log_unmatched_dead_letters()

        return handled

    def _log_unmatched_dead_letters(self) -> int:
        """
        Queries and logs the count of orphaned dead-letter records that do not match
        any alert in the `alerts` table (e.g., malformed payloads or invalid contracts
        rejected with HTTP 400 that exhausted Pub/Sub retries).
        Restricts scan to the last 24 hours to prevent indefinite warning loops on older failures
        and enable BigQuery DAY partition pruning on publish_time.
        """
        unmatched_query = f"""
        SELECT COUNT(1) AS unmatched_count
        FROM `{self.project_id}.{self.dataset_id}.alerts_dead_letter` dlq
        LEFT JOIN `{self.project_id}.{self.dataset_id}.alerts` a
          ON JSON_VALUE(dlq.attributes, '$.alert_id') = a.alert_id
        WHERE a.alert_id IS NULL
          AND DATE(dlq.publish_time) >= DATE_SUB(CURRENT_DATE(), INTERVAL 1 DAY)
          AND dlq.publish_time >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 1 DAY);
        """
        job_config = bigquery.QueryJobConfig(maximum_bytes_billed=self.max_bytes_billed)
        try:
            query_job = self.bq_client.query(unmatched_query, job_config=job_config)
            rows = list(query_job.result())
            unmatched_count = rows[0]["unmatched_count"] if rows else 0
            if unmatched_count > 0:
                logger.warning(
                    "Detected %d unmatched orphaned message(s) in %s.alerts_dead_letter (last 24h) with no matching alert in alerts table.",
                    unmatched_count, self.dataset_id,
                )
            return int(unmatched_count)
        except Exception as e:
            logger.warning("Unmatched dead-letter query failed: %s", e)
            return 0


def main():
    parser = argparse.ArgumentParser(description="Scheduled Micro-Batch Threat Detector")
    parser.add_argument("--lookback", type=int, default=15, help="Lookback window in minutes (default: 15)")
    parser.add_argument("--min-score", type=int, default=100, help="Minimum threat score threshold (default: 100)")
    args = parser.parse_args()

    detector = ThreatDetector()
    detector.run_detection_cycle(lookback_minutes=args.lookback, min_score=args.min_score)


if __name__ == "__main__":
    main()

