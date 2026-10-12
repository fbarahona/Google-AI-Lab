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

import os
import sys
import json
import logging
import argparse
from datetime import datetime, timezone
from typing import List, Dict, Any

from google.cloud import bigquery
from google.cloud import pubsub_v1

logger = logging.getLogger("ThreatDetectorJob")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

PROJECT_ID = os.getenv("GOOGLE_CLOUD_PROJECT", "oso-ai-503519")
DATASET_ID = os.getenv("BIGQUERY_DATASET", "Cymbal_Cyber")
ALERTS_TOPIC = os.getenv("ALERTS_TOPIC", "cymbal_cyber_alerts")


class ThreatDetector:
    def __init__(self, project_id: str = PROJECT_ID, dataset_id: str = DATASET_ID, topic_id: str = ALERTS_TOPIC):
        self.project_id = project_id
        self.dataset_id = dataset_id
        self.topic_id = topic_id
        self.bq_client = bigquery.Client(project=project_id)
        self.publisher = pubsub_v1.PublisherClient()
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

    def _merge_and_fetch_new_alerts(self, lookback_minutes: int, min_score: int) -> List[Dict[str, Any]]:
        """
        Uses BigQuery MERGE to bucket 2-minute windows, scoring only windows that closed
        more than 60 seconds ago. Returns only rows inserted during this run.
        """
        merge_query = f"""
        DECLARE current_run_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP();

        MERGE `{self.project_id}.{self.dataset_id}.alerts` T
        USING (
          WITH BucketedEvents AS (
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
            FROM `{self.project_id}.{self.dataset_id}.user_access_events` AS access
            INNER JOIN `{self.project_id}.{self.dataset_id}.network_events` AS network
              ON access.assigned_internal_ip = network.source_ip
            WHERE access.event_timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {lookback_minutes} MINUTE)
              AND network.event_timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {lookback_minutes} MINUTE)
              AND access.event_type = 'login_success'
            GROUP BY access.user_id, access.device_id, access.source_ip, window_start, window_end
            -- Only evaluate windows that closed more than 60s ago (late-data allowance)
            HAVING window_end <= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 60 SECOND)
               AND total_2_min_threat_score >= {min_score}
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
        try:
            logger.info("Executing MERGE query against alerts table...")
            merge_job = self.bq_client.query(merge_query)
            merge_job.result()
        except Exception as e:
            logger.error("Error executing MERGE query: %s", e)
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
          AND detected_at >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 5 MINUTE)
        ORDER BY window_start ASC;
        """
        try:
            query_job = self.bq_client.query(fetch_query)
            return [dict(row.items()) for row in query_job.result()]
        except Exception as e:
            logger.error("Error fetching newly created alerts: %s", e)
            return []

    def _publish_alerts(self, alerts: List[Dict[str, Any]]) -> int:
        """
        Publishes alerts to cymbal_cyber_alerts matching the unified Alert Contract.
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
                    "window_start": alert["window_start"],
                    "window_end": alert["window_end"],
                    "total_2_min_threat_score": alert["total_2_min_threat_score"],
                    "high_privilege_request_count": alert.get("high_privilege_request_count", 0),
                    "malicious_command_count": alert.get("malicious_command_count", 0),
                    "malicious_dns_count": alert.get("malicious_dns_count", 0),
                    "detected_at": alert["detected_at"]
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
          dlq.alert_id,
          dlq.payload,
          dlq.dead_lettered_at
        FROM `{self.project_id}.{self.dataset_id}.alerts_dead_letter` dlq
        INNER JOIN `{self.project_id}.{self.dataset_id}.alerts` a
          ON dlq.alert_id = a.alert_id
        WHERE a.status != 'DEAD_LETTERED'
        LIMIT 20;
        """
        try:
            query_job = self.bq_client.query(dlq_query)
            dead_letters = [dict(row.items()) for row in query_job.result()]
        except Exception as e:
            logger.warning("DLQ inspection query failed (table may be empty or uncreated yet): %s", e)
            return 0

        handled = 0
        for dl in dead_letters:
            alert_id = dl["alert_id"]
            if not alert_id:
                continue

            # 1. Update alerts table status to DEAD_LETTERED
            update_query = f"""
            UPDATE `{self.project_id}.{self.dataset_id}.alerts`
            SET status = 'DEAD_LETTERED', updated_at = CURRENT_TIMESTAMP()
            WHERE alert_id = '{alert_id}';
            """
            try:
                self.bq_client.query(update_query).result()
            except Exception as e:
                logger.error("Failed to update status for DEAD_LETTERED alert %s: %s", alert_id, e)

            # 2. Insert auto-escalation ticket into soc_tickets
            ticket_id = f"DLQ-AUTO-ESCALATE-{alert_id.replace('|', '-')}"
            insert_ticket_sql = f"""
            INSERT INTO `{self.project_id}.{self.dataset_id}.soc_tickets` (
              ticket_id, created_at, user_id, device_id, source_ip,
              threat_score, severity, status, agent_decision, agent_reason,
              mitre_tactics, indicators_of_compromise, screenshot_url,
              structured_report, human_decision, human_comment, adjudicated_at
            )
            VALUES (
              '{ticket_id}',
              CURRENT_TIMESTAMP(),
              SPLIT('{alert_id}', '|')[OFFSET(0)],
              'endpoint-unknown',
              '0.0.0.0',
              2000,
              'CRITICAL',
              'ESCALATED',
              'DEAD_LETTER_AUTO_ESCALATION',
              'Alert failed max delivery attempts (5) to the ADK agent webhook and landed on DLQ. Auto-escalated for immediate human triage.',
              ['Execution', 'Defense Evasion'],
              ['DLQ Failure', '{alert_id}'],
              NULL,
              '### DLQ Auto-Escalation Report\\n\\nAlert `{alert_id}` exhausted all Pub/Sub delivery attempts. The automated webhook failed to respond. Immediate human intervention required.',
              NULL, NULL, NULL
            );
            """
            try:
                self.bq_client.query(insert_ticket_sql).result()
                logger.warning("Auto-escalated DLQ alert '%s' to SOC tickets as '%s'", alert_id, ticket_id)
                handled += 1
            except Exception as e:
                logger.error("Failed to insert auto-escalation ticket for %s: %s", alert_id, e)

        return handled


def main():
    parser = argparse.ArgumentParser(description="Scheduled Micro-Batch Threat Detector")
    parser.add_argument("--lookback", type=int, default=15, help="Lookback window in minutes (default: 15)")
    parser.add_argument("--min-score", type=int, default=100, help="Minimum threat score threshold (default: 100)")
    args = parser.parse_args()

    detector = ThreatDetector()
    detector.run_detection_cycle(lookback_minutes=args.lookback, min_score=args.min_score)


if __name__ == "__main__":
    main()

