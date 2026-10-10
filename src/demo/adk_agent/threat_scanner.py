"""
BigQuery Threat Scanner Service
===============================
Actively scans BigQuery dataset (Cymbal_Cyber) for new threat events,
extracts anomalies, and invokes the ADK Agent Orchestrator to investigate
and pass confirmed threats to the SOC Ticketing System.

Usage:
  python -m src.demo.adk_agent.threat_scanner --once
  python -m src.demo.adk_agent.threat_scanner --daemon --interval 30
"""

import os
import sys
import time
import json
import uuid
import asyncio
import logging
import argparse
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

from google.cloud import bigquery
from google.genai import types
from google.adk.sessions import InMemorySessionService
from google.adk.runners import Runner

from .agent import root_agent, bq_analytics_plugin
from .logging_utils import setup_logging, log_agent_event

logger = logging.getLogger("BigQueryThreatScanner")

PROJECT_ID = os.getenv("GOOGLE_CLOUD_PROJECT", "oso-ai-503519")
DATASET_ID = os.getenv("BIGQUERY_DATASET", "Cymbal_Cyber")
SCAN_INTERVAL_SECONDS = 30


class BigQueryThreatScanner:
    def __init__(self, project_id: str = PROJECT_ID, dataset_id: str = DATASET_ID):
        self.project_id = project_id
        self.dataset_id = dataset_id
        self.bq_client = bigquery.Client(project=project_id)
        self.session_service = InMemorySessionService()

    def find_new_threat_events(self, lookback_minutes: int = 15, min_score: int = 100) -> List[Dict[str, Any]]:
        """
        Queries BigQuery to detect correlated security threat events that
        have not yet been assessed in adk_threat_assessment.
        """
        query = f"""
        WITH CorrelatedEvents AS (
          SELECT
            access.user_id,
            access.device_id,
            access.source_ip,
            MAX(access.event_timestamp) AS window_end,
            SUM(
              CASE
                WHEN network.event_type = 'policy_violation' THEN 50
                WHEN network.event_type = 'dns_query' AND REGEXP_CONTAINS(network.network_domain, r'(\\.ru|\\.xyz|\\.org|bad-domain|c2-server)') THEN 60
                ELSE 0
              END
              + CASE WHEN network.permission_level_requested IN ('root', 'admin') THEN 35 ELSE 0 END
              + CASE WHEN REGEXP_CONTAINS(access.user_agent, r'^(python-requests|curl|Go-http-client)') THEN 20 ELSE 0 END
              + CASE WHEN network.event_type = 'file_transfer' AND network.file_type IN ('exe', 'dll', 'ps1', 'bat', 'vbs') THEN 40 ELSE 0 END
              + CASE WHEN REGEXP_CONTAINS(network.command_line, r'(?i)(powershell -enc|IEX|DownloadString|mimikatz|payload)') THEN 100 ELSE 0 END
            ) AS total_2_min_threat_score,
            COUNTIF(network.permission_level_requested IN ('root', 'admin')) AS high_privilege_request_count,
            COUNTIF(REGEXP_CONTAINS(network.command_line, r'(?i)(powershell -enc|IEX|mimikatz|payload)')) AS malicious_command_count,
            COUNTIF(REGEXP_CONTAINS(network.network_domain, r'(\\.ru|\\.xyz|bad-domain|c2-server)')) AS malicious_dns_count
          FROM `{self.project_id}.{self.dataset_id}.user_access_events` AS access
          INNER JOIN `{self.project_id}.{self.dataset_id}.network_events` AS network
            ON access.assigned_internal_ip = network.source_ip
          WHERE access.event_timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {lookback_minutes} MINUTE)
            AND network.event_timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {lookback_minutes} MINUTE)
            AND access.event_type = 'login_success'
          GROUP BY access.user_id, access.device_id, access.source_ip
          HAVING total_2_min_threat_score >= {min_score}
        )
        SELECT c.*
        FROM CorrelatedEvents c
        LEFT JOIN `{self.project_id}.{self.dataset_id}.adk_threat_assessment` a
          ON c.user_id = a.user_id
          AND a.transaction_window_end >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {lookback_minutes} MINUTE)
        WHERE a.user_id IS NULL
        LIMIT 5;
        """
        try:
            logger.info("Scanning BigQuery (%s.%s) for new threat events...", self.project_id, self.dataset_id)
            query_job = self.bq_client.query(query)
            results = [dict(row.items()) for row in query_job.result()]
            # Format datetime fields
            for r in results:
                if "window_end" in r and r["window_end"]:
                    r["window_end"] = r["window_end"].isoformat()
            logger.info("Found %d unassessed threat events in BigQuery.", len(results))
            return results
        except Exception as e:
            logger.warning("BigQuery threat scan query failed: %s", e)
            return []

    async def investigate_threat(self, threat_payload: Dict[str, Any]) -> str:
        """
        Invokes the ADK Agent Orchestrator to investigate the threat and pass
        the ticket to the SOC ticketing system.
        """
        app_name = "cymbal_cyber_adk"
        session_id = f"bq-threat-{uuid.uuid4().hex[:8]}"
        user_id = threat_payload.get("user_id", "security_scanner")

        payload_json = json.dumps(threat_payload, default=str)
        logger.info("Dispatching threat to ADK Multi-Agent Orchestrator (Session: %s)...", session_id)

        session = await self.session_service.create_session(
            app_name=app_name,
            user_id=user_id,
            session_id=session_id,
            state={"ticket_id": f"SOC-TICKET-{user_id}-{int(time.time())}"}
        )

        plugins = [bq_analytics_plugin] if bq_analytics_plugin else []
        runner = Runner(
            agent=root_agent,
            app_name=app_name,
            session_service=self.session_service,
            plugins=plugins
        )

        content = types.Content(role="user", parts=[types.Part(text=payload_json)])
        final_response = ""

        async for event in runner.run_async(
            user_id=user_id,
            session_id=session_id,
            new_message=content
        ):
            if event.is_final_response():
                if event.content and event.content.parts:
                    final_response = event.content.parts[0].text
                    logger.info("ADK Agent Orchestrator Response:\n%s", final_response)

        return final_response

    async def run_loop(self, daemon: bool = False, interval: int = SCAN_INTERVAL_SECONDS):
        """Runs the threat scanning loop."""
        setup_logging()
        logger.info("Starting BigQuery Threat Scanner (Daemon: %s, Interval: %ds)...", daemon, interval)

        while True:
            threats = self.find_new_threat_events()
            for threat in threats:
                logger.info("Discovered Threat for user: %s (Score: %s)", threat.get("user_id"), threat.get("total_2_min_threat_score"))
                await self.investigate_threat(threat)

            if not daemon:
                logger.info("Single scan run completed.")
                break

            await asyncio.sleep(interval)


def main():
    parser = argparse.ArgumentParser(description="BigQuery Threat Scanner Service")
    parser.add_argument("--daemon", action="store_true", help="Run scanner continuously in the background.")
    parser.add_argument("--once", action="store_true", help="Run a single scan and exit.")
    parser.add_argument("--interval", type=int, default=SCAN_INTERVAL_SECONDS, help="Seconds between scans.")
    parser.add_argument("--project-id", default=PROJECT_ID, help="GCP Project ID.")
    parser.add_argument("--dataset", default=DATASET_ID, help="BigQuery dataset name.")
    args = parser.parse_args()

    scanner = BigQueryThreatScanner(project_id=args.project_id, dataset_id=args.dataset)
    daemon_mode = args.daemon and not args.once
    asyncio.run(scanner.run_loop(daemon=daemon_mode, interval=args.interval))


if __name__ == "__main__":
    main()

