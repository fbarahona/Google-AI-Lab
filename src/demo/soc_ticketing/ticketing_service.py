"""
SOC Ticketing Service
=====================
Manages the end-to-end incident ticketing lifecycle:
1. Passes validated security incident tickets to the SOC ticketing queue.
2. Persists ticket state across BigQuery (Cymbal_Cyber.soc_tickets) and GCS.
3. Dispatches optional outbound alerts to webhooks (Slack, Teams, Jira, ServiceNow, SOAR).
4. Synchronizes human analyst adjudication and writes resolution back to BigQuery.
"""

import os
import json
import time
import logging
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List

from .models import SocTicket

logger = logging.getLogger("SocTicketingService")


class SocTicketingService:
    def __init__(
        self,
        project_id: str = "oso-ai-503519",
        dataset_id: str = "Cymbal_Cyber",
        escalation_bucket: Optional[str] = None,
        webhook_url: Optional[str] = None
    ):
        self.project_id = project_id
        self.dataset_id = dataset_id
        self.escalation_bucket_name = (
            escalation_bucket
            or os.getenv("ESCALATION_BUCKET", f"cymbal-cyber-adk-escalations-bucket_{project_id}")
        )
        self.webhook_url = webhook_url or os.getenv("SOC_WEBHOOK_URL")

        # Lazy GCP clients
        self._bq_client = None
        self._storage_client = None

    @property
    def bq_client(self):
        if self._bq_client is None:
            from google.cloud import bigquery
            self._bq_client = bigquery.Client(project=self.project_id)
        return self._bq_client

    @property
    def storage_client(self):
        if self._storage_client is None:
            from google.cloud import storage
            self._storage_client = storage.Client(project=self.project_id)
        return self._storage_client

    def create_and_dispatch_ticket(self, ticket: SocTicket) -> str:
        """
        Ingests and dispatches a new incident ticket to the SOC ticketing system:
        - Uploads ticket payload to GCS for real-time analyst queue / Streamlit pickup
        - Inserts ticket row into BigQuery soc_tickets and adk_threat_assessment
        - Dispatches webhook notification if configured.
        """
        logger.info("Passing ticket %s to SOC ticketing system...", ticket.ticket_id)

        # 1. Write to GCS queue for SOC analyst console
        try:
            bucket = self.storage_client.bucket(self.escalation_bucket_name)
            filename = f"human_escalation_information_{ticket.ticket_id}.json"
            blob = bucket.blob(filename)
            gcs_payload = {
                "timestamp": ticket.created_at,
                "ticket_id": ticket.ticket_id,
                "user_id": ticket.user_id,
                "device_id": ticket.device_id,
                "severity": ticket.severity,
                "threat_score": ticket.threat_score,
                "context_for_human": ticket.structured_report,
                "agent_reason_for_escalation": ticket.agent_reason,
                "screenshot_url": ticket.screenshot_url,
                "mitre_tactics": ticket.mitre_tactics,
                "indicators_of_compromise": ticket.indicators_of_compromise
            }
            blob.upload_from_string(
                json.dumps(gcs_payload, indent=2),
                content_type="application/json"
            )
            logger.info("Uploaded ticket %s to gs://%s/%s", ticket.ticket_id, self.escalation_bucket_name, filename)
        except Exception as e:
            logger.warning("Could not upload ticket to GCS escalation bucket: %s", e)

        # 2. Persist to BigQuery tables
        try:
            # soc_tickets table
            soc_table_id = f"{self.project_id}.{self.dataset_id}.soc_tickets"
            row = ticket.model_dump()
            errors = self.bq_client.insert_rows_json(soc_table_id, [row])
            if errors:
                logger.warning("Error logging to BigQuery soc_tickets: %s", errors)
            else:
                logger.info("Persisted ticket %s to %s", ticket.ticket_id, soc_table_id)

            # adk_threat_assessment table (compatibility with existing continuous query schema)
            threat_table_id = f"{self.project_id}.{self.dataset_id}.adk_threat_assessment"
            assessment_row = {
                "transaction_window_end": ticket.created_at,
                "user_id": ticket.user_id,
                "device_id": ticket.device_id,
                "source_ip": ticket.source_ip,
                "total_2_min_threat_score": ticket.threat_score,
                "agent_decision": ticket.agent_decision,
                "agent_reason": ticket.agent_reason,
                "human_decision": ticket.human_decision,
                "human_reason": ticket.human_comment,
                "alert_payload": json.dumps({
                    "ticket_id": ticket.ticket_id,
                    "user_id": ticket.user_id,
                    "device_id": ticket.device_id,
                    "source_ip": ticket.source_ip,
                    "threat_score": ticket.threat_score,
                    "severity": ticket.severity
                })
            }
            self.bq_client.insert_rows_json(threat_table_id, [assessment_row])
        except Exception as e:
            logger.warning("Could not persist ticket to BigQuery: %s", e)

        # 3. Trigger Outbound Webhook (Optional SOAR / ChatOps)
        if self.webhook_url:
            self._send_webhook(ticket)

        return f"Successfully dispatched ticket {ticket.ticket_id} to SOC ticketing system with severity {ticket.severity}."

    def _send_webhook(self, ticket: SocTicket):
        """Dispatches an HTTP POST webhook notification."""
        try:
            import urllib.request
            payload = {
                "text": f"🚨 [SOC Incident {ticket.ticket_id}] Severity: {ticket.severity} | User: {ticket.user_id} | Threat Score: {ticket.threat_score}",
                "ticket": ticket.model_dump()
            }
            req = urllib.request.Request(
                self.webhook_url,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"}
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                logger.info("Outbound webhook dispatched. Status: %s", resp.status)
        except Exception as e:
            logger.warning("Webhook dispatch failed: %s", e)

    def record_human_verdict(
        self,
        ticket_id: str,
        human_decision: str,
        human_comment: str
    ) -> bool:
        """Records the human SOC analyst's verdict and updates ticket status."""
        logger.info("Recording analyst verdict for ticket %s: %s", ticket_id, human_decision)
        now_iso = datetime.now(timezone.utc).isoformat()
        try:
            # Update BigQuery
            query = f"""
            UPDATE `{self.project_id}.{self.dataset_id}.soc_tickets`
            SET
              status = 'RESOLVED',
              human_decision = @decision,
              human_comment = @comment,
              adjudicated_at = @adjudicated_at
            WHERE ticket_id = @ticket_id
            """
            from google.cloud import bigquery
            job_config = bigquery.QueryJobConfig(
                query_parameters=[
                    bigquery.ScalarQueryParameter("decision", "STRING", human_decision),
                    bigquery.ScalarQueryParameter("comment", "STRING", human_comment),
                    bigquery.ScalarQueryParameter("adjudicated_at", "STRING", now_iso),
                    bigquery.ScalarQueryParameter("ticket_id", "STRING", ticket_id)
                ]
            )
            self.bq_client.query(query, job_config=job_config).result()
            return True
        except Exception as e:
            logger.error("Failed to update ticket verdict in BigQuery: %s", e)
            return False

