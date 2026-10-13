"""
SOC Ticketing Service
=====================
Manages the end-to-end incident ticketing lifecycle:
1. Passes validated security incident tickets to the active SOC ticketing queue.
2. Archives and queries historical tickets (approved genuine threats and dismissed false positives).
3. Persists ticket state across BigQuery (Cymbal_Cyber.soc_tickets), GCS, and local file storage.
4. Provides aggregated metrics for dashboard visualization.
"""

import glob
import json
import logging
import os
import time
from datetime import UTC, datetime, timedelta
from typing import Any

try:
    from .models import SocTicket
except ImportError:
    from models import SocTicket

logger = logging.getLogger("SocTicketingService")

LOCAL_QUEUE_DIR = os.getenv("LOCAL_QUEUE_DIR", "./local_demo_data/escalations")
LOCAL_HISTORY_DIR = os.path.join(LOCAL_QUEUE_DIR, "history")


class SocTicketingService:
    def __init__(
        self,
        project_id: str | None = None,
        dataset_id: str = "Cymbal_Cyber",
        escalation_bucket: str | None = None,
        webhook_url: str | None = None
    ):
        self.project_id = project_id or os.getenv("GOOGLE_CLOUD_PROJECT", "local-demo")
        self.dataset_id = dataset_id
        self.escalation_bucket_name = (
            escalation_bucket
            or os.getenv("ESCALATION_BUCKET", f"cymbal-cyber-adk-escalations-bucket_{project_id}")
        )
        self.webhook_url = webhook_url or os.getenv("SOC_WEBHOOK_URL")

        self._bq_client = None
        self._storage_client = None

        os.makedirs(self.queue_dir, exist_ok=True)
        os.makedirs(self.history_dir, exist_ok=True)

    @property
    def queue_dir(self) -> str:
        d = os.getenv("LOCAL_QUEUE_DIR", "./local_demo_data/escalations")
        os.makedirs(d, exist_ok=True)
        return d

    @property
    def history_dir(self) -> str:
        d = os.path.join(self.queue_dir, "history")
        os.makedirs(d, exist_ok=True)
        return d

    @property
    def bq_client(self):
        if self._bq_client is None:
            try:
                from google.cloud import bigquery
                self._bq_client = bigquery.Client(project=self.project_id)
            except Exception:
                self._bq_client = None
        return self._bq_client

    @property
    def storage_client(self):
        if self._storage_client is None:
            try:
                from google.cloud import storage
                self._storage_client = storage.Client(project=self.project_id)
            except Exception:
                self._storage_client = None
        return self._storage_client

    def is_cloud_enabled(self) -> bool:
        """Determines if GCP Cloud Storage is actively accessible."""
        if os.getenv("LOCAL_MODE", "false").lower() == "true":
            return False
        try:
            if self.storage_client is not None:
                self.storage_client.bucket(self.escalation_bucket_name)
                return True
        except Exception:
            pass
        return False

    def create_and_dispatch_ticket(self, ticket: SocTicket) -> str:
        """
        Ingests and dispatches a new incident ticket to the SOC ticketing system:
        - Uploads ticket payload to GCS (or local file queue in local mode)
        - Inserts ticket row into BigQuery soc_tickets and adk_threat_assessment
        """
        logger.info("Passing ticket %s to SOC ticketing system...", ticket.ticket_id)
        payload = ticket.model_dump()

        # 1. Cloud Storage write (if cloud available)
        if self.is_cloud_enabled():
            try:
                bucket = self.storage_client.bucket(self.escalation_bucket_name)
                filename = f"human_escalation_information_{ticket.ticket_id}.json"
                blob = bucket.blob(filename)
                blob.upload_from_string(json.dumps(payload, indent=2), content_type="application/json")
                logger.info("Uploaded ticket %s to gs://%s/%s", ticket.ticket_id, self.escalation_bucket_name, filename)
            except Exception as e:
                logger.warning("Could not upload to GCS: %s", e)

        # 2. Local File Queue write
        local_file = os.path.join(self.queue_dir, f"human_escalation_information_{ticket.ticket_id}.json")
        with open(local_file, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)

        # 3. BigQuery write (if available)
        if self.bq_client is not None:
            try:
                soc_table_id = f"{self.project_id}.{self.dataset_id}.soc_tickets"
                self.bq_client.insert_rows_json(soc_table_id, [payload])
                logger.info("Persisted ticket %s to %s", ticket.ticket_id, soc_table_id)
            except Exception as e:
                logger.warning("Could not persist ticket to BigQuery soc_tickets: %s", e)

            try:
                assessment_table_id = f"{self.project_id}.{self.dataset_id}.adk_threat_assessment"
                assessment_row = {
                    "transaction_window_end": ticket.transaction_window_end or datetime.now(UTC).isoformat(),
                    "user_id": ticket.user_id,
                    "device_id": ticket.device_id,
                    "source_ip": ticket.source_ip,
                    "total_2_min_threat_score": ticket.threat_score,
                    "agent_decision": ticket.agent_decision or "GENUINE_THREAT",
                    "agent_reason": ticket.agent_reason,
                    "human_decision": None,
                    "human_reason": None,
                    "alert_payload": json.dumps(payload)
                }
                self.bq_client.insert_rows_json(assessment_table_id, [assessment_row])
                logger.info("Persisted assessment for user %s to %s", ticket.user_id, assessment_table_id)
            except Exception as e:
                logger.warning("Could not persist ticket to BigQuery adk_threat_assessment: %s", e)

        return f"Successfully dispatched ticket {ticket.ticket_id} to SOC ticketing system with severity {ticket.severity}."

    def fetch_new_tickets(self) -> list[dict[str, Any]]:
        """Retrieves all active, pending incident tickets awaiting analyst review."""
        tickets: list[dict[str, Any]] = []

        if self.is_cloud_enabled():
            try:
                bucket = self.storage_client.bucket(self.escalation_bucket_name)
                for blob in bucket.list_blobs():
                    if blob.name.startswith("human_escalation_information_") and blob.name.endswith(".json"):
                        try:
                            data = json.loads(blob.download_as_text())
                            tickets.append(data)
                        except Exception:
                            pass
                return tickets
            except Exception:
                pass

        # Fallback to local queue
        for path in glob.glob(os.path.join(self.queue_dir, "human_escalation_information_*.json")):
            try:
                with open(path, encoding="utf-8") as f:
                    tickets.append(json.load(f))
            except Exception:
                pass

        # Sort newest first
        tickets.sort(key=lambda x: x.get("timestamp") or x.get("created_at") or "", reverse=True)
        return tickets

    def record_human_verdict(
        self,
        ticket_id: str,
        human_decision: str,
        human_comment: str
    ) -> bool:
        """
        Records human analyst adjudication:
        - Resolves ticket as GENUINE_THREAT or FALSE_POSITIVE
        - Archives ticket into historical store
        - Removes from active escalation queue
        """
        logger.info("Recording analyst verdict for ticket %s: %s", ticket_id, human_decision)
        now_iso = datetime.now(UTC).isoformat()

        # Find existing ticket
        ticket_data = None
        active_local_path = os.path.join(self.queue_dir, f"human_escalation_information_{ticket_id}.json")

        if os.path.exists(active_local_path):
            try:
                with open(active_local_path, encoding="utf-8") as f:
                    ticket_data = json.load(f)
            except Exception:
                pass

        if not ticket_data and self.is_cloud_enabled():
            try:
                bucket = self.storage_client.bucket(self.escalation_bucket_name)
                blob = bucket.blob(f"human_escalation_information_{ticket_id}.json")
                if blob.exists():
                    ticket_data = json.loads(blob.download_as_text())
            except Exception:
                pass

        if not ticket_data:
            ticket_data = {
                "ticket_id": ticket_id,
                "created_at": now_iso,
                "user_id": "unknown_user",
                "device_id": "unknown_device",
                "source_ip": "10.0.0.1",
                "threat_score": 100,
                "severity": "HIGH",
                "status": "RESOLVED",
                "agent_decision": "PERCEIVED_THREAT",
                "agent_reason": "Escalated for human triage",
                "structured_report": "Incident escalated."
            }

        # Update resolution metadata
        ticket_data["status"] = "RESOLVED"
        ticket_data["human_decision"] = human_decision
        ticket_data["human_comment"] = human_comment
        ticket_data["adjudicated_at"] = now_iso

        # 1. Save to Local History Archive
        os.makedirs(self.history_dir, exist_ok=True)
        hist_local_path = os.path.join(self.history_dir, f"resolved_{ticket_id}.json")
        with open(hist_local_path, "w", encoding="utf-8") as f:
            json.dump(ticket_data, f, indent=2)

        # 2. Remove active request file
        if os.path.exists(active_local_path):
            try:
                os.remove(active_local_path)
            except Exception:
                pass

        # 3. Cloud update
        if self.is_cloud_enabled():
            try:
                bucket = self.storage_client.bucket(self.escalation_bucket_name)
                # Upload response file for waiting ADK agent runner
                resp_blob = bucket.blob(f"human_escalation_response_{ticket_id}.json")
                resp_payload = {
                    "ticket_id": ticket_id,
                    "human_decision": human_decision,
                    "human_comment": human_comment,
                    "timestamp": time.time()
                }
                resp_blob.upload_from_string(json.dumps(resp_payload, indent=2), content_type="application/json")

                # Upload to archive folder
                hist_blob = bucket.blob(f"history/resolved_{ticket_id}.json")
                hist_blob.upload_from_string(json.dumps(ticket_data, indent=2), content_type="application/json")

                # Delete active pending request
                req_blob = bucket.blob(f"human_escalation_information_{ticket_id}.json")
                if req_blob.exists():
                    req_blob.delete()
            except Exception as e:
                logger.warning("Cloud verdict sync warning: %s", e)

        # 4. BigQuery Update
        if self.bq_client is not None:
            try:
                from google.cloud import bigquery
                query = f"""
                UPDATE `{self.project_id}.{self.dataset_id}.soc_tickets`
                SET
                  status = 'RESOLVED',
                  human_decision = @decision,
                  human_comment = @comment,
                  adjudicated_at = @adjudicated_at
                WHERE ticket_id = @ticket_id
                """
                job_config = bigquery.QueryJobConfig(
                    query_parameters=[
                        bigquery.ScalarQueryParameter("decision", "STRING", human_decision),
                        bigquery.ScalarQueryParameter("comment", "STRING", human_comment),
                        bigquery.ScalarQueryParameter("adjudicated_at", "STRING", now_iso),
                        bigquery.ScalarQueryParameter("ticket_id", "STRING", ticket_id)
                    ]
                )
                self.bq_client.query(query, job_config=job_config).result()
            except Exception as e:
                logger.warning("BigQuery verdict update warning: %s", e)

        return True

    def fetch_historic_tickets(self) -> list[dict[str, Any]]:
        """
        Retrieves all archived and historical tickets (both Approved Genuine Threats and False Positives).
        Seeds a rich historical baseline if history is empty.
        """
        historic: list[dict[str, Any]] = []

        # 1. Cloud BigQuery query if available
        if self.bq_client is not None:
            try:
                query = f"""
                SELECT * FROM `{self.project_id}.{self.dataset_id}.soc_tickets`
                WHERE status = 'RESOLVED' OR human_decision IS NOT NULL
                ORDER BY adjudicated_at DESC LIMIT 100
                """
                results = list(self.bq_client.query(query).result())
                if results:
                    return [dict(row.items()) for row in results]
            except Exception:
                pass

        # 2. Local History Files
        for path in glob.glob(os.path.join(self.history_dir, "resolved_*.json")):
            try:
                with open(path, encoding="utf-8") as f:
                    historic.append(json.load(f))
            except Exception:
                pass

        # If history has fewer than 5 records, seed realistic historical items for demonstration
        if len(historic) < 5:
            seed_items = self._generate_seed_history()
            for item in seed_items:
                # Save locally so they persist across runs
                hist_file = os.path.join(self.history_dir, f"resolved_{item['ticket_id']}.json")
                if not os.path.exists(hist_file):
                    try:
                        with open(hist_file, "w", encoding="utf-8") as f:
                            json.dump(item, f, indent=2)
                    except Exception:
                        pass
                historic.append(item)

        historic.sort(key=lambda x: x.get("adjudicated_at") or x.get("created_at") or "", reverse=True)
        return historic

    def _generate_seed_history(self) -> list[dict[str, Any]]:
        """Generates realistic baseline historic tickets for the dashboard."""
        now = datetime.now(UTC)
        screenshots_dir = "local_demo_data/user_screenshots" if os.path.exists("local_demo_data/user_screenshots") else "src/demo/user_screenshots"
        return [
            {
                "ticket_id": "SOC-TICKET-g.harris-1791600100",
                "created_at": (now - timedelta(days=2, hours=3)).isoformat(),
                "user_id": "g.harris",
                "device_id": "ws-hr-05",
                "source_ip": "175.45.176.10",
                "threat_score": 2400,
                "severity": "CRITICAL",
                "status": "RESOLVED",
                "category": "Malware",
                "sla_status": "Within SLA",
                "geo_country": "North Korea",
                "geo_lat": 39.0392,
                "geo_lon": 125.7625,
                "agent_decision": "PERCEIVED_THREAT",
                "agent_reason": "C2 beaconing and unauthorized PowerShell script execution detected from known Lazarus Group IP.",
                "mitre_tactics": ["Command and Control", "Execution", "Initial Access"],
                "indicators_of_compromise": ["175.45.176.10", "c2-server-1.xyz"],
                "screenshot_url": f"{screenshots_dir}/g.harris.png",
                "structured_report": "### Security Incident Report\n* **User:** g.harris\n* **Verdict:** Genuine Threat\n* **Evidence:** Visual terminal confirmed Mimikatz execution.",
                "human_decision": "Genuine Threat",
                "human_comment": "Confirmed credential theft and lateral movement attempt. Workstation isolated and credentials revoked.",
                "adjudicated_at": (now - timedelta(days=2, hours=2)).isoformat()
            },
            {
                "ticket_id": "SOC-TICKET-l.taylor-1791580220",
                "created_at": (now - timedelta(days=3, hours=5)).isoformat(),
                "user_id": "l.taylor",
                "device_id": "ws-hr-01",
                "source_ip": "74.125.70.93",
                "threat_score": 120,
                "severity": "LOW",
                "status": "RESOLVED",
                "category": "Policy Violation",
                "sla_status": "Within SLA",
                "geo_country": "United States",
                "geo_lat": 37.7749,
                "geo_lon": -122.4194,
                "agent_decision": "FALSE_POSITIVE",
                "agent_reason": "Automated IT backup script triggering threshold; no hostile foreign IPs or escalation detected.",
                "mitre_tactics": ["Discovery"],
                "indicators_of_compromise": ["74.125.70.93"],
                "screenshot_url": f"{screenshots_dir}/l.taylor.png",
                "structured_report": "### Security Incident Report\n* **User:** l.taylor\n* **Verdict:** False Positive\n* **Evidence:** Standard maintenance script.",
                "human_decision": "False Positive",
                "human_comment": "Scheduled maintenance routine verified with DevOps team.",
                "adjudicated_at": (now - timedelta(days=3, hours=4, minutes=40)).isoformat()
            },
            {
                "ticket_id": "SOC-TICKET-r.patel-1791550180",
                "created_at": (now - timedelta(days=4, hours=1)).isoformat(),
                "user_id": "r.patel",
                "device_id": "srv-web-prod-02",
                "source_ip": "194.26.135.68",
                "threat_score": 1950,
                "severity": "CRITICAL",
                "status": "RESOLVED",
                "category": "Risky Domain/URL",
                "sla_status": "Within SLA",
                "geo_country": "Russia",
                "geo_lat": 55.7558,
                "geo_lon": 37.6173,
                "agent_decision": "PERCEIVED_THREAT",
                "agent_reason": "High-risk domain connection to 'my-payload-downloader.ru' and multiple login failures.",
                "mitre_tactics": ["Initial Access", "Command and Control"],
                "indicators_of_compromise": ["194.26.135.68", "my-payload-downloader.ru"],
                "screenshot_url": f"{screenshots_dir}/r.patel.png",
                "structured_report": "### Security Incident Report\n* **User:** r.patel\n* **Origin:** Moscow, Russia\n* **Domain:** my-payload-downloader.ru",
                "human_decision": "Genuine Threat",
                "human_comment": "Blocked external IP at perimeter firewall. Domain sinkholed.",
                "adjudicated_at": (now - timedelta(days=4)).isoformat()
            },
            {
                "ticket_id": "SOC-TICKET-c.wilson-1791510400",
                "created_at": (now - timedelta(days=6, hours=8)).isoformat(),
                "user_id": "c.wilson",
                "device_id": "ws-finance-03",
                "source_ip": "74.125.10.15",
                "threat_score": 280,
                "severity": "MEDIUM",
                "status": "RESOLVED",
                "category": "Data Leak",
                "sla_status": "Approaching SLA",
                "geo_country": "United States",
                "geo_lat": 40.7128,
                "geo_lon": -74.0060,
                "agent_decision": "FALSE_POSITIVE",
                "agent_reason": "Elevated outbound file transfer volume during quarter-end financial reconciliation.",
                "mitre_tactics": ["Collection"],
                "indicators_of_compromise": ["74.125.10.15"],
                "screenshot_url": f"{screenshots_dir}/c.wilson.png",
                "structured_report": "### Security Incident Report\n* **User:** c.wilson\n* **Type:** Financial data transfer",
                "human_decision": "False Positive",
                "human_comment": "Approved quarterly financial ledger sync with authorized external auditor.",
                "adjudicated_at": (now - timedelta(days=6, hours=4)).isoformat()
            },
            {
                "ticket_id": "SOC-TICKET-temp-contractor-1791480050",
                "created_at": (now - timedelta(days=8, hours=2)).isoformat(),
                "user_id": "temp_contractor",
                "device_id": "ws-dev-11",
                "source_ip": "185.220.101.5",
                "threat_score": 1400,
                "severity": "HIGH",
                "status": "RESOLVED",
                "category": "Botnet",
                "sla_status": "Within SLA",
                "geo_country": "Germany",
                "geo_lat": 52.5200,
                "geo_lon": 13.4050,
                "agent_decision": "PERCEIVED_THREAT",
                "agent_reason": "Connection originating from known Tor exit node with port scanning activity.",
                "mitre_tactics": ["Reconnaissance"],
                "indicators_of_compromise": ["185.220.101.5"],
                "screenshot_url": f"{screenshots_dir}/temp_contractor.png",
                "structured_report": "### Security Incident Report\n* **User:** temp_contractor\n* **IP:** Tor exit node",
                "human_decision": "Genuine Threat",
                "human_comment": "Contractor VPN session terminated. Tor IP added to dynamic blocklist.",
                "adjudicated_at": (now - timedelta(days=8, hours=1)).isoformat()
            }
        ]
