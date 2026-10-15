"""
SOC Ticketing Service
=====================
Manages the end-to-end incident ticketing lifecycle:
1. Passes validated security incident tickets to the active SOC ticketing queue.
2. Archives and queries historical tickets (approved genuine threats and dismissed false positives).
3. Persists ticket state across BigQuery (Cymbal_Cyber.soc_tickets), GCS, and local file storage.
4. Queries BigQuery directly as the Single Source of Truth for tickets and dashboard telemetry.
5. Employs append-resolution and CTE deduplication to seamlessly handle BigQuery streaming buffers.
6. Provides dynamic aggregated metrics for dashboard visualization.
"""

import glob
import json
import logging
import os
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from src.demo.soc_ticketing.models import (
    AUTO_CLOSED_FP_DECISION,
    SIMULATED_DECISION,
    SocTicket,
)

logger = logging.getLogger("SocTicketingService")

REPO_ROOT = Path(__file__).resolve().parents[3]
SCREENSHOTS_DIR = REPO_ROOT / "local_demo_data" / "user_screenshots"
DEFAULT_QUEUE_DIR = REPO_ROOT / "local_demo_data" / "escalations"

SOC_TICKET_COLUMNS = frozenset(
    {
        "ticket_id",
        "created_at",
        "user_id",
        "device_id",
        "source_ip",
        "threat_score",
        "severity",
        "status",
        "agent_decision",
        "agent_reason",
        "mitre_tactics",
        "indicators_of_compromise",
        "screenshot_url",
        "structured_report",
        "human_decision",
        "human_comment",
        "adjudicated_at",
    }
)
SOC_TICKET_REQUIRED_STRINGS = (
    "ticket_id",
    "created_at",
    "user_id",
    "device_id",
    "source_ip",
    "severity",
    "status",
    "agent_decision",
    "agent_reason",
    "structured_report",
)


class TicketPersistenceError(RuntimeError):
    """A ticket could not be written to its system of record."""


class SocTicketingService:
    def __init__(
        self,
        project_id: str | None = None,
        dataset_id: str = "Cymbal_Cyber",
        escalation_bucket: str | None = None,
        webhook_url: str | None = None,
    ):
        self.project_id = project_id or os.getenv("GOOGLE_CLOUD_PROJECT", "local-demo")
        self.dataset_id = dataset_id
        self.escalation_bucket_name = escalation_bucket or os.getenv(
            "ESCALATION_BUCKET",
            f"cymbal-cyber-adk-escalations-bucket_{self.project_id}",
        )
        self.webhook_url = webhook_url or os.getenv("SOC_WEBHOOK_URL")

        self._bq_client = None
        self._storage_client = None

        os.makedirs(self.queue_dir, exist_ok=True)
        os.makedirs(self.history_dir, exist_ok=True)

    @property
    def queue_dir(self) -> str:
        """Local ticket queue: LOCAL_QUEUE_DIR, else the repo's, whatever the working dir."""
        d = os.getenv("LOCAL_QUEUE_DIR") or str(DEFAULT_QUEUE_DIR)
        os.makedirs(d, exist_ok=True)
        return d

    @property
    def history_dir(self) -> str:
        d = os.path.join(self.queue_dir, "history")
        os.makedirs(d, exist_ok=True)
        return d

    # Clients use Application Default Credentials: the service's SA in the cloud and
    # `gcloud auth application-default login` on a workstation.
    @property
    def bq_client(self):
        if self._bq_client is None:
            if self._local_mode():
                return None
            try:
                from google.cloud import bigquery

                self._bq_client = bigquery.Client(project=self.project_id)
            except Exception as e:
                logger.warning("BigQuery client unavailable: %s", e)
        return self._bq_client

    @property
    def storage_client(self):
        if self._storage_client is None:
            if self._local_mode():
                return None
            try:
                from google.cloud import storage

                self._storage_client = storage.Client(project=self.project_id)
            except Exception as e:
                logger.warning("Cloud Storage client unavailable: %s", e)
        return self._storage_client

    def is_cloud_enabled(self) -> bool:
        """Determines if GCP BigQuery or Cloud Storage is actively accessible."""
        if os.getenv("LOCAL_MODE", "false").lower() == "true":
            return False
        if self.bq_client is not None:
            return True
        if self.storage_client is not None:
            try:
                self.storage_client.bucket(self.escalation_bucket_name)
                return True
            except Exception:
                pass
        return False

    @staticmethod
    def _local_mode() -> bool:
        return os.getenv("LOCAL_MODE", "false").lower() == "true"

    @staticmethod
    def _soc_tickets_row(ticket_data: dict[str, Any]) -> dict[str, Any]:
        """Projects a ticket dict onto the soc_tickets columns, filling REQUIRED ones."""
        row = {k: v for k, v in ticket_data.items() if k in SOC_TICKET_COLUMNS}
        for list_col in ("mitre_tactics", "indicators_of_compromise"):
            if not isinstance(row.get(list_col), list):
                row[list_col] = []
        for req_str in SOC_TICKET_REQUIRED_STRINGS:
            if row.get(req_str) is None:
                row[req_str] = ""
        return row

    def _assessment_row(self, ticket: SocTicket, **overrides: Any) -> dict[str, Any]:
        row = {
            "transaction_window_end": ticket.transaction_window_end
            or datetime.now(UTC).isoformat(),
            "user_id": ticket.user_id,
            "device_id": ticket.device_id,
            "source_ip": ticket.source_ip,
            "total_2_min_threat_score": ticket.threat_score,
            "agent_decision": ticket.agent_decision or "GENUINE_THREAT",
            "agent_reason": ticket.agent_reason,
            "human_decision": None,
            "human_reason": None,
            "alert_payload": json.dumps(ticket.model_dump()),
        }
        row.update(overrides)
        return row

    def _insert_required(self, table: str, row: dict[str, Any], ticket_id: str) -> None:
        """Streams one row into BigQuery; raises TicketPersistenceError on any failure."""
        table_id = f"{self.project_id}.{self.dataset_id}.{table}"
        if self.bq_client is None:
            raise TicketPersistenceError(
                f"Ticket {ticket_id} not stored: no BigQuery client for {table_id}."
            )
        try:
            errors = self.bq_client.insert_rows_json(
                table_id, [row], ignore_unknown_values=True
            )
        except Exception as e:
            raise TicketPersistenceError(
                f"Ticket {ticket_id} not stored in {table_id}: {e}"
            ) from e
        if errors:
            raise TicketPersistenceError(
                f"Ticket {ticket_id} not stored in {table_id}: {errors}"
            )
        logger.info("Persisted ticket %s to %s", ticket_id, table_id)

    def _write_local_json(self, path: str, payload: dict[str, Any]) -> None:
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2)
        except OSError as e:
            raise TicketPersistenceError(
                f"Ticket {payload.get('ticket_id')} not stored at {path}: {e}"
            ) from e

    def create_and_dispatch_ticket(self, ticket: SocTicket) -> str:
        """
        Ingests and dispatches a new incident ticket to the SOC ticketing system.

        Fails closed: raises TicketPersistenceError unless the ticket reached its system
        of record (BigQuery soc_tickets and adk_threat_assessment in the cloud, the local
        file queue in LOCAL_MODE), so callers never report a lost ticket as dispatched.
        The GCS escalation copy is best effort. Writing the same ticket_id again
        overwrites the GCS and local copies, and readers deduplicate BigQuery rows.
        """
        logger.info("Passing ticket %s to SOC ticketing system...", ticket.ticket_id)
        payload = ticket.model_dump()
        filename = f"human_escalation_information_{ticket.ticket_id}.json"

        if self._local_mode():
            self._write_local_json(os.path.join(self.queue_dir, filename), payload)
            return f"Successfully dispatched ticket {ticket.ticket_id} to SOC ticketing system with severity {ticket.severity}."

        # BigQuery is the system of record; a failure here must not look like success.
        self._insert_required(
            "soc_tickets", self._soc_tickets_row(payload), ticket.ticket_id
        )
        self._insert_required(
            "adk_threat_assessment", self._assessment_row(ticket), ticket.ticket_id
        )

        if self.storage_client is not None:
            try:
                bucket = self.storage_client.bucket(self.escalation_bucket_name)
                bucket.blob(filename).upload_from_string(
                    json.dumps(payload, indent=2), content_type="application/json"
                )
                logger.info(
                    "Uploaded ticket %s to gs://%s/%s",
                    ticket.ticket_id,
                    self.escalation_bucket_name,
                    filename,
                )
            except Exception as e:
                logger.warning("Could not upload ticket copy to GCS: %s", e)

        return f"Successfully dispatched ticket {ticket.ticket_id} to SOC ticketing system with severity {ticket.severity}."

    def record_auto_closed_false_positive(self, ticket: SocTicket) -> str:
        """
        Archives an alert the agent closed as false positive on its own.

        The ticket is stored as RESOLVED with no analyst verdict, so it shows up in the
        archive (and not in the triage queue) where analysts can review the closure.
        Fails closed like create_and_dispatch_ticket.
        """
        now_iso = datetime.now(UTC).isoformat()
        ticket = ticket.model_copy(
            update={
                "status": "RESOLVED",
                "agent_decision": AUTO_CLOSED_FP_DECISION,
                "adjudicated_at": ticket.adjudicated_at or now_iso,
            }
        )
        payload = ticket.model_dump()

        if self._local_mode():
            self._write_local_json(
                os.path.join(self.history_dir, f"resolved_{ticket.ticket_id}.json"),
                payload,
            )
        else:
            self._insert_required(
                "soc_tickets", self._soc_tickets_row(payload), ticket.ticket_id
            )
            self._insert_required(
                "adk_threat_assessment",
                self._assessment_row(ticket, agent_decision="FALSE_POSITIVE"),
                ticket.ticket_id,
            )
        logger.info("Archived auto-closed false positive %s", ticket.ticket_id)
        return f"Archived ticket {ticket.ticket_id} as a false positive closed by the agent."

    def fetch_new_tickets(self) -> list[dict[str, Any]]:
        """
        Retrieves all active, pending incident tickets awaiting analyst review.
        Queries BigQuery Cymbal_Cyber.soc_tickets as the Single Source of Truth.
        Uses CTE deduplication to reliably reflect the latest state even with streaming buffers.
        Falls back to local file queue only if BigQuery is unavailable (local mode).
        """
        tickets: list[dict[str, Any]] = []

        if self.bq_client is not None:
            try:
                query = f"""
                WITH deduplicated_tickets AS (
                  SELECT * EXCEPT(rn) FROM (
                    SELECT *,
                      ROW_NUMBER() OVER (
                        PARTITION BY ticket_id
                        ORDER BY
                          CASE WHEN human_decision IS NOT NULL AND human_decision != '' THEN 1 ELSE 2 END,
                          COALESCE(adjudicated_at, created_at) DESC
                      ) AS rn
                    FROM `{self.project_id}.{self.dataset_id}.soc_tickets`
                  )
                  WHERE rn = 1
                )
                SELECT
                  ticket_id,
                  created_at,
                  user_id,
                  device_id,
                  source_ip,
                  threat_score,
                  severity,
                  status,
                  agent_decision,
                  agent_reason,
                  mitre_tactics,
                  indicators_of_compromise,
                  screenshot_url,
                  structured_report,
                  human_decision,
                  human_comment,
                  adjudicated_at
                FROM deduplicated_tickets
                WHERE (status IN ('OPEN', 'ESCALATED', 'UNDER_INVESTIGATION') OR status IS NULL)
                  AND (human_decision IS NULL OR human_decision = '')
                ORDER BY created_at DESC
                LIMIT 100
                """
                results = list(self.bq_client.query(query).result())
                tickets = [dict(row.items()) for row in results]
            except Exception as e:
                logger.warning("BigQuery fetch_new_tickets query failed: %s", e)

        # Reconcile GCS escalation files if cloud storage is enabled (Self-Healing Sync)
        if self.is_cloud_enabled() and self.storage_client is not None:
            try:
                bucket = self.storage_client.bucket(self.escalation_bucket_name)
                bq_ticket_ids = {
                    t.get("ticket_id") for t in tickets if t.get("ticket_id")
                }
                for blob in bucket.list_blobs(prefix="human_escalation_information_"):
                    if blob.name.endswith(".json"):
                        try:
                            gcs_ticket = json.loads(blob.download_as_text())
                            tid = gcs_ticket.get("ticket_id")
                            if tid and tid not in bq_ticket_ids:
                                tickets.append(gcs_ticket)
                                bq_ticket_ids.add(tid)
                                self._backfill_ticket_to_bq(gcs_ticket)
                        except Exception as parse_err:
                            logger.debug(
                                "Failed parsing GCS blob %s: %s", blob.name, parse_err
                            )
            except Exception as gcs_err:
                logger.debug("GCS escalation bucket sync check skipped: %s", gcs_err)

        if not tickets:
            # Fallback to local queue if no tickets retrieved from BQ or GCS
            for path in glob.glob(
                os.path.join(self.queue_dir, "human_escalation_information_*.json")
            ):
                try:
                    with open(path, encoding="utf-8") as f:
                        tickets.append(json.load(f))
                except Exception:
                    pass

        # Sort newest first
        tickets.sort(
            key=lambda x: str(x.get("created_at") or x.get("timestamp") or ""),
            reverse=True,
        )
        return tickets

    def _backfill_ticket_to_bq(self, ticket_data: dict[str, Any]) -> None:
        """Self-healing backfill of GCS escalation ticket into BigQuery soc_tickets."""
        if self.bq_client is None:
            return
        try:
            soc_table_id = f"{self.project_id}.{self.dataset_id}.soc_tickets"
            soc_row = self._soc_tickets_row(ticket_data)

            errors = self.bq_client.insert_rows_json(
                soc_table_id, [soc_row], ignore_unknown_values=True
            )
            if errors:
                logger.warning(
                    "BigQuery backfill errors for %s: %s",
                    ticket_data.get("ticket_id"),
                    errors,
                )
            else:
                logger.info(
                    "Successfully self-healed and backfilled ticket %s into BigQuery",
                    ticket_data.get("ticket_id"),
                )
        except Exception as e:
            logger.warning(
                "Failed self-healing backfill of ticket %s to BigQuery: %s",
                ticket_data.get("ticket_id"),
                e,
            )

    def record_human_verdict(
        self, ticket_id: str, human_decision: str, human_comment: str
    ) -> bool:
        """
        Records human analyst adjudication:
        - Resolves ticket as GENUINE_THREAT or FALSE_POSITIVE in BigQuery
        - Updates adk_threat_assessment table with human decision
        - Handles BigQuery streaming buffer with append-resolution
        - Archives ticket into historical store
        - Removes from active escalation queue
        """
        logger.info(
            "Recording analyst verdict for ticket %s: %s", ticket_id, human_decision
        )
        now_iso = datetime.now(UTC).isoformat()

        # Find existing ticket locally, in GCS, or in BigQuery
        ticket_data = None
        active_local_path = os.path.join(
            self.queue_dir, f"human_escalation_information_{ticket_id}.json"
        )

        if os.path.exists(active_local_path):
            try:
                with open(active_local_path, encoding="utf-8") as f:
                    ticket_data = json.load(f)
            except Exception:
                pass

        if (
            not ticket_data
            and self.is_cloud_enabled()
            and self.storage_client is not None
        ):
            try:
                bucket = self.storage_client.bucket(self.escalation_bucket_name)
                blob = bucket.blob(f"human_escalation_information_{ticket_id}.json")
                if blob.exists():
                    ticket_data = json.loads(blob.download_as_text())
            except Exception:
                pass

        if not ticket_data and self.bq_client is not None:
            try:
                query = f"""
                SELECT * FROM `{self.project_id}.{self.dataset_id}.soc_tickets`
                WHERE ticket_id = @ticket_id LIMIT 1
                """
                from google.cloud import bigquery

                cfg = bigquery.QueryJobConfig(
                    query_parameters=[
                        bigquery.ScalarQueryParameter("ticket_id", "STRING", ticket_id)
                    ]
                )
                b_rows = list(self.bq_client.query(query, job_config=cfg).result())
                if b_rows:
                    ticket_data = dict(b_rows[0].items())
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
                "structured_report": "Incident escalated.",
            }

        # Update resolution metadata
        ticket_data["status"] = "RESOLVED"
        ticket_data["human_decision"] = human_decision
        ticket_data["human_comment"] = human_comment
        ticket_data["adjudicated_at"] = now_iso

        # 1. Save to Local History Archive
        os.makedirs(self.history_dir, exist_ok=True)
        hist_local_path = os.path.join(self.history_dir, f"resolved_{ticket_id}.json")
        try:
            with open(hist_local_path, "w", encoding="utf-8") as f:
                json.dump(ticket_data, f, indent=2)
        except Exception:
            pass

        # 2. Remove active local request file
        if os.path.exists(active_local_path):
            try:
                os.remove(active_local_path)
            except Exception:
                pass

        # 3. Cloud Storage update
        if self.is_cloud_enabled() and self.storage_client is not None:
            try:
                bucket = self.storage_client.bucket(self.escalation_bucket_name)
                resp_blob = bucket.blob(f"human_escalation_response_{ticket_id}.json")
                resp_payload = {
                    "ticket_id": ticket_id,
                    "human_decision": human_decision,
                    "human_comment": human_comment,
                    "timestamp": time.time(),
                }
                resp_blob.upload_from_string(
                    json.dumps(resp_payload, indent=2), content_type="application/json"
                )

                hist_blob = bucket.blob(f"history/resolved_{ticket_id}.json")
                hist_blob.upload_from_string(
                    json.dumps(ticket_data, indent=2), content_type="application/json"
                )

                req_blob = bucket.blob(f"human_escalation_information_{ticket_id}.json")
                if req_blob.exists():
                    req_blob.delete()
            except Exception as e:
                logger.warning("Cloud verdict sync warning: %s", e)

        # 4. BigQuery Update via Immutable Event-Sourcing (Single Source of Truth)
        # Note: BigQuery prohibits DML UPDATE/DELETE statements over rows in an active streaming buffer.
        # We append the resolved state row directly using insert_rows_json. Deduplicating readers
        # (fetch_historic_tickets, fetch_new_tickets, fetch_dashboard_metrics) dynamically pick
        # the latest adjudicated row via ROW_NUMBER() windowing with zero streaming buffer errors.
        if self.bq_client is not None and ticket_data:
            try:
                soc_table_id = f"{self.project_id}.{self.dataset_id}.soc_tickets"
                resolved_row = self._soc_tickets_row(ticket_data)
                resolved_row["status"] = "RESOLVED"
                resolved_row["human_decision"] = human_decision
                resolved_row["human_comment"] = human_comment
                resolved_row["adjudicated_at"] = now_iso

                self.bq_client.insert_rows_json(
                    soc_table_id, [resolved_row], ignore_unknown_values=True
                )
                logger.info(
                    "Inserted resolved state row for %s into BigQuery soc_tickets",
                    ticket_id,
                )
            except Exception as ins_err:
                logger.warning(
                    "Could not append resolved state row into BigQuery: %s", ins_err
                )

            # Similarly append resolved assessment to adk_threat_assessment
            try:
                assessment_table_id = (
                    f"{self.project_id}.{self.dataset_id}.adk_threat_assessment"
                )
                assessment_row = {
                    "transaction_window_end": ticket_data.get("transaction_window_end")
                    or now_iso,
                    "user_id": ticket_data.get("user_id"),
                    "device_id": ticket_data.get("device_id"),
                    "source_ip": ticket_data.get("source_ip"),
                    "total_2_min_threat_score": ticket_data.get("threat_score") or 0,
                    "agent_decision": ticket_data.get("agent_decision")
                    or "GENUINE_THREAT",
                    "agent_reason": ticket_data.get("agent_reason"),
                    "human_decision": human_decision,
                    "human_reason": human_comment,
                    "alert_payload": json.dumps(ticket_data),
                }
                self.bq_client.insert_rows_json(
                    assessment_table_id, [assessment_row], ignore_unknown_values=True
                )
                logger.info(
                    "Appended resolved assessment for %s into BigQuery adk_threat_assessment",
                    ticket_data.get("user_id"),
                )
            except Exception as assess_err:
                logger.debug("adk_threat_assessment append notice: %s", assess_err)

        return True

    def fetch_historic_tickets(self) -> list[dict[str, Any]]:
        """
        Retrieves all archived and historical tickets (Approved Threats and False Positives).
        Queries BigQuery Cymbal_Cyber.soc_tickets as the Single Source of Truth.
        Uses CTE deduplication to reliably reflect the latest state even with streaming buffers.
        Falls back to local history files only if BigQuery is unavailable (local mode).
        """
        historic: list[dict[str, Any]] = []

        if self.bq_client is not None:
            try:
                query = f"""
                WITH deduplicated_tickets AS (
                  SELECT * EXCEPT(rn) FROM (
                    SELECT *,
                      ROW_NUMBER() OVER (
                        PARTITION BY ticket_id
                        ORDER BY
                          CASE WHEN human_decision IS NOT NULL AND human_decision != '' THEN 1 ELSE 2 END,
                          COALESCE(adjudicated_at, created_at) DESC
                      ) AS rn
                    FROM `{self.project_id}.{self.dataset_id}.soc_tickets`
                  )
                  WHERE rn = 1
                )
                SELECT
                  ticket_id,
                  created_at,
                  user_id,
                  device_id,
                  source_ip,
                  threat_score,
                  severity,
                  status,
                  agent_decision,
                  agent_reason,
                  mitre_tactics,
                  indicators_of_compromise,
                  screenshot_url,
                  structured_report,
                  human_decision,
                  human_comment,
                  adjudicated_at
                FROM deduplicated_tickets
                WHERE status = 'RESOLVED' OR (human_decision IS NOT NULL AND human_decision != '')
                ORDER BY adjudicated_at DESC, created_at DESC
                LIMIT 200
                """
                results = list(self.bq_client.query(query).result())
                return [dict(row.items()) for row in results]
            except Exception as e:
                logger.warning("BigQuery fetch_historic_tickets failed: %s", e)

        # Fallback to Local History Files
        for path in glob.glob(os.path.join(self.history_dir, "resolved_*.json")):
            try:
                with open(path, encoding="utf-8") as f:
                    historic.append(json.load(f))
            except Exception:
                pass

        if len(historic) < 5:
            # Sample history so a fresh local console is not empty. It is marked
            # SIMULATED (badge, left out of every KPI) and never written to disk.
            historic.extend(self._generate_seed_history())

        historic.sort(
            key=lambda x: x.get("adjudicated_at") or x.get("created_at") or "",
            reverse=True,
        )
        return historic

    def _build_time_clauses(self, time_range: str) -> tuple[str, str, str, str]:
        """
        Builds WHERE clauses for each table based on the selected time range.
        Returns: (access_clause, net_clause, alert_clause, ticket_clause)
        """
        interval_map = {
            "Last 24 Hours": ("INTERVAL 24 HOUR", 1),
            "Last 7 Days": ("INTERVAL 7 DAY", 7),
            "Last 30 Days": ("INTERVAL 30 DAY", 30),
            "Last 90 Days": ("INTERVAL 90 DAY", 90),
        }
        if time_range not in interval_map:
            return ("", "", "", "")

        interval_sql, days = interval_map[time_range]
        access_clause = (
            f"WHERE DATE(event_timestamp) >= DATE_SUB(CURRENT_DATE(), INTERVAL {days} DAY) "
            f"AND event_timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), {interval_sql})"
        )
        net_clause = (
            f"WHERE DATE(event_timestamp) >= DATE_SUB(CURRENT_DATE(), INTERVAL {days} DAY) "
            f"AND event_timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), {interval_sql})"
        )
        alert_clause = (
            f"WHERE DATE(window_end) >= DATE_SUB(CURRENT_DATE(), INTERVAL {days} DAY) "
            f"AND window_end >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), {interval_sql})"
        )
        ticket_clause = (
            f"WHERE SAFE.PARSE_TIMESTAMP('%Y-%m-%dT%H:%M:%E*S%Ez', created_at) >= "
            f"TIMESTAMP_SUB(CURRENT_TIMESTAMP(), {interval_sql})"
        )
        return (access_clause, net_clause, alert_clause, ticket_clause)

    def fetch_dashboard_metrics(self, time_range: str = "All Time") -> dict[str, Any]:
        """
        Dynamically calculates all SOC dashboard metrics directly from BigQuery tables.
        Provides clean fallback / zero counts when tables are empty.
        Uses CTE deduplication on soc_tickets so metrics always reflect the latest state,
        and leaves out simulated tickets written by the console's demo controls.
        """
        metrics: dict[str, Any] = {
            "monitored_devices": 0,
            "monitored_endpoints": 0,
            "monitored_users": 0,
            "processed_logs": 0,
            "security_events": 0,
            "triaged_alerts": 0,
            "escalated_alerts": 0,
            "auto_closed_alerts": 0,
            "alerts_by_severity": [],
            "alerts_by_status": [],
            "alerts_by_sla": [],
            "alerts_by_category": [],
            "log_rate_trend": [],
            "log_breakdown": [],
            "threat_trend": [],
            "threat_points": [],
        }

        if self.bq_client is None:
            new_t = [
                t
                for t in self.fetch_new_tickets()
                if t.get("agent_decision") != SIMULATED_DECISION
            ]
            hist_t = [
                t
                for t in self.fetch_historic_tickets()
                if t.get("agent_decision") != SIMULATED_DECISION
            ]
            metrics["escalated_alerts"] = len(new_t)
            metrics["triaged_alerts"] = len(hist_t)
            metrics["auto_closed_alerts"] = sum(
                1 for t in hist_t if t.get("agent_decision") == AUTO_CLOSED_FP_DECISION
            )
            return metrics

        access_where, net_where, alert_where, ticket_where = self._build_time_clauses(
            time_range
        )

        # 1. Summary KPIs
        try:
            summary_sql = f"""
            WITH deduplicated_tickets AS (
              SELECT * EXCEPT(rn) FROM (
                SELECT *,
                  ROW_NUMBER() OVER (
                    PARTITION BY ticket_id
                    ORDER BY
                      CASE WHEN human_decision IS NOT NULL AND human_decision != '' THEN 1 ELSE 2 END,
                      COALESCE(adjudicated_at, created_at) DESC
                  ) AS rn
                FROM `{self.project_id}.{self.dataset_id}.soc_tickets`
              )
              WHERE rn = 1
                AND COALESCE(agent_decision, '') != '{SIMULATED_DECISION}'
            ),
            access_stats AS (
              SELECT
                COUNT(*) AS total_access_logs,
                COUNT(DISTINCT user_id) AS distinct_users,
                COUNT(DISTINCT device_id) AS distinct_devices,
                COUNT(DISTINCT assigned_internal_ip) AS distinct_endpoints
              FROM `{self.project_id}.{self.dataset_id}.user_access_events`
              {access_where}
            ),
            network_stats AS (
              SELECT
                COUNT(*) AS total_net_logs
              FROM `{self.project_id}.{self.dataset_id}.network_events`
              {net_where}
            ),
            alert_stats AS (
              SELECT
                COUNT(*) AS total_security_events
              FROM `{self.project_id}.{self.dataset_id}.alerts`
              {alert_where}
            ),
            ticket_stats AS (
              SELECT
                COUNT(*) AS total_tickets,
                COUNTIF(status = 'RESOLVED' OR (human_decision IS NOT NULL AND human_decision != '')) AS triaged_alerts,
                COUNTIF(status IN ('OPEN', 'ESCALATED', 'UNDER_INVESTIGATION') AND (human_decision IS NULL OR human_decision = '')) AS escalated_alerts,
                COUNTIF(agent_decision = '{AUTO_CLOSED_FP_DECISION}') AS auto_closed_alerts
              FROM deduplicated_tickets
              {ticket_where}
            )
            SELECT *
            FROM access_stats
            CROSS JOIN network_stats
            CROSS JOIN alert_stats
            CROSS JOIN ticket_stats;
            """
            rows = list(self.bq_client.query(summary_sql).result())
            if rows:
                r = rows[0]
                total_access = r.get("total_access_logs") or 0
                total_net = r.get("total_net_logs") or 0
                metrics["processed_logs"] = total_access + total_net
                metrics["monitored_users"] = r.get("distinct_users") or 0
                metrics["monitored_devices"] = r.get("distinct_devices") or 0
                metrics["monitored_endpoints"] = r.get("distinct_endpoints") or 0
                metrics["security_events"] = r.get("total_security_events") or 0
                metrics["triaged_alerts"] = r.get("triaged_alerts") or 0
                metrics["escalated_alerts"] = r.get("escalated_alerts") or 0
                metrics["auto_closed_alerts"] = r.get("auto_closed_alerts") or 0
        except Exception as e:
            logger.warning("Error querying summary KPIs: %s", e)

        # 2. Alerts by Severity
        try:
            sev_sql = f"""
            WITH deduplicated_tickets AS (
              SELECT * EXCEPT(rn) FROM (
                SELECT *,
                  ROW_NUMBER() OVER (
                    PARTITION BY ticket_id
                    ORDER BY
                      CASE WHEN human_decision IS NOT NULL AND human_decision != '' THEN 1 ELSE 2 END,
                      COALESCE(adjudicated_at, created_at) DESC
                  ) AS rn
                FROM `{self.project_id}.{self.dataset_id}.soc_tickets`
              )
              WHERE rn = 1
                AND COALESCE(agent_decision, '') != '{SIMULATED_DECISION}'
            )
            SELECT
              INITCAP(severity) AS severity,
              COUNT(*) AS count
            FROM deduplicated_tickets
            {ticket_where}
            GROUP BY severity
            """
            metrics["alerts_by_severity"] = [
                dict(row.items()) for row in self.bq_client.query(sev_sql).result()
            ]
        except Exception as e:
            logger.warning("Error querying alerts by severity: %s", e)

        # 3. Alerts by Status
        try:
            stat_sql = f"""
            WITH deduplicated_tickets AS (
              SELECT * EXCEPT(rn) FROM (
                SELECT *,
                  ROW_NUMBER() OVER (
                    PARTITION BY ticket_id
                    ORDER BY
                      CASE WHEN human_decision IS NOT NULL AND human_decision != '' THEN 1 ELSE 2 END,
                      COALESCE(adjudicated_at, created_at) DESC
                  ) AS rn
                FROM `{self.project_id}.{self.dataset_id}.soc_tickets`
              )
              WHERE rn = 1
                AND COALESCE(agent_decision, '') != '{SIMULATED_DECISION}'
            )
            SELECT
              CASE
                WHEN status IN ('OPEN', 'ESCALATED', 'UNDER_INVESTIGATION') AND (human_decision IS NULL OR human_decision = '') THEN 'Open'
                WHEN status = 'RESOLVED' AND human_decision = 'Genuine Threat' THEN 'Escalated'
                WHEN status = 'RESOLVED' THEN 'Closed'
                ELSE 'In Progress'
              END AS status,
              COUNT(*) AS count
            FROM deduplicated_tickets
            {ticket_where}
            GROUP BY status
            """
            metrics["alerts_by_status"] = [
                dict(row.items()) for row in self.bq_client.query(stat_sql).result()
            ]
        except Exception as e:
            logger.warning("Error querying alerts by status: %s", e)

        # 4. Alerts by SLA
        try:
            sla_sql = f"""
            WITH deduplicated_tickets AS (
              SELECT * EXCEPT(rn) FROM (
                SELECT *,
                  ROW_NUMBER() OVER (
                    PARTITION BY ticket_id
                    ORDER BY
                      CASE WHEN human_decision IS NOT NULL AND human_decision != '' THEN 1 ELSE 2 END,
                      COALESCE(adjudicated_at, created_at) DESC
                  ) AS rn
                FROM `{self.project_id}.{self.dataset_id}.soc_tickets`
              )
              WHERE rn = 1
                AND COALESCE(agent_decision, '') != '{SIMULATED_DECISION}'
            )
            SELECT
              CASE
                WHEN status = 'RESOLVED' THEN 'Within SLA'
                WHEN TIMESTAMP_DIFF(CURRENT_TIMESTAMP(), SAFE.PARSE_TIMESTAMP('%Y-%m-%dT%H:%M:%E*S%Ez', created_at), MINUTE) > 60 THEN 'Breached SLA'
                WHEN TIMESTAMP_DIFF(CURRENT_TIMESTAMP(), SAFE.PARSE_TIMESTAMP('%Y-%m-%dT%H:%M:%E*S%Ez', created_at), MINUTE) > 30 THEN 'Approaching SLA'
                ELSE 'Within SLA'
              END AS sla,
              COUNT(*) AS count
            FROM deduplicated_tickets
            {ticket_where}
            GROUP BY sla
            """
            metrics["alerts_by_sla"] = [
                dict(row.items()) for row in self.bq_client.query(sla_sql).result()
            ]
        except Exception as e:
            logger.warning("Error querying alerts by SLA: %s", e)

        # 5. Alerts by Category (MITRE tactics)
        try:
            cat_sql = f"""
            WITH deduplicated_tickets AS (
              SELECT * EXCEPT(rn) FROM (
                SELECT *,
                  ROW_NUMBER() OVER (
                    PARTITION BY ticket_id
                    ORDER BY
                      CASE WHEN human_decision IS NOT NULL AND human_decision != '' THEN 1 ELSE 2 END,
                      COALESCE(adjudicated_at, created_at) DESC
                  ) AS rn
                FROM `{self.project_id}.{self.dataset_id}.soc_tickets`
              )
              WHERE rn = 1
                AND COALESCE(agent_decision, '') != '{SIMULATED_DECISION}'
            )
            SELECT
              tactic AS category,
              COUNT(*) AS count
            FROM deduplicated_tickets,
            UNNEST(mitre_tactics) AS tactic
            {ticket_where}
            GROUP BY category
            ORDER BY count DESC
            LIMIT 6
            """
            metrics["alerts_by_category"] = [
                dict(row.items()) for row in self.bq_client.query(cat_sql).result()
            ]
        except Exception as e:
            logger.warning("Error querying alerts by category: %s", e)

        # 6. Log Rate Trend
        try:
            rate_sql = f"""
            SELECT
              FORMAT_DATE('%m/%d', DATE(event_timestamp)) AS date,
              COUNT(*) AS count
            FROM (
              SELECT event_timestamp FROM `{self.project_id}.{self.dataset_id}.user_access_events`
              {access_where}
              UNION ALL
              SELECT event_timestamp FROM `{self.project_id}.{self.dataset_id}.network_events`
              {net_where}
            )
            GROUP BY date
            ORDER BY date ASC
            LIMIT 7
            """
            rate_rows = [
                dict(row.items()) for row in self.bq_client.query(rate_sql).result()
            ]
            metrics["log_rate_trend"] = [
                {
                    "date": r["date"],
                    "rate": round(r["count"] / 86400.0, 2) if r.get("count") else 0.0,
                }
                for r in rate_rows
            ]
        except Exception as e:
            logger.warning("Error querying log rate trend: %s", e)

        # 7. Log Collection Breakdown
        try:
            breakdown_sql = f"""
            SELECT
              FORMAT_DATE('%m/%d', DATE(event_timestamp)) AS date,
              event_type AS type,
              COUNT(*) AS volume
            FROM (
              SELECT event_timestamp, event_type FROM `{self.project_id}.{self.dataset_id}.user_access_events`
              {access_where}
              UNION ALL
              SELECT event_timestamp, event_type FROM `{self.project_id}.{self.dataset_id}.network_events`
              {net_where}
            )
            GROUP BY date, type
            ORDER BY date ASC
            LIMIT 25
            """
            metrics["log_breakdown"] = [
                dict(row.items())
                for row in self.bq_client.query(breakdown_sql).result()
            ]
        except Exception as e:
            logger.warning("Error querying log breakdown: %s", e)

        # 8. Threat Detection Trend
        try:
            trend_sql = f"""
            SELECT
              FORMAT_DATE('%m/%d', DATE(window_end)) AS date,
              COUNT(*) AS count
            FROM `{self.project_id}.{self.dataset_id}.alerts`
            {alert_where}
            GROUP BY date
            ORDER BY date ASC
            LIMIT 7
            """
            trend_rows = [
                dict(row.items()) for row in self.bq_client.query(trend_sql).result()
            ]
            metrics["threat_trend"] = [
                {"date": r["date"], "metric": "Security Events", "count": r["count"]}
                for r in trend_rows
            ]
        except Exception as e:
            logger.warning("Error querying threat trend: %s", e)

        # 9. Geographical Threat Origins (Threat Points)
        try:
            map_sql = f"""
            WITH deduplicated_tickets AS (
              SELECT * EXCEPT(rn) FROM (
                SELECT *,
                  ROW_NUMBER() OVER (
                    PARTITION BY ticket_id
                    ORDER BY
                      CASE WHEN human_decision IS NOT NULL AND human_decision != '' THEN 1 ELSE 2 END,
                      COALESCE(adjudicated_at, created_at) DESC
                  ) AS rn
                FROM `{self.project_id}.{self.dataset_id}.soc_tickets`
              )
              WHERE rn = 1
                AND COALESCE(agent_decision, '') != '{SIMULATED_DECISION}'
            )
            SELECT
              user_id,
              source_ip,
              threat_score,
              severity,
              agent_reason
            FROM deduplicated_tickets
            {ticket_where}
            ORDER BY created_at DESC
            LIMIT 50
            """
            map_rows = [
                dict(row.items()) for row in self.bq_client.query(map_sql).result()
            ]
            points = []
            for r in map_rows:
                ip = r.get("source_ip", "")
                geo = self._resolve_ip_geo(ip, r.get("user_id", ""))
                points.append(
                    {
                        "name": f"{r.get('user_id')} ({geo['country']})",
                        "lat": geo["lat"],
                        "lon": geo["lon"],
                        "threat": str(r.get("agent_reason", "Perceived Threat"))[:60],
                        "score": r.get("threat_score", 100),
                        "color": [244, 67, 54, 220]
                        if r.get("severity") == "CRITICAL"
                        else [255, 152, 0, 200],
                    }
                )
            metrics["threat_points"] = points
        except Exception as e:
            logger.warning("Error querying threat points: %s", e)

        return metrics

    @staticmethod
    def _resolve_ip_geo(ip: str, user_id: str) -> dict[str, Any]:
        """Maps IP or user scenario to known geographic coordinates."""
        known_geos = {
            "175.45.176.10": {
                "country": "North Korea",
                "lat": 39.0392,
                "lon": 125.7625,
            },
            "175.45.177.32": {
                "country": "North Korea",
                "lat": 39.0392,
                "lon": 125.7625,
            },
            "194.26.135.68": {"country": "Russia", "lat": 55.7558, "lon": 37.6173},
            "185.220.101.5": {"country": "Germany", "lat": 52.5200, "lon": 13.4050},
            "74.125.70.93": {
                "country": "United States",
                "lat": 37.7749,
                "lon": -122.4194,
            },
            "74.125.10.15": {
                "country": "United States",
                "lat": 40.7128,
                "lon": -74.0060,
            },
        }
        if ip in known_geos:
            return known_geos[ip]
        if "u.lewis" in user_id or "g.harris" in user_id:
            return {"country": "North Korea", "lat": 39.0392, "lon": 125.7625}
        if "r.patel" in user_id:
            return {"country": "Russia", "lat": 55.7558, "lon": 37.6173}
        if "contractor" in user_id:
            return {"country": "Germany", "lat": 52.5200, "lon": 13.4050}
        return {"country": "External Origin", "lat": 20.0, "lon": 0.0}

    def _generate_seed_history(self) -> list[dict[str, Any]]:
        """Sample adjudicated tickets for an empty local archive, marked SIMULATED."""
        now = datetime.now(UTC)
        screenshots_dir = str(SCREENSHOTS_DIR)
        samples = [
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
                "adjudicated_at": (now - timedelta(days=2, hours=2)).isoformat(),
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
                "adjudicated_at": (
                    now - timedelta(days=3, hours=4, minutes=40)
                ).isoformat(),
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
                "indicators_of_compromise": [
                    "194.26.135.68",
                    "my-payload-downloader.ru",
                ],
                "screenshot_url": f"{screenshots_dir}/r.patel.png",
                "structured_report": "### Security Incident Report\n* **User:** r.patel\n* **Origin:** Moscow, Russia\n* **Domain:** my-payload-downloader.ru",
                "human_decision": "Genuine Threat",
                "human_comment": "Blocked external IP at perimeter firewall. Domain sinkholed.",
                "adjudicated_at": (now - timedelta(days=4)).isoformat(),
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
                "adjudicated_at": (now - timedelta(days=6, hours=4)).isoformat(),
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
                "adjudicated_at": (now - timedelta(days=8, hours=1)).isoformat(),
            },
        ]
        for sample in samples:
            sample["ticket_id"] = sample["ticket_id"].replace(
                "SOC-TICKET-", "SIM-TICKET-", 1
            )
            sample["agent_decision"] = SIMULATED_DECISION
        return samples
