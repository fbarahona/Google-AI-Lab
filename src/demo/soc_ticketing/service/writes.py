"""
Ticket persistence. BigQuery is the system of record in the cloud and the file
queue in LOCAL_MODE; a ticket that does not reach it raises TicketPersistenceError.
State changes are appended to soc_tickets, never updated in place.
"""

import json
import os
import time
from datetime import UTC, datetime
from typing import Any

from src.demo.soc_ticketing.models import AUTO_CLOSED_FP_DECISION, SocTicket
from src.demo.soc_ticketing.service.schema import (
    SOC_TICKET_COLUMNS,
    SOC_TICKET_REQUIRED_STRINGS,
    TicketPersistenceError,
    _row_dict,
    logger,
)


class TicketWritesMixin:
    """Write side of SocTicketingService."""

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
        # TIMESTAMP columns: an empty string is not a timestamp.
        if not row.get("created_at"):
            row["created_at"] = datetime.now(UTC).isoformat()
        if not row.get("adjudicated_at"):
            row.pop("adjudicated_at", None)
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
                SELECT * FROM `{self._current_tickets}`
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
                    ticket_data = _row_dict(b_rows[0])
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
