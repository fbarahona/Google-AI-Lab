"""
Analyst queue and archive reads, always through the soc_tickets_current view (the
latest state of each ticket), with local-file fallbacks for LOCAL_MODE.
"""

import glob
import json
import os
from typing import Any

from src.demo.soc_ticketing.service.schema import _row_dict, logger


class TicketQueriesMixin:
    """Read side of SocTicketingService: queue, archive, incident roll-up."""

    def fetch_new_tickets(self) -> list[dict[str, Any]]:
        """
        Retrieves all active, pending incident tickets awaiting analyst review.
        Queries BigQuery Cymbal_Cyber.soc_tickets as the Single Source of Truth.
        Reads soc_tickets_current, the latest state of each ticket.
        Falls back to local file queue only if BigQuery is unavailable (local mode).
        """
        tickets: list[dict[str, Any]] = []

        if self.bq_client is not None:
            try:
                query = f"""
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
                FROM `{self._current_tickets}`
                WHERE is_pending
                ORDER BY created_at DESC
                LIMIT 100
                """
                results = list(self.bq_client.query(query).result())
                tickets = [_row_dict(row) for row in results]
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
        if self.is_cloud_enabled():
            self._attach_incident_stats(tickets)
        return tickets

    def _attach_incident_stats(self, tickets: list[dict[str, Any]]) -> None:
        """
        Adds the incident roll-up (windows, total and peak score) to each ticket filed
        for a correlated incident. A ticket's ID ends in the first 10 hex characters of
        SHA-256(alert_id), and the published alert opens its incident (incident_id =
        alert_id), so tickets match incidents without storing the alert_id. Best
        effort: a ticket without a match keeps its window score only.
        """
        users = sorted({t["user_id"] for t in tickets if t.get("user_id")})
        if self.bq_client is None or not users:
            return
        try:
            from google.cloud import bigquery

            query = f"""
            SELECT
              SUBSTR(TO_HEX(SHA256(incident_id)), 1, 10) AS ticket_suffix,
              windows,
              total_threat_score,
              peak_window_score
            FROM `{self.project_id}.{self.dataset_id}.incidents`
            WHERE user_id IN UNNEST(@users)
            """
            cfg = bigquery.QueryJobConfig(
                query_parameters=[
                    bigquery.ArrayQueryParameter("users", "STRING", users)
                ]
            )
            stats = {
                row["ticket_suffix"]: _row_dict(row)
                for row in self.bq_client.query(query, job_config=cfg).result()
            }
        except Exception as e:
            logger.warning("Incident stats lookup failed: %s", e)
            return
        for ticket in tickets:
            suffix = str(ticket.get("ticket_id") or "").rsplit("-", 1)[-1]
            match = stats.get(suffix)
            if match:
                ticket["incident_windows"] = match["windows"]
                ticket["incident_total_score"] = match["total_threat_score"]
                ticket["incident_peak_score"] = match["peak_window_score"]

    def fetch_historic_tickets(self) -> list[dict[str, Any]]:
        """
        Retrieves all archived and historical tickets (Approved Threats and False Positives).
        Queries BigQuery Cymbal_Cyber.soc_tickets as the Single Source of Truth.
        Reads soc_tickets_current, the latest state of each ticket.
        Falls back to local history files only if BigQuery is unavailable (local mode).
        """
        historic: list[dict[str, Any]] = []

        if self.bq_client is not None:
            try:
                query = f"""
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
                FROM `{self._current_tickets}`
                WHERE status = 'RESOLVED' OR is_adjudicated
                ORDER BY adjudicated_at DESC, created_at DESC
                LIMIT 200
                """
                results = list(self.bq_client.query(query).result())
                historic = [_row_dict(row) for row in results]
                self._attach_incident_stats(historic)
                return historic
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
