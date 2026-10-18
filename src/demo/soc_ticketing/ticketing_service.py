"""
SOC Ticketing Service
=====================
Manages the end-to-end incident ticketing lifecycle:
1. Passes validated security incident tickets to the active SOC ticketing queue.
2. Archives and queries historical tickets (approved genuine threats and dismissed false positives).
3. Persists ticket state across BigQuery (Cymbal_Cyber.soc_tickets), GCS, and local file storage.
4. Queries BigQuery directly as the Single Source of Truth for tickets and dashboard telemetry.
5. Appends every state change to soc_tickets and reads the latest state through the
   soc_tickets_current view, so streaming-buffer rows never need an UPDATE.
6. Provides dynamic aggregated metrics for dashboard visualization.
"""

import os

from src.demo.soc_ticketing.service.metrics import DashboardMetricsMixin
from src.demo.soc_ticketing.service.queries import TicketQueriesMixin

# Re-exported so `from src.demo.soc_ticketing.ticketing_service import X` keeps
# working for code and tests written before the service was split into modules.
from src.demo.soc_ticketing.service.schema import (  # noqa: F401
    DEFAULT_QUEUE_DIR,
    REPO_ROOT,
    SCREENSHOTS_DIR,
    SOC_TICKET_COLUMNS,
    SOC_TICKET_REQUIRED_STRINGS,
    TicketPersistenceError,
    _row_dict,
    logger,
)
from src.demo.soc_ticketing.service.seed_data import SeedHistoryMixin
from src.demo.soc_ticketing.service.writes import TicketWritesMixin


class SocTicketingService(
    TicketWritesMixin, TicketQueriesMixin, DashboardMetricsMixin, SeedHistoryMixin
):
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
    def _current_tickets(self) -> str:
        """The soc_tickets_current view: one row per ticket, its latest state."""
        return f"{self.project_id}.{self.dataset_id}.soc_tickets_current"

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
