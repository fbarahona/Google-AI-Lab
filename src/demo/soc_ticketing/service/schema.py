"""The soc_tickets column contract, shared paths, and the persistence error."""

import logging
from datetime import datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger("SocTicketingService")

REPO_ROOT = Path(__file__).resolve().parents[4]
SCREENSHOTS_DIR = REPO_ROOT / "local_demo_data" / "user_screenshots"
DEFAULT_QUEUE_DIR = REPO_ROOT / "local_demo_data" / "escalations"


def _row_dict(row: Any) -> dict[str, Any]:
    """A BigQuery row as a ticket dict, with TIMESTAMP columns as ISO-8601 strings
    (the shape local and GCS tickets already have)."""
    return {k: v.isoformat() if isinstance(v, datetime) else v for k, v in row.items()}


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
