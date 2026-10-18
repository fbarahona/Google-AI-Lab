"""
Deterministic ticket IDs and severity normalization.

One alert always maps to one ticket ID, so Pub/Sub redeliveries overwrite rather
than duplicate.
"""

import hashlib
import re
import time
import uuid
from typing import Any

from adk_agent.tools.clients import SEVERITIES
from adk_agent.tools.sql_guard import sanitize_entity_value


def _clean_ticket_user(user_id: str | None) -> str:
    """Sanitizes user_id for use in a ticket ID, preventing JSON object bleed."""
    if not user_id:
        return "unknown_user"
    try:
        return sanitize_entity_value(user_id, field_name="user_id")
    except ValueError:
        match = re.match(r"^[a-zA-Z0-9\._-]+", str(user_id))
        return match.group(0) if match else "invalid_id"


def ticket_id_for_alert(
    user_id: str | None, alert_id: str | None, prefix: str = "SOC-TICKET"
) -> str:
    """
    Ticket ID for one detection alert: the same alert always maps to the same ticket,
    so Pub/Sub redeliveries overwrite rather than duplicate, and two alerts for one
    user never collide. Without an alert_id the suffix is random.
    """
    if alert_id:
        suffix = hashlib.sha256(alert_id.encode("utf-8")).hexdigest()[:10]
    else:
        suffix = uuid.uuid4().hex[:10]
    return f"{prefix}-{_clean_ticket_user(user_id)}-{suffix}"


def alert_id_from_payload(data: dict[str, Any]) -> str | None:
    """The alert contract's alert_id, or user_id|window_end when it is missing."""
    if data.get("alert_id"):
        return str(data["alert_id"])
    user = data.get("user_id") or data.get("user")
    window_end = data.get("window_end") or data.get("transaction_window_end")
    return f"{user}|{window_end}" if user and window_end else None


def normalize_severity(severity: str | None, default: str = "HIGH") -> str:
    sev = str(severity or "").strip().upper()
    return sev if sev in SEVERITIES else default


def create_rich_ticket_id(user_id: str) -> dict[str, str]:
    """
    Generates a standardized, readable ticket ID that is unique per call.
    During an investigation the security gate replaces it with the alert's own ticket ID.
    """
    return {
        "ticket_id": f"SOC-TICKET-{_clean_ticket_user(user_id)}-{int(time.time())}-{uuid.uuid4().hex[:6]}"
    }
