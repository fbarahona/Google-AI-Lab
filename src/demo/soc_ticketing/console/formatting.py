"""Labels and ticket helpers shared by the console pages."""

import os
import re
from typing import Any

from src.demo.soc_ticketing.console.config import SCREENSHOTS_DIR
from src.demo.soc_ticketing.models import AUTO_CLOSED_FP_DECISION, SIMULATED_DECISION


def format_count(n: int) -> str:
    """Formats large integer counts into clean human-readable units (K, M)."""
    if n >= 1_000_000:
        return f"{n / 1_000_000:.1f}M"
    if n >= 1_000:
        return f"{n / 1_000:.1f}K"
    return str(n)


def short_ts(value: Any) -> str:
    return str(value or "")[:19].replace("T", " ")


def score_label(ticket: dict[str, Any]) -> str:
    """Queue score: the incident total when the ticket covers several windows."""
    windows = ticket.get("incident_windows") or 0
    if windows > 1:
        return f"score {ticket.get('incident_total_score')} ({windows} windows)"
    return f"score {ticket.get('threat_score', 'N/A')}"


def entity_label(value: Any) -> str:
    """Header value for a ticket entity; placeholders mean the field was not in the alert."""
    text = str(value or "")
    if not text or text.startswith(("unknown_", "unresolved_")):
        return "Not in alert"
    return text


def is_simulated(ticket: dict[str, Any]) -> bool:
    return ticket.get("agent_decision") == SIMULATED_DECISION


def is_auto_closed(ticket: dict[str, Any]) -> bool:
    """Closed as false positive by the agent itself, with no analyst verdict."""
    return ticket.get("agent_decision") == AUTO_CLOSED_FP_DECISION and not ticket.get(
        "human_decision"
    )


def archive_verdict(ticket: dict[str, Any]) -> str:
    if is_auto_closed(ticket):
        return "Auto-closed"
    return ticket.get("human_decision") or "Adjudicated"


def ticket_report(ticket: dict[str, Any]) -> str:
    return (
        ticket.get("structured_report")
        or ticket.get("context_for_human")
        or ticket.get("agent_reason")
        or ""
    )


def screenshot_source(ticket: dict[str, Any]) -> str | None:
    user = ticket.get("user_id", "")
    local_path = os.path.join(SCREENSHOTS_DIR, f"{user}.png")
    if os.path.exists(local_path):
        return local_path
    url = ticket.get("screenshot_url") or ""
    if not url.startswith("http"):
        match = re.search(
            r"https://storage\.googleapis\.com/[^\s\)\"\']+", ticket_report(ticket)
        )
        url = match.group(0) if match else ""
    return url or None


def as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value] if value else []
    return [str(v) for v in value if v]
