"""
The ticketing service and its cached reads, shared by every page, plus the demo
actions. Every panel shares one query per refresh interval, so navigating between
pages does not hit BigQuery again.
"""

import logging
from typing import Any

import streamlit as st

from src.demo.soc_ticketing.console.config import (
    DATASET_ID,
    PROJECT_ID,
    REFRESH_SECONDS,
    SCREENSHOTS_DIR,
)
from src.demo.soc_ticketing.demo_actions import (
    inject_threat_scenario,
    stream_benign_logs,
)
from src.demo.soc_ticketing.ticketing_service import SocTicketingService

logger = logging.getLogger("SocConsole")


@st.cache_resource
def get_service() -> SocTicketingService:
    return SocTicketingService(project_id=PROJECT_ID, dataset_id=DATASET_ID)


# Cached reads: every panel and page shares one query per refresh interval, so
# navigating between pages does not hit BigQuery again.
@st.cache_data(ttl=REFRESH_SECONDS, show_spinner=False)
def load_metrics(time_range: str) -> dict[str, Any]:
    return get_service().fetch_dashboard_metrics(time_range=time_range)


@st.cache_data(ttl=REFRESH_SECONDS, show_spinner=False)
def load_new_tickets() -> list[dict[str, Any]]:
    return get_service().fetch_new_tickets()


@st.cache_data(ttl=REFRESH_SECONDS, show_spinner=False)
def load_historic_tickets() -> list[dict[str, Any]]:
    return get_service().fetch_historic_tickets()


def refresh_data() -> None:
    load_metrics.clear()
    load_new_tickets.clear()
    load_historic_tickets.clear()


def live_interval() -> str | None:
    """Refresh interval for live panels, or None when the presenter paused it."""
    return f"{REFRESH_SECONDS}s" if st.session_state.get("live_refresh", True) else None


def run_demo_action(label: str, action) -> None:
    try:
        with st.spinner(f"{label}..."):
            message = action()
    except Exception as e:
        logger.exception("%s failed", label)
        detail = str(e)
        if len(detail) > 200:
            detail = detail[:200] + "..."
        st.session_state.status_toast = f"{label} failed: {detail}"
        st.session_state.status_toast_icon = "❌"
        return
    refresh_data()
    st.session_state.status_toast = message or f"{label}: done."


def inject(threat_type: str, user_id: str) -> None:
    run_demo_action(
        f"Injecting {threat_type.replace('_', ' ')} scenario for {user_id}",
        lambda: inject_threat_scenario(
            get_service(), threat_type, user_id, SCREENSHOTS_DIR
        ),
    )


def stream_logs() -> None:
    run_demo_action(
        "Streaming 50 benign enterprise logs",
        lambda: stream_benign_logs(get_service(), batch_size=50),
    )
