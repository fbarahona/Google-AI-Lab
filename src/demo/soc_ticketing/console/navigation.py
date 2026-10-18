"""
The page registry and the sidebar panels.

The entry script creates the pages on every run, as Streamlit expects, and
registers them in the session's state, so pages that link to another page (the
overview's "Open Triage Queue" button) find this run's pages. Session state, not a
module global: the module is shared by every analyst's session in the process.
"""

from datetime import UTC, datetime
from typing import Any

import streamlit as st

from src.demo.soc_ticketing.console.config import DATASET_ID, PROJECT_ID
from src.demo.soc_ticketing.console.data import (
    get_service,
    load_historic_tickets,
    load_new_tickets,
)
from src.demo.soc_ticketing.console.formatting import is_simulated

_PAGES_KEY = "console_pages"


def register_pages(pages: dict[str, Any]) -> None:
    """Records this run's pages (overview, triage, archive) for the session."""
    st.session_state[_PAGES_KEY] = pages


def registered_pages() -> dict[str, Any]:
    """This session's pages, keyed by name."""
    return st.session_state[_PAGES_KEY]


def nav_links() -> None:
    """Page links; the triage count refreshes with the live panels."""
    pages = registered_pages()
    for page in pages.values():
        label = page.title
        if page is pages["triage"]:
            label = f"{page.title} ({len(load_new_tickets())})"
        st.page_link(page, label=label, icon=page.icon, width="stretch")


def status_panel() -> None:
    # Simulated tickets sit in the queue with a badge but, like every other
    # dashboard metric, are left out of the counts.
    queue = load_new_tickets()
    pending = sum(not is_simulated(t) for t in queue)
    simulated = len(queue) - pending
    archived = sum(not is_simulated(t) for t in load_historic_tickets())
    mode = (
        "Cloud (BigQuery SSOT)"
        if get_service().is_cloud_enabled()
        else "Local simulation"
    )
    st.markdown('<div class="panel-title">System status</div>', unsafe_allow_html=True)
    c1, c2 = st.columns(2)
    c1.metric(
        "Pending",
        pending,
        help=f"{simulated} simulated ticket(s) also in the queue, not counted."
        if simulated
        else None,
    )
    c2.metric("Archived", archived)
    st.caption(f"Mode: {mode}")
    st.caption(f"Dataset: {PROJECT_ID}.{DATASET_ID}")
    st.caption(f"Updated {datetime.now(UTC):%H:%M:%S} UTC")
