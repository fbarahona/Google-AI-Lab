"""
SOC As-A-Service Monitoring Console & Ticketing Portal
======================================================
Streamlit multipage console backed by BigQuery (Cymbal_Cyber) as the Single Source of Truth:
1. Overview (KPI funnel, donut charts, category bars, trend lines, world threat map)
2. Triage Queue (live ticket queue + incident dossier with the agent's analysis,
   recommendations, evidence, an ADK assistant to question the ticket, and adjudication)
3. Ticket Archive (adjudicated incidents with the same dossier view)

Live data is refreshed by fragments with their own interval, so a refresh only
redraws the panel that changed and never resets navigation or a form being typed.
"""

import streamlit as st

# Run from the repository root with `uv run python -m streamlit run`, so `src.demo` imports
# resolve from it (the Cloud Run command does the same).
from src.demo.soc_ticketing.console.archive import archive_page
from src.demo.soc_ticketing.console.config import REFRESH_SECONDS
from src.demo.soc_ticketing.console.data import (
    get_service,
    inject,
    live_interval,
    refresh_data,
    stream_logs,
)
from src.demo.soc_ticketing.console.navigation import (
    nav_links,
    register_pages,
    status_panel,
)
from src.demo.soc_ticketing.console.overview import overview_page
from src.demo.soc_ticketing.console.theme import CONSOLE_CSS
from src.demo.soc_ticketing.console.triage import triage_page

st.set_page_config(
    page_title="SOC As-A-Service",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Enterprise Dark Theme CSS styling
st.markdown(CONSOLE_CSS, unsafe_allow_html=True)

service = get_service()

st.session_state.setdefault("selected_ticket_id", None)
st.session_state.setdefault("status_toast", None)
st.session_state.setdefault("seen_ticket_ids", None)

if st.session_state.status_toast:
    st.toast(
        st.session_state.status_toast,
        icon=st.session_state.pop("status_toast_icon", None) or "✅",
    )
    st.session_state.status_toast = None

# ==============================================================================
# NAVIGATION & SIDEBAR
# ==============================================================================
PAGES = {
    "overview": st.Page(
        overview_page,
        title="Overview",
        icon=":material/dashboard:",
        url_path="overview",
        default=True,
    ),
    "triage": st.Page(
        triage_page,
        title="Triage Queue",
        icon=":material/notifications_active:",
        url_path="triage",
    ),
    "archive": st.Page(
        archive_page,
        title="Ticket Archive",
        icon=":material/inventory_2:",
        url_path="archive",
    ),
}
register_pages(PAGES)


with st.sidebar:
    st.markdown(
        '<div class="brand-title">🛡️ SOC AS-A-SERVICE</div>', unsafe_allow_html=True
    )
    st.markdown(
        '<div class="brand-sub">Cymbal Cyber · ADK multi-agent triage</div>',
        unsafe_allow_html=True,
    )

    st.fragment(nav_links, run_every=live_interval())()

    st.divider()
    with st.container(border=True):
        st.fragment(status_panel, run_every=live_interval())()

    st.toggle(
        f"Live refresh (every {REFRESH_SECONDS}s)",
        value=True,
        key="live_refresh",
        help="Live panels poll for new data on their own; pausing keeps the screen still for a presentation.",
    )
    if st.button("Refresh now", icon=":material/refresh:", width="stretch"):
        refresh_data()
        st.rerun()

    with st.expander("Demo controls", icon=":material/science:"):
        if st.button("Inject malicious APT (u.lewis)", width="stretch", key="sb_mal"):
            inject("malicious", "u.lewis")
            st.rerun()
        if st.button("Inject false positive (l.taylor)", width="stretch", key="sb_fp"):
            inject("false_positive", "l.taylor")
            st.rerun()
        if st.button("Stream 50 benign logs", width="stretch", key="sb_benign"):
            stream_logs()
            st.rerun()
        if not service.is_cloud_enabled():
            st.caption(
                "Local mode: `uv run python -m src.demo.local_runner --threat malicious` runs the full pipeline."
            )

navigation = st.navigation(list(PAGES.values()), position="hidden")
navigation.run()
