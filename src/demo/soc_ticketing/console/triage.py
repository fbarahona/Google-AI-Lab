"""Page 2: the triage queue, with the selected ticket's dossier."""

from datetime import UTC, datetime

import streamlit as st

from src.demo.soc_ticketing.console.config import SEVERITY_ICONS
from src.demo.soc_ticketing.console.data import (
    inject,
    live_interval,
    load_new_tickets,
    refresh_data,
)
from src.demo.soc_ticketing.console.formatting import (
    entity_label,
    is_simulated,
    score_label,
    short_ts,
)
from src.demo.soc_ticketing.console.ticket_detail import render_ticket_detail


def queue_panel() -> None:
    tickets = load_new_tickets()
    ids = [t.get("ticket_id") for t in tickets]

    seen = st.session_state.seen_ticket_ids
    if seen is not None:
        for t in tickets:
            if t.get("ticket_id") not in seen:
                st.toast(
                    f"New ticket for {t.get('user_id')} ({t.get('severity')})",
                    icon="🚨",
                )
    st.session_state.seen_ticket_ids = set(ids)

    head_l, head_r = st.columns([3, 1], vertical_alignment="center")
    head_l.markdown(
        f'<div class="panel-title">Queue ({len(tickets)})</div>', unsafe_allow_html=True
    )
    if head_r.button(
        "", icon=":material/refresh:", key="queue_refresh", help="Refresh now"
    ):
        refresh_data()
        st.rerun()

    if not tickets:
        st.success("🟢 No pending tickets. All alerts have been adjudicated.")
        if st.button(
            "Inject Malicious APT Scenario (u.lewis)",
            type="primary",
            width="stretch",
            key="q_mal",
        ):
            inject("malicious", "u.lewis")
            st.rerun()
        if st.button(
            "Inject False Positive Scenario (l.taylor)", width="stretch", key="q_fp"
        ):
            inject("false_positive", "l.taylor")
            st.rerun()
        return

    severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    sev_filter = st.pills(
        "Severity",
        severities,
        selection_mode="multi",
        key="queue_sev_filter",
        label_visibility="collapsed",
    )
    shown = [
        t
        for t in tickets
        if not sev_filter or str(t.get("severity")).upper() in sev_filter
    ]

    with st.container(height=640, border=False):
        for t in shown:
            tid = t.get("ticket_id")
            sev = str(t.get("severity") or "HIGH").upper()
            selected = tid == st.session_state.selected_ticket_id
            label = (
                f"{SEVERITY_ICONS.get(sev, '⚪')} **{entity_label(t.get('user_id'))}** · {sev} · "
                f"{score_label(t)}"
                f"{' · 🧪 Simulated' if is_simulated(t) else ''}  \n"
                f"{short_ts(t.get('created_at') or t.get('timestamp'))}"
            )
            if st.button(
                label,
                key=f"q_{tid}",
                type="primary" if selected else "secondary",
                width="stretch",
            ):
                st.session_state.selected_ticket_id = tid
                st.rerun()

    st.caption(f"Updated {datetime.now(UTC):%H:%M:%S} UTC")


def triage_page() -> None:
    st.markdown('<p class="page-title">Triage Queue</p>', unsafe_allow_html=True)
    st.markdown(
        '<div class="page-sub">Tickets escalated by the ADK multi-agent pipeline, '
        "waiting for an analyst decision.</div>",
        unsafe_allow_html=True,
    )

    col_list, col_detail = st.columns([1, 2.6], gap="medium")
    with col_list, st.container(border=True):
        st.fragment(queue_panel, run_every=live_interval())()

    tickets = load_new_tickets()
    ids = [t.get("ticket_id") for t in tickets]
    if tickets and st.session_state.selected_ticket_id not in ids:
        st.session_state.selected_ticket_id = ids[0]
    current = next(
        (
            t
            for t in tickets
            if t.get("ticket_id") == st.session_state.selected_ticket_id
        ),
        None,
    )

    with col_detail:
        if current:
            render_ticket_detail(current, archived=False)
        else:
            with st.container(border=True):
                st.info("Select a ticket from the queue to open its dossier.")
