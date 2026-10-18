"""Page 3: the ticket archive, with KPIs, filters and the same dossier view."""

import pandas as pd
import streamlit as st

from src.demo.soc_ticketing.console.data import load_historic_tickets
from src.demo.soc_ticketing.console.formatting import (
    archive_verdict,
    is_auto_closed,
    is_simulated,
    short_ts,
)
from src.demo.soc_ticketing.console.ticket_detail import render_ticket_detail


def archive_page() -> None:
    st.markdown('<p class="page-title">Ticket Archive</p>', unsafe_allow_html=True)
    st.markdown(
        '<div class="page-sub">Closed incidents: approved genuine threats, dismissed false positives, and false positives the agent closed on its own.</div>',
        unsafe_allow_html=True,
    )
    historic = load_historic_tickets()

    # Simulated tickets stay listed below but are left out of the KPIs.
    counted = [t for t in historic if not is_simulated(t)]
    total = len(counted)
    threats = sum(1 for t in counted if t.get("human_decision") == "Genuine Threat")
    fps = sum(1 for t in counted if t.get("human_decision") == "False Positive")
    auto_closed = sum(1 for t in counted if is_auto_closed(t))
    k1, k2, k3, k5, k4 = st.columns(5)
    k1.metric("Archived Incidents", total)
    k2.metric(
        "Approved Threats",
        threats,
        delta=f"{threats / total * 100:.1f}% ratio" if total else None,
        delta_color="inverse",
    )
    k3.metric(
        "Dismissed False Positives",
        fps,
        delta=f"{fps / total * 100:.1f}% filtered" if total else None,
    )
    k5.metric("Auto-closed by Agent", auto_closed)
    k4.metric("Avg Resolution Time (MTTR)", "18 mins" if total else "0 mins")

    f1, f2, f3 = st.columns([2, 1, 1])
    query = f1.text_input(
        "Search",
        placeholder="User, ticket ID, IP or notes (e.g. u.lewis, Mimikatz)",
        label_visibility="collapsed",
    )
    verdict_filter = f2.selectbox(
        "Verdict",
        ["All Verdicts", "Genuine Threat", "False Positive", "Auto-closed"],
        label_visibility="collapsed",
    )
    severity_filter = f3.selectbox(
        "Severity",
        ["All Severities", "CRITICAL", "HIGH", "MEDIUM", "LOW"],
        label_visibility="collapsed",
    )

    filtered = historic
    if verdict_filter != "All Verdicts":
        filtered = [t for t in filtered if archive_verdict(t) == verdict_filter]
    if severity_filter != "All Severities":
        filtered = [t for t in filtered if t.get("severity") == severity_filter]
    if query:
        q = query.lower()
        fields = ("ticket_id", "user_id", "source_ip", "human_comment", "agent_reason")
        filtered = [
            t for t in filtered if any(q in str(t.get(f, "")).lower() for f in fields)
        ]

    if not filtered:
        st.info("No archived tickets match the selected filters.")
        return

    rows = [
        {
            "Ticket ID": t.get("ticket_id"),
            "Source": "🧪 Simulated" if is_simulated(t) else "Agent",
            "User": t.get("user_id"),
            "Origin IP": t.get("source_ip"),
            "Score": t.get("threat_score"),
            "Severity": t.get("severity"),
            "Verdict": {
                "Genuine Threat": "🔴 Genuine Threat",
                "Auto-closed": "🤖 Auto-closed FP",
            }.get(archive_verdict(t), "🟢 False Positive"),
            "Resolution Notes": t.get("human_comment")
            or ("Not reviewed by an analyst" if is_auto_closed(t) else "N/A"),
            "Adjudicated At": short_ts(t.get("adjudicated_at") or t.get("created_at")),
        }
        for t in filtered
    ]
    st.caption("Select a row to open the full dossier.")
    event = st.dataframe(
        pd.DataFrame(rows),
        width="stretch",
        hide_index=True,
        height=min(38 + 35 * len(rows), 320),
        on_select="rerun",
        selection_mode="single-row",
        key="archive_table",
    )
    if event.selection.rows:
        render_ticket_detail(filtered[event.selection.rows[0]], archived=True)
