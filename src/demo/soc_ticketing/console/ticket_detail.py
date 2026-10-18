"""
The ticket dossier, shared by the triage queue and the archive: header, agent
analysis, recommendations, evidence, the Ask the Agent chat, the full report, and
the analyst adjudication form. Report text comes from user desktops, so it is
always rendered through neutralize_markdown.
"""

import logging
from typing import Any

import streamlit as st

from src.demo.soc_ticketing.console.config import (
    ADK_WEB_URL,
    SEVERITY_COLORS,
    SEVERITY_ICONS,
    SUGGESTED_QUESTIONS,
)
from src.demo.soc_ticketing.console.data import get_service, refresh_data
from src.demo.soc_ticketing.console.formatting import (
    archive_verdict,
    as_list,
    entity_label,
    is_auto_closed,
    is_simulated,
    screenshot_source,
    short_ts,
    ticket_report,
)
from src.demo.soc_ticketing.report_parser import neutralize_markdown, parse_report
from src.demo.soc_ticketing.ticket_assistant import TicketAssistant

logger = logging.getLogger("SocConsole")


def render_sections(sections, empty_message: str) -> None:
    if not sections:
        st.info(empty_message)
        return
    for section in sections:
        with st.container(border=True):
            st.markdown(f"**{neutralize_markdown(section.title)}**")
            st.markdown(neutralize_markdown(section.body))


@st.fragment
def ticket_chat(ticket: dict[str, Any]) -> None:
    """Chat with an ADK agent about this ticket; reruns only this panel."""
    tid = ticket.get("ticket_id")
    history: list[dict[str, str]] = st.session_state.setdefault(f"chat_{tid}", [])

    top_l, top_r = st.columns([3, 1])
    top_l.caption(
        "Ask the ADK SOC assistant about this ticket. It reads the ticket and the "
        "agent's report; it cannot change anything."
    )
    if ADK_WEB_URL:
        top_r.link_button("Open ADK Web UI", ADK_WEB_URL, icon=":material/open_in_new:")

    question = None
    if not history:
        cols = st.columns(len(SUGGESTED_QUESTIONS))
        for i, suggestion in enumerate(SUGGESTED_QUESTIONS):
            if cols[i].button(suggestion, key=f"suggest_{tid}_{i}", width="stretch"):
                question = suggestion

    messages = st.container(height=360 if history else 80, border=False)
    with messages:
        for msg in history:
            with st.chat_message(
                msg["role"], avatar="🧑‍💻" if msg["role"] == "user" else "🛡️"
            ):
                st.markdown(neutralize_markdown(msg["content"]))

    typed = st.chat_input("Ask about this ticket...", key=f"chat_input_{tid}")
    question = typed or question
    if not question:
        return

    history.append({"role": "user", "content": question})
    with messages:
        with st.chat_message("user", avatar="🧑‍💻"):
            st.markdown(question)
        with st.chat_message("assistant", avatar="🛡️"):
            with st.spinner("The agent is reviewing the ticket..."):
                try:
                    key = f"assistant_{tid}"
                    if key not in st.session_state:
                        st.session_state[key] = TicketAssistant(ticket)
                    answer = st.session_state[key].ask(question)
                except Exception as e:
                    logger.warning("Ticket assistant failed: %s", e)
                    answer = (
                        "⚠️ The assistant is unavailable right now "
                        f"(`{type(e).__name__}`). Check the model credentials for the console."
                    )
    history.append({"role": "assistant", "content": answer})
    st.rerun(scope="fragment")


def render_ticket_detail(ticket: dict[str, Any], archived: bool) -> None:
    tid = ticket.get("ticket_id", "Unknown")
    sev = str(ticket.get("severity") or "HIGH").upper()
    decision = str(ticket.get("agent_decision") or "UNKNOWN")
    report = ticket_report(ticket)
    parsed = parse_report(report)

    with st.container(border=True):
        head_l, head_r = st.columns([3, 2], vertical_alignment="center")
        with head_l:
            st.markdown(f"#### {SEVERITY_ICONS.get(sev, '⚪')} `{tid}`")
        with head_r:
            badges = st.container(horizontal=True, horizontal_alignment="right")
            badges.badge(sev, color=SEVERITY_COLORS.get(sev, "gray"))
            if is_simulated(ticket):
                badges.badge("Simulated", color="gray", icon=":material/science:")
            else:
                badges.badge(
                    decision.replace("_", " "),
                    color="violet",
                    icon=":material/smart_toy:",
                )
            if archived and is_auto_closed(ticket):
                badges.badge(
                    "Auto-closed by agent", color="blue", icon=":material/smart_toy:"
                )
            elif archived:
                verdict = archive_verdict(ticket)
                badges.badge(
                    verdict,
                    color="red" if verdict == "Genuine Threat" else "green",
                    icon=":material/gavel:",
                )
            else:
                badges.badge(str(ticket.get("status") or "OPEN"), color="gray")

        if is_simulated(ticket):
            st.caption(
                "Scripted by the demo controls, not produced by the agent. "
                "Left out of every dashboard metric."
            )
        elif is_auto_closed(ticket):
            st.caption(
                "The agent closed this alert as a false positive on its own. "
                "No analyst has reviewed it."
            )

        m1, m2, m3, m4 = st.columns(4)
        m1.metric("User", entity_label(ticket.get("user_id")))
        m2.metric("Device", entity_label(ticket.get("device_id")))
        m3.metric("Origin IP", entity_label(ticket.get("source_ip")))
        windows = ticket.get("incident_windows") or 0
        if windows > 1:
            m4.metric(
                "Incident Score",
                ticket.get("incident_total_score"),
                help=(
                    f"{windows} correlated 2-minute windows, peak "
                    f"{ticket.get('incident_peak_score')}. The agent was alerted on "
                    f"the first window (score {ticket.get('threat_score')})."
                ),
            )
        else:
            m4.metric("Threat Score", ticket.get("threat_score", "N/A"))

        reason = (
            ticket.get("agent_reason")
            or ticket.get("agent_reason_for_escalation")
            or "Threat score threshold exceeded."
        )
        if is_simulated(ticket):
            st.info(f"**Scripted verdict:** {reason}", icon=":material/science:")
        elif "FALSE" in decision:
            st.success(f"**Agent verdict:** {reason}", icon=":material/verified_user:")
        else:
            st.error(f"**Agent verdict:** {reason}", icon=":material/crisis_alert:")
        st.caption(
            f"Created {short_ts(ticket.get('created_at') or ticket.get('timestamp'))} UTC"
        )

    tab_analysis, tab_recs, tab_evidence, tab_chat, tab_raw = st.tabs(
        [
            ":material/psychology: Agent Analysis",
            ":material/checklist: Recommendations",
            ":material/fingerprint: Evidence",
            ":material/forum: Ask the Agent",
            ":material/description: Full Report",
        ]
    )

    with tab_analysis:
        render_sections(
            parsed.analysis, "The agent did not record an analysis for this ticket."
        )

    with tab_recs:
        render_sections(
            parsed.recommendations,
            "The agent's report for this ticket has no recommendations section. "
            "Ask the agent in the *Ask the Agent* tab for next steps.",
        )

    with tab_evidence:
        ev_l, ev_r = st.columns([1, 1.3], gap="medium")
        with ev_l:
            with st.container(border=True):
                st.markdown(
                    '<div class="panel-title">MITRE ATT&CK tactics</div>',
                    unsafe_allow_html=True,
                )
                tactics = as_list(ticket.get("mitre_tactics"))
                if tactics:
                    row = st.container(horizontal=True)
                    for tactic in tactics:
                        row.badge(tactic, color="orange")
                else:
                    st.caption("None recorded.")
            with st.container(border=True):
                st.markdown(
                    '<div class="panel-title">Indicators of compromise</div>',
                    unsafe_allow_html=True,
                )
                iocs = as_list(ticket.get("indicators_of_compromise"))
                if iocs:
                    st.code("\n".join(iocs), language=None)
                else:
                    st.caption("None recorded.")
            if ticket.get("geo_country"):
                st.metric("Origin Country", ticket.get("geo_country"))
        with ev_r:
            source = screenshot_source(ticket)
            with st.container(border=True):
                st.markdown(
                    '<div class="panel-title">Desktop screenshot evidence</div>',
                    unsafe_allow_html=True,
                )
                if source:
                    st.image(
                        source,
                        caption=f"Captured from {ticket.get('device_id')} (user {ticket.get('user_id')})",
                        width="stretch",
                    )
                else:
                    st.caption("No screenshot available for this entity.")
        if parsed.evidence:
            st.markdown(
                '<div class="panel-title">Raw investigation findings</div>',
                unsafe_allow_html=True,
            )
            for i, section in enumerate(parsed.evidence):
                with st.expander(neutralize_markdown(section.title), expanded=i == 0):
                    st.markdown(neutralize_markdown(section.body))

    with tab_chat:
        ticket_chat(ticket)

    with tab_raw:
        st.download_button(
            "Download report (.md)",
            data=report or "",
            file_name=f"{tid}.md",
            mime="text/markdown",
            icon=":material/download:",
        )
        with st.container(border=True):
            # Rendered without HTML, images or live links: the report carries text
            # captured from user desktops.
            st.markdown(
                neutralize_markdown(report)
                or "*No structured report content recorded.*"
            )

    if archived:
        with st.container(border=True):
            st.markdown(
                '<div class="panel-title">Analyst resolution</div>',
                unsafe_allow_html=True,
            )
            if is_auto_closed(ticket):
                st.markdown(
                    "**Verdict:** Closed automatically by the agent as False Positive; "
                    "not reviewed by an analyst."
                )
                st.caption(f"Closed {short_ts(ticket.get('adjudicated_at'))} UTC")
            else:
                st.markdown(f"**Verdict:** {ticket.get('human_decision') or 'N/A'}")
                st.markdown(
                    f"**Notes:** {ticket.get('human_comment') or 'No notes entered.'}"
                )
                st.caption(f"Adjudicated {short_ts(ticket.get('adjudicated_at'))} UTC")
        return

    with st.form(key=f"adjudicate_{tid}", border=True):
        st.markdown(
            '<div class="panel-title">Analyst adjudication</div>',
            unsafe_allow_html=True,
        )
        verdict = st.segmented_control(
            "Determination",
            ["Genuine Threat", "False Positive"],
            default="Genuine Threat",
            required=True,
        )
        notes = st.text_area(
            "Resolution notes",
            placeholder="Remediation actions taken (host isolation, credential revocation) "
            "or the rationale for dismissing it as a false positive...",
            height=100,
        )
        if st.form_submit_button(
            "Submit resolution & archive",
            type="primary",
            width="stretch",
            icon=":material/gavel:",
        ):
            get_service().record_human_verdict(tid, verdict, notes)
            refresh_data()
            st.session_state.selected_ticket_id = None
            st.session_state.status_toast = f"{tid} archived as {verdict}."
            st.rerun()
