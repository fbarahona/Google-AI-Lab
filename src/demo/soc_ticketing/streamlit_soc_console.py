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

import logging
import os
import re
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pandas as pd
import streamlit as st

logger = logging.getLogger("SocConsole")

# Ensure directory is on sys.path if run directly via `streamlit run`
_CURRENT_DIR = Path(__file__).resolve().parent
if str(_CURRENT_DIR) not in sys.path:
    sys.path.insert(0, str(_CURRENT_DIR))
_SRC_DIR = _CURRENT_DIR.parent.parent
if str(_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(_SRC_DIR))

try:
    from .dashboard_charts import (
        create_category_bar_chart,
        create_donut_chart,
        create_log_breakdown_chart,
        create_log_rate_chart,
        create_threat_map_deck,
        create_threat_trend_chart,
    )
    from .demo_actions import inject_threat_scenario, stream_benign_logs
    from .models import AUTO_CLOSED_FP_DECISION, SIMULATED_DECISION
    from .report_parser import parse_report
    from .ticket_assistant import TicketAssistant
    from .ticketing_service import SocTicketingService
except ImportError:
    from dashboard_charts import (
        create_category_bar_chart,
        create_donut_chart,
        create_log_breakdown_chart,
        create_log_rate_chart,
        create_threat_map_deck,
        create_threat_trend_chart,
    )
    from demo_actions import inject_threat_scenario, stream_benign_logs
    from models import AUTO_CLOSED_FP_DECISION, SIMULATED_DECISION
    from report_parser import parse_report
    from ticket_assistant import TicketAssistant
    from ticketing_service import SocTicketingService

st.set_page_config(
    page_title="SOC As-A-Service",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Enterprise Dark Theme CSS styling
st.markdown(
    """
<style>
    .stApp { background-color: #0b111e; color: #f1f5f9; }
    header[data-testid="stHeader"] { background-color: #0b111e; }
    section[data-testid="stSidebar"] {
        background-color: #070b13;
        border-right: 1px solid #1e293b;
    }
    div[data-testid="stMetric"] {
        background-color: #111a2d;
        border: 1px solid #1e293b;
        border-radius: 8px;
        padding: 10px 14px;
    }
    div[data-testid="stMetricLabel"] p {
        color: #94a3b8 !important;
        font-size: 0.8rem !important;
        font-weight: 500;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }
    div[data-testid="stMetricValue"] {
        color: #ffffff !important;
        font-weight: 700 !important;
        font-size: 1.35rem !important;
    }
    div[data-testid="stVerticalBlockBorderWrapper"] {
        background-color: #10192a;
        border: 1px solid #1e293b !important;
        border-radius: 8px;
    }
    .brand-title {
        font-size: 1.15rem;
        font-weight: 800;
        letter-spacing: 1.5px;
        color: #ffffff;
        margin-bottom: 4px;
    }
    .brand-sub { color: #64748b; font-size: 0.8rem; margin-bottom: 12px; }
    .page-title { font-size: 1.5rem; font-weight: 700; color: #f8fafc; margin: 0; }
    .page-sub { color: #94a3b8; font-size: 0.9rem; margin-bottom: 8px; }
    .panel-title {
        font-size: 0.8rem;
        font-weight: 700;
        color: #cbd5e1;
        text-transform: uppercase;
        letter-spacing: 0.6px;
    }
    .muted { color: #64748b; font-size: 0.78rem; }
    .kpi-container {
        display: flex;
        justify-content: space-between;
        align-items: center;
        gap: 8px;
        background: #10192a;
        border: 1px solid #1e293b;
        border-radius: 8px;
        padding: 16px 20px;
        margin-bottom: 16px;
    }
    .kpi-item { text-align: center; flex: 1; }
    .kpi-val { font-size: 1.5rem; font-weight: 700; color: #ffffff; }
    .kpi-lbl {
        font-size: 0.72rem;
        color: #94a3b8;
        margin-top: 4px;
        text-transform: uppercase;
        letter-spacing: 0.4px;
    }
    .kpi-divider { color: #334155; font-size: 1.2rem; }
</style>
""",
    unsafe_allow_html=True,
)

PROJECT_ID = os.getenv("GOOGLE_CLOUD_PROJECT", "local-demo")
DATASET_ID = os.getenv("BIGQUERY_DATASET", "Cymbal_Cyber")
REPO_ROOT = Path(__file__).resolve().parents[3]
SCREENSHOTS_DIR = str(REPO_ROOT / "local_demo_data" / "user_screenshots")
# How often the live panels poll for new data.
REFRESH_SECONDS = max(5, int(os.getenv("SOC_REFRESH_SECONDS", "20")))
# Optional link to the ADK web UI, shown next to the ticket assistant.
ADK_WEB_URL = os.getenv("ADK_WEB_URL", "")

SEVERITY_COLORS = {
    "CRITICAL": "red",
    "HIGH": "orange",
    "MEDIUM": "yellow",
    "LOW": "blue",
}
SEVERITY_ICONS = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}
TIME_RANGE_LABELS = {
    "All Time": "All time",
    "Last 24 Hours": "24h",
    "Last 7 Days": "7d",
    "Last 30 Days": "30d",
    "Last 90 Days": "90d",
}
TIME_RANGES = list(TIME_RANGE_LABELS)
SUGGESTED_QUESTIONS = [
    "Summarize this incident in three bullet points",
    "What should I do first to contain it?",
    "Is there any sign this could be a false positive?",
]


@st.cache_resource
def get_service() -> SocTicketingService:
    return SocTicketingService(project_id=PROJECT_ID, dataset_id=DATASET_ID)


service = get_service()


# Cached reads: every panel and page shares one query per refresh interval, so
# navigating between pages does not hit BigQuery again.
@st.cache_data(ttl=REFRESH_SECONDS, show_spinner=False)
def load_metrics(time_range: str) -> dict[str, Any]:
    return service.fetch_dashboard_metrics(time_range=time_range)


@st.cache_data(ttl=REFRESH_SECONDS, show_spinner=False)
def load_new_tickets() -> list[dict[str, Any]]:
    return service.fetch_new_tickets()


@st.cache_data(ttl=REFRESH_SECONDS, show_spinner=False)
def load_historic_tickets() -> list[dict[str, Any]]:
    return service.fetch_historic_tickets()


def refresh_data() -> None:
    load_metrics.clear()
    load_new_tickets.clear()
    load_historic_tickets.clear()


def live_interval() -> str | None:
    """Refresh interval for live panels, or None when the presenter paused it."""
    return f"{REFRESH_SECONDS}s" if st.session_state.get("live_refresh", True) else None


def format_count(n: int) -> str:
    """Formats large integer counts into clean human-readable units (K, M)."""
    if n >= 1_000_000:
        return f"{n / 1_000_000:.1f}M"
    if n >= 1_000:
        return f"{n / 1_000:.1f}K"
    return str(n)


def short_ts(value: Any) -> str:
    return str(value or "")[:19].replace("T", " ")


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
        lambda: inject_threat_scenario(service, threat_type, user_id, SCREENSHOTS_DIR),
    )


def stream_logs() -> None:
    run_demo_action(
        "Streaming 50 benign enterprise logs",
        lambda: stream_benign_logs(service, batch_size=50),
    )


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
# TICKET DOSSIER (shared by the triage queue and the archive)
# ==============================================================================
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


def render_sections(sections, empty_message: str) -> None:
    if not sections:
        st.info(empty_message)
        return
    for section in sections:
        with st.container(border=True):
            st.markdown(f"**{section.title}**")
            st.markdown(section.body)


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
                st.markdown(msg["content"])

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
        m1.metric("User", ticket.get("user_id", "Unknown"))
        m2.metric("Device", ticket.get("device_id", "Unknown"))
        m3.metric("Origin IP", ticket.get("source_ip", "Unknown"))
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
                with st.expander(section.title, expanded=i == 0):
                    st.markdown(section.body)

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
            # Rendered without HTML: the report carries text captured from user desktops.
            st.markdown(report or "*No structured report content recorded.*")

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
            service.record_human_verdict(tid, verdict, notes)
            refresh_data()
            st.session_state.selected_ticket_id = None
            st.session_state.status_toast = f"{tid} archived as {verdict}."
            st.rerun()


# ==============================================================================
# PAGE 1: OVERVIEW
# ==============================================================================
def overview_page() -> None:
    head_l, head_m, head_r = st.columns([2.2, 2.2, 1.2], vertical_alignment="bottom")
    with head_l:
        st.markdown(
            '<p class="page-title">SOC Monitoring Overview</p>', unsafe_allow_html=True
        )
        st.markdown(
            f'<div class="page-sub">BigQuery dataset {PROJECT_ID}.{DATASET_ID}</div>',
            unsafe_allow_html=True,
        )
    with head_m:
        time_filter = st.segmented_control(
            "Time range",
            TIME_RANGES,
            format_func=TIME_RANGE_LABELS.get,
            default="All Time",
            required=True,
            key="time_filter",
            label_visibility="collapsed",
        )
    with head_r:
        if st.button(
            "Open Triage Queue",
            type="primary",
            width="stretch",
            icon=":material/notifications_active:",
        ):
            st.switch_page(PAGES["triage"])

    st.fragment(overview_live, run_every=live_interval())(time_filter)


def overview_live(time_filter: str) -> None:
    metrics = load_metrics(time_filter)
    new_tickets = load_new_tickets()

    kpis = [
        ("Monitored Devices", metrics["monitored_devices"], "#ffffff"),
        ("Monitored Endpoints", metrics["monitored_endpoints"], "#ffffff"),
        ("Monitored Users", metrics["monitored_users"], "#ffffff"),
        ("Processed Logs", metrics["processed_logs"], "#ffffff"),
        ("Security Events", metrics["security_events"], "#ffffff"),
        ("Triaged Alerts", metrics["triaged_alerts"], "#ff9800"),
        ("Escalated Alerts", metrics["escalated_alerts"], "#f44336"),
    ]
    items = '<div class="kpi-divider">&rsaquo;</div>'.join(
        f'<div class="kpi-item"><div class="kpi-val" style="color: {color};">{format_count(val)}</div>'
        f'<div class="kpi-lbl">{label}</div></div>'
        for label, val, color in kpis
    )
    st.markdown(f'<div class="kpi-container">{items}</div>', unsafe_allow_html=True)

    if metrics["processed_logs"] == 0 and not new_tickets:
        with st.container(border=True):
            st.markdown(
                "### 📡 BigQuery Telemetry Pipeline Connected — Ready for Ingestion"
            )
            st.markdown(
                "The dataset is at baseline zero. Generate synthetic enterprise logs or inject a "
                "threat scenario to see the AI detection pipeline in action. The same controls "
                "are always available under **Demo controls** in the sidebar."
            )
            c1, c2, c3 = st.columns(3)
            if c1.button(
                "Inject Malicious APT Scenario (u.lewis)",
                type="primary",
                width="stretch",
                key="ov_mal",
            ):
                inject("malicious", "u.lewis")
                st.rerun()
            if c2.button(
                "Inject False Positive Scenario (l.taylor)",
                width="stretch",
                key="ov_fp",
            ):
                inject("false_positive", "l.taylor")
                st.rerun()
            if c3.button(
                "Stream 50 Benign Enterprise Logs", width="stretch", key="ov_benign"
            ):
                stream_logs()
                st.rerun()

    total_alerts = metrics["triaged_alerts"] + metrics["escalated_alerts"]
    c_sev, c_stat, c_sla, c_cat = st.columns([1, 1, 1, 1.4], gap="medium")
    donuts = [
        (
            c_sev,
            "ALERTS BY SEVERITY",
            "alerts_by_severity",
            "severity",
            {
                "Critical": "#f44336",
                "High": "#ff9800",
                "Medium": "#ffca28",
                "Low": "#00e5ff",
            },
        ),
        (
            c_stat,
            "ALERTS BY STATUS",
            "alerts_by_status",
            "status",
            {
                "Open": "#00e5ff",
                "In Progress": "#ff9800",
                "Closed": "#00e676",
                "Escalated": "#f44336",
            },
        ),
        (
            c_sla,
            "ALERTS BY SLA",
            "alerts_by_sla",
            "sla",
            {
                "Within SLA": "#00e676",
                "Approaching SLA": "#ffca28",
                "Breached SLA": "#f44336",
            },
        ),
    ]
    for col, title, key, category, colors in donuts:
        with col, st.container(border=True):
            st.markdown(f"**{title}**")
            st.altair_chart(
                create_donut_chart(
                    metrics[key],
                    category,
                    "count",
                    colors,
                    center_label="Alerts",
                    center_total=total_alerts,
                ),
                width="stretch",
            )
    with c_cat, st.container(border=True):
        st.markdown("**OPEN ALERTS BY CATEGORY**")
        st.altair_chart(
            create_category_bar_chart(metrics["alerts_by_category"]), width="stretch"
        )

    c_rate, c_break, c_trend = st.columns([1, 1.2, 1], gap="medium")
    with c_rate, st.container(border=True):
        st.markdown("**AVERAGE LOG RATE (per second)**")
        st.altair_chart(
            create_log_rate_chart(metrics["log_rate_trend"]), width="stretch"
        )
    with c_break, st.container(border=True):
        st.markdown("**LOG COLLECTION BREAKDOWN**")
        st.altair_chart(
            create_log_breakdown_chart(metrics["log_breakdown"]), width="stretch"
        )
    with c_trend, st.container(border=True):
        st.markdown("**THREAT DETECTION TREND**")
        st.altair_chart(
            create_threat_trend_chart(metrics["threat_trend"]), width="stretch"
        )

    with st.container(border=True):
        st.markdown(
            f"**GEOGRAPHICAL THREAT ORIGINS & REPUTATION MAP "
            f"({len(metrics['threat_points'])} Active Locations)**"
        )
        st.pydeck_chart(
            create_threat_map_deck(metrics["threat_points"]), width="stretch"
        )

    with st.container(border=True):
        st.markdown(f"**ACTIVE ALERTS REQUIRING TRIAGE ({len(new_tickets)})**")
        if not new_tickets:
            st.success("🟢 No pending alerts in the active queue.")
        else:
            st.caption("Select a row to open it in the triage queue.")
            rows = [
                {
                    "Ticket ID": t.get("ticket_id"),
                    "Severity": f"{SEVERITY_ICONS.get(str(t.get('severity')).upper(), '⚪')} {t.get('severity')}",
                    "User": t.get("user_id"),
                    "Device": t.get("device_id"),
                    "Origin IP": t.get("source_ip"),
                    "Threat Score": t.get("threat_score"),
                    "Created At": short_ts(t.get("created_at") or t.get("timestamp")),
                }
                for t in new_tickets[:10]
            ]
            event = st.dataframe(
                pd.DataFrame(rows),
                width="stretch",
                hide_index=True,
                on_select="rerun",
                selection_mode="single-row",
                key="overview_alerts",
            )
            if event.selection.rows:
                st.session_state.selected_ticket_id = rows[event.selection.rows[0]][
                    "Ticket ID"
                ]
                st.switch_page(PAGES["triage"])

    st.caption(f"Last updated {datetime.now(UTC):%H:%M:%S} UTC")


# ==============================================================================
# PAGE 2: TRIAGE QUEUE
# ==============================================================================
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
                f"{SEVERITY_ICONS.get(sev, '⚪')} **{t.get('user_id', 'Unknown')}** · {sev} · "
                f"score {t.get('threat_score', 'N/A')}"
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


# ==============================================================================
# PAGE 3: TICKET ARCHIVE
# ==============================================================================
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


def status_panel() -> None:
    pending = len(load_new_tickets())
    archived = len(load_historic_tickets())
    mode = "Cloud (BigQuery SSOT)" if service.is_cloud_enabled() else "Local simulation"
    st.markdown('<div class="panel-title">System status</div>', unsafe_allow_html=True)
    c1, c2 = st.columns(2)
    c1.metric("Pending", pending)
    c2.metric("Archived", archived)
    st.caption(f"Mode: {mode}")
    st.caption(f"Dataset: {PROJECT_ID}.{DATASET_ID}")
    st.caption(f"Updated {datetime.now(UTC):%H:%M:%S} UTC")


with st.sidebar:
    st.markdown(
        '<div class="brand-title">🛡️ SOC AS-A-SERVICE</div>', unsafe_allow_html=True
    )
    st.markdown(
        '<div class="brand-sub">Cymbal Cyber · ADK multi-agent triage</div>',
        unsafe_allow_html=True,
    )

    for page in PAGES.values():
        label = page.title
        if page is PAGES["triage"]:
            label = f"{page.title} ({len(load_new_tickets())})"
        st.page_link(page, label=label, icon=page.icon, width="stretch")

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
                "Local mode: `python -m src.demo.local_runner --threat malicious` runs the full pipeline."
            )

navigation = st.navigation(list(PAGES.values()), position="hidden")
navigation.run()
