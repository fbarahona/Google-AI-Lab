"""
SOC As-A-Service Monitoring Console & Ticketing Portal
======================================================
Comprehensive enterprise SOC portal matching the SOC As-A-Service dashboard:
1. Monitoring Overview (Full KPI summary, Donut charts, category bars, trend lines, world threat map)
   - Backed directly by BigQuery (Cymbal_Cyber) as the Single Source of Truth.
2. New Tickets (Active incident queue for human triage with multimodal screenshot forensics)
3. Historic Tickets (Archived repository of Approved Genuine Threats vs Dismissed False Positives)
"""

import logging
import os
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

import pandas as pd
import streamlit as st
from streamlit_autorefresh import st_autorefresh

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
    from .models import SocTicket
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
    from models import SocTicket
    from ticketing_service import SocTicketingService

# Page configuration
st.set_page_config(
    page_title="SOC As-A-Service",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Enterprise Dark Theme CSS styling
st.markdown("""
<style>
    /* Dark Theme Base Overrides */
    .stApp {
        background-color: #0b111e;
        color: #f1f5f9;
    }
    header[data-testid="stHeader"] {
        background-color: #0b111e;
    }
    section[data-testid="stSidebar"] {
        background-color: #070b13;
        border-right: 1px solid #1e293b;
    }

    /* Metric Card Enhancements */
    div[data-testid="stMetric"] {
        background-color: #111a2d;
        border: 1px solid #1e293b;
        border-radius: 8px;
        padding: 12px 16px;
    }
    div[data-testid="stMetricLabel"] p {
        color: #94a3b8 !important;
        font-size: 0.85rem !important;
        font-weight: 500;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }
    div[data-testid="stMetricValue"] {
        color: #ffffff !important;
        font-weight: 700 !important;
    }

    /* Container Card borders */
    div[data-testid="stVerticalBlockBorderWrapper"] {
        background-color: #10192a;
        border: 1px solid #1e293b !important;
        border-radius: 8px;
    }

    /* Custom Header Pills & Brand */
    .brand-title {
        font-size: 1.25rem;
        font-weight: 800;
        letter-spacing: 1.5px;
        color: #ffffff;
        margin-bottom: 20px;
        display: flex;
        align-items: center;
        gap: 8px;
    }
    .brand-pill {
        color: #00e5ff;
        font-size: 0.8rem;
        font-weight: 700;
        background: rgba(0, 229, 255, 0.12);
        padding: 2px 8px;
        border-radius: 4px;
        border: 1px solid rgba(0, 229, 255, 0.3);
    }
    .breadcrumb-title {
        color: #94a3b8;
        font-size: 0.95rem;
        font-weight: 500;
        display: flex;
        align-items: center;
        gap: 6px;
    }
    .breadcrumb-active {
        color: #f8fafc;
        font-weight: 700;
    }

    /* Custom funnels */
    .kpi-container {
        display: flex;
        justify-content: space-between;
        align-items: center;
        gap: 8px;
        background: #10192a;
        border: 1px solid #1e293b;
        border-radius: 8px;
        padding: 16px 20px;
        margin-bottom: 20px;
    }
    .kpi-item {
        text-align: center;
        flex: 1;
    }
    .kpi-val {
        font-size: 1.5rem;
        font-weight: 700;
        color: #ffffff;
    }
    .kpi-lbl {
        font-size: 0.75rem;
        color: #94a3b8;
        margin-top: 4px;
        text-transform: uppercase;
        letter-spacing: 0.4px;
    }
    .kpi-divider {
        color: #334155;
        font-size: 1.2rem;
    }
</style>
""", unsafe_allow_html=True)

# Autorefresh every 15 seconds
st_autorefresh(interval=15 * 1000, key="soc_autorefresh")

# Service initialization
PROJECT_ID = os.getenv("GOOGLE_CLOUD_PROJECT", "local-demo")
DATASET_ID = os.getenv("BIGQUERY_DATASET", "Cymbal_Cyber")
REPO_ROOT = Path(__file__).resolve().parents[3]
SCREENSHOTS_DIR = str(REPO_ROOT / "local_demo_data" / "user_screenshots")


@st.cache_resource
def get_service() -> SocTicketingService:
    return SocTicketingService(project_id=PROJECT_ID, dataset_id=DATASET_ID)


service = get_service()


def format_count(n: int) -> str:
    """Formats large integer counts into clean human-readable units (K, M)."""
    if n >= 1_000_000:
        return f"{n / 1_000_000:.1f}M"
    if n >= 1_000:
        return f"{n / 1_000:.1f}K"
    return str(n)


def inject_threat_scenario(svc: SocTicketingService, threat_type: str, user_id: str):
    """Programmatically injects a threat scenario directly into BigQuery and SOC ticketing."""
    from demo.data_generator.log_generator import SyntheticLogEngine
    from demo.data_generator.sinks import BigQuerySink, LocalSink

    eng = SyntheticLogEngine(project_id=svc.project_id, dataset_id=svc.dataset_id)
    acc_events, net_events = eng.inject_threat(threat_type=threat_type, user_id=user_id)

    # 1. Write events to sink
    if svc.bq_client is not None:
        try:
            sink = BigQuerySink(project_id=svc.project_id, dataset_id=svc.dataset_id)
            sink.write_events(acc_events, net_events)
        except Exception as e:
            logger.warning("Could not write events to BigQuery sink: %s", e)
    else:
        LocalSink(output_dir=svc.queue_dir).write_events(acc_events, net_events)

    # 2. Create and dispatch SocTicket
    now_epoch = int(time.time())
    ticket_id = f"SOC-TICKET-{user_id}-{now_epoch}"
    is_malicious = (threat_type == "malicious")
    severity = "CRITICAL" if is_malicious else "LOW"
    score = 1950 if is_malicious else 120
    category = "Malware" if is_malicious else "Policy Violation"
    dev_id = acc_events[0].get("device_id", "ws-hr-05") if acc_events else "ws-hr-05"
    src_ip = acc_events[0].get("source_ip", "175.45.176.10") if acc_events else "175.45.176.10"
    reason = (
        "APT attack: Mimikatz credential theft and unauthorized connection to North Korea C2."
        if is_malicious else
        "IT maintenance backup script execution triggering threshold; verified benign routine."
    )
    report = (
        f"### Security Incident Report\n"
        f"* **Target Entity:** `{user_id}`\n"
        f"* **Device:** `{dev_id}`\n"
        f"* **Origin IP:** `{src_ip}`\n"
        f"* **Threat Score:** `{score}`\n"
        f"* **Severity:** `{severity}`\n\n"
        f"**Agent Investigation Summary:**\n"
        f"{reason}\n\n"
        f"**Indicators of Compromise:**\n"
        f"- `{src_ip}`\n"
    )
    ticket = SocTicket(
        ticket_id=ticket_id,
        user_id=user_id,
        device_id=dev_id,
        source_ip=src_ip,
        threat_score=score,
        severity=severity,
        status="ESCALATED",
        category=category,
        agent_decision="PERCEIVED_THREAT" if is_malicious else "FALSE_POSITIVE",
        agent_reason=reason,
        mitre_tactics=["Command and Control", "Execution", "Initial Access"] if is_malicious else ["Discovery"],
        indicators_of_compromise=[src_ip],
        structured_report=report,
        screenshot_url=f"{SCREENSHOTS_DIR}/{user_id}.png"
    )
    svc.create_and_dispatch_ticket(ticket)


def stream_benign_logs(svc: SocTicketingService, batch_size: int = 50):
    """Streams a batch of benign activity logs into BigQuery."""
    from demo.data_generator.log_generator import SyntheticLogEngine
    from demo.data_generator.sinks import BigQuerySink, LocalSink

    eng = SyntheticLogEngine(project_id=svc.project_id, dataset_id=svc.dataset_id)
    acc_events, net_events = eng.generate_benign_batch(count=batch_size)

    if svc.bq_client is not None:
        try:
            sink = BigQuerySink(project_id=svc.project_id, dataset_id=svc.dataset_id)
            sink.write_events(acc_events, net_events)
        except Exception as e:
            logger.warning("Could not write benign batch to BigQuery: %s", e)
    else:
        LocalSink(output_dir=svc.queue_dir).write_events(acc_events, net_events)


# Session State
if "selected_ticket_id" not in st.session_state:
    st.session_state.selected_ticket_id = None
if "active_nav_tab" not in st.session_state:
    st.session_state.active_nav_tab = "Monitoring Overview"
if "status_toast" not in st.session_state:
    st.session_state.status_toast = None
if "response_comment" not in st.session_state:
    st.session_state.response_comment = ""
if "decision_choice" not in st.session_state:
    st.session_state.decision_choice = "Genuine Threat"

# Toast Feedback
if st.session_state.status_toast:
    st.toast(st.session_state.status_toast, icon="✅")
    st.session_state.status_toast = None


# ==============================================================================
# SIDEBAR NAVIGATION & CONTROLS
# ==============================================================================
with st.sidebar:
    st.markdown('<div class="brand-title">🛡️ SOC AS-A-SERVICE</div>', unsafe_allow_html=True)

    nav_options = [
        "Monitoring Overview",
        "New Tickets",
        "Historic Tickets"
    ]

    selected_nav = st.radio(
        "Navigation",
        nav_options,
        index=nav_options.index(st.session_state.active_nav_tab) if st.session_state.active_nav_tab in nav_options else 0,
        label_visibility="collapsed"
    )
    st.session_state.active_nav_tab = selected_nav

    st.divider()

    time_filter = st.selectbox(
        "Time Range Filter",
        ["All Time", "Last 24 Hours", "Last 7 Days", "Last 30 Days", "Last 90 Days"],
        index=0
    )

    st.divider()

    # Dynamic Data Ingestion from BigQuery Single Source of Truth
    with st.spinner("Querying BigQuery telemetry..."):
        metrics = service.fetch_dashboard_metrics(time_range=time_filter)
        new_tickets = service.fetch_new_tickets()
        historic_tickets = service.fetch_historic_tickets()

    st.markdown("##### System Status")
    mode_name = "Cloud Mode (BigQuery SSOT)" if service.is_cloud_enabled() else "Local Simulation Mode"
    st.markdown(f"**Mode:** `{mode_name}`")
    st.markdown(f"**Dataset:** `{PROJECT_ID}.{DATASET_ID}`")
    st.markdown(f"**Pending Queue:** `{len(new_tickets)} tickets`")
    st.markdown(f"**Historic Archive:** `{len(historic_tickets)} tickets`")
    st.markdown(f"**Processed Logs:** `{format_count(metrics['processed_logs'])}`")
    st.markdown(f"**Security Events:** `{metrics['security_events']}`")

    if not service.is_cloud_enabled():
        st.info("💡 Running locally. To inject a fresh threat scenario, run:\n`python -m src.demo.local_runner --threat malicious`")


# ==============================================================================
# VIEW 1: MONITORING OVERVIEW (DYNAMIC BIGQUERY TELEMETRY)
# ==============================================================================
if st.session_state.active_nav_tab == "Monitoring Overview":

    # Top Breadcrumb and Action Bar
    col_bread, col_time = st.columns([3, 1])
    with col_bread:
        st.markdown(f'<div class="breadcrumb-title">> <span>SOC Monitoring Overview</span> <span class="brand-pill">{time_filter}</span></div>', unsafe_allow_html=True)
    with col_time:
        if st.button("🚨 View Open Alerts Queue", type="primary", width="stretch"):
            st.session_state.active_nav_tab = "New Tickets"
            st.rerun()

    st.markdown(" ")

    # 1. Top KPI Summary Funnel (Dynamic from BigQuery)
    kpi_html = f"""
    <div class="kpi-container">
        <div class="kpi-item">
            <div class="kpi-val">{format_count(metrics['monitored_devices'])}</div>
            <div class="kpi-lbl">Monitored Devices</div>
        </div>
        <div class="kpi-divider">&rsaquo;</div>
        <div class="kpi-item">
            <div class="kpi-val">{format_count(metrics['monitored_endpoints'])}</div>
            <div class="kpi-lbl">Monitored Endpoints</div>
        </div>
        <div class="kpi-divider">&rsaquo;</div>
        <div class="kpi-item">
            <div class="kpi-val">{format_count(metrics['monitored_users'])}</div>
            <div class="kpi-lbl">Monitored Users</div>
        </div>
        <div class="kpi-divider">&rsaquo;</div>
        <div class="kpi-item">
            <div class="kpi-val">{format_count(metrics['processed_logs'])}</div>
            <div class="kpi-lbl">Processed Logs</div>
        </div>
        <div class="kpi-divider">&rsaquo;</div>
        <div class="kpi-item">
            <div class="kpi-val">{format_count(metrics['security_events'])}</div>
            <div class="kpi-lbl">Security Events</div>
        </div>
        <div class="kpi-divider">&rsaquo;</div>
        <div class="kpi-item">
            <div class="kpi-val" style="color: #ff9800;">{format_count(metrics['triaged_alerts'])}</div>
            <div class="kpi-lbl">Triaged Alerts</div>
        </div>
        <div class="kpi-divider">&rsaquo;</div>
        <div class="kpi-item">
            <div class="kpi-val" style="color: #f44336;">{format_count(metrics['escalated_alerts'])}</div>
            <div class="kpi-lbl">Escalated Alerts</div>
        </div>
    </div>
    """
    st.markdown(kpi_html, unsafe_allow_html=True)

    # Clean Ingestion Action Card when BigQuery dataset is empty
    if metrics["processed_logs"] == 0 and len(new_tickets) == 0:
        with st.container(border=True):
            st.markdown("### 📡 BigQuery Telemetry Pipeline Connected — Ready for Ingestion")
            st.markdown(
                f"BigQuery dataset **`{PROJECT_ID}.{DATASET_ID}`** is currently at baseline zero. "
                "You can generate synthetic enterprise access/network logs or inject live threat scenarios to see the real-time AI detection pipeline in action."
            )
            col_b1, col_b2, col_b3 = st.columns([1, 1, 1])
            with col_b1:
                if st.button("🚨 Inject Malicious APT Scenario (u.lewis)", type="primary", width="stretch"):
                    with st.spinner("Injecting malicious scenario into BigQuery..."):
                        inject_threat_scenario(service, threat_type="malicious", user_id="u.lewis")
                        st.session_state.status_toast = "Malicious APT scenario injected into BigQuery!"
                        st.rerun()
            with col_b2:
                if st.button("🛡️ Inject False Positive Scenario (l.taylor)", width="stretch"):
                    with st.spinner("Injecting false positive scenario into BigQuery..."):
                        inject_threat_scenario(service, threat_type="false_positive", user_id="l.taylor")
                        st.session_state.status_toast = "False Positive scenario injected into BigQuery!"
                        st.rerun()
            with col_b3:
                if st.button("📊 Stream 50 Benign Enterprise Logs", width="stretch"):
                    with st.spinner("Streaming benign activity to BigQuery..."):
                        stream_benign_logs(service, batch_size=50)
                        st.session_state.status_toast = "Streamed 50 benign logs to BigQuery!"
                        st.rerun()

    # 2. Mid Row: 3 Donut Charts + 1 Horizontal Bar Chart
    c_sev, c_stat, c_sla, c_cat = st.columns([1, 1, 1, 1.4], gap="medium")
    total_alerts_count = metrics["triaged_alerts"] + metrics["escalated_alerts"]

    # Donut 1: Alerts by Severity
    with c_sev:
        with st.container(border=True):
            st.markdown("**ALERTS BY SEVERITY**")
            sev_colors = {"Critical": "#f44336", "High": "#ff9800", "Medium": "#ffca28", "Low": "#00e5ff"}
            chart_sev = create_donut_chart(
                metrics["alerts_by_severity"],
                "severity",
                "count",
                sev_colors,
                center_label="Alerts",
                center_total=total_alerts_count
            )
            st.altair_chart(chart_sev, width="stretch")

    # Donut 2: Alerts by Status
    with c_stat:
        with st.container(border=True):
            st.markdown("**ALERTS BY STATUS**")
            stat_colors = {"Open": "#00e5ff", "In Progress": "#ff9800", "Closed": "#00e676", "Escalated": "#f44336"}
            chart_stat = create_donut_chart(
                metrics["alerts_by_status"],
                "status",
                "count",
                stat_colors,
                center_label="Alerts",
                center_total=total_alerts_count
            )
            st.altair_chart(chart_stat, width="stretch")

    # Donut 3: Alerts by SLA
    with c_sla:
        with st.container(border=True):
            st.markdown("**ALERTS BY SLA**")
            sla_colors = {"Within SLA": "#00e676", "Approaching SLA": "#ffca28", "Breached SLA": "#f44336"}
            chart_sla = create_donut_chart(
                metrics["alerts_by_sla"],
                "sla",
                "count",
                sla_colors,
                center_label="Alerts",
                center_total=total_alerts_count
            )
            st.altair_chart(chart_sla, width="stretch")

    # Horizontal Bar: Open Alerts by Category
    with c_cat:
        with st.container(border=True):
            st.markdown("**OPEN ALERTS BY CATEGORY**")
            chart_cat = create_category_bar_chart(metrics["alerts_by_category"])
            st.altair_chart(chart_cat, width="stretch")

    # 3. Third Row: Log Rate + Log Collection Breakdown + Threat Detection Trend
    c_rate, c_break, c_trend = st.columns([1, 1.2, 1], gap="medium")

    with c_rate:
        with st.container(border=True):
            st.markdown("**AVERAGE LOG RATE (per second)**")
            st.altair_chart(create_log_rate_chart(metrics["log_rate_trend"]), width="stretch")

    with c_break:
        with st.container(border=True):
            st.markdown("**LOG COLLECTION BREAKDOWN**")
            st.altair_chart(create_log_breakdown_chart(metrics["log_breakdown"]), width="stretch")

    with c_trend:
        with st.container(border=True):
            st.markdown("**THREAT DETECTION TREND**")
            st.altair_chart(create_threat_trend_chart(metrics["threat_trend"]), width="stretch")

    # 4. Global Threat Map
    with st.container(border=True):
        st.markdown(f"**GEOGRAPHICAL THREAT ORIGINS & REPUTATION MAP ({len(metrics['threat_points'])} Active Locations)**")
        threat_deck = create_threat_map_deck(metrics["threat_points"])
        st.pydeck_chart(threat_deck, width="stretch")

    # 5. Quick Preview of Recent Alerts
    with st.container(border=True):
        st.markdown(f"**ACTIVE ALERTS REQUIRING TRIAGE ({len(new_tickets)})**")
        if not new_tickets:
            st.success("🟢 No pending alerts in the active queue. All threats are currently mitigated.")
        else:
            preview_rows = []
            for t in new_tickets[:10]:
                preview_rows.append({
                    "Ticket ID": t.get("ticket_id"),
                    "User": t.get("user_id"),
                    "Device": t.get("device_id"),
                    "Origin IP": t.get("source_ip"),
                    "Threat Score": t.get("threat_score"),
                    "Severity": t.get("severity"),
                    "Created At": str(t.get("created_at") or t.get("timestamp"))[:19]
                })
            st.dataframe(pd.DataFrame(preview_rows), width="stretch", hide_index=True)


# ==============================================================================
# VIEW 2: NEW TICKETS (ACTIVE TRIAGE QUEUE & WORKFLOW)
# ==============================================================================
elif st.session_state.active_nav_tab == "New Tickets":
    st.markdown('<div class="breadcrumb-title">> <span>SOC Portal</span> > <span class="breadcrumb-active">New Tickets Triage Queue</span></div>', unsafe_allow_html=True)
    st.markdown("### 🚨 Pending Incident Triage")
    st.caption("Review active alerts escalated by the Google ADK multi-agent pipeline and submit analyst determinations.")

    if not new_tickets:
        st.info("🟢 No pending incident tickets in the queue. All alerts have been adjudicated!")
        col_in1, col_in2 = st.columns(2)
        with col_in1:
            if st.button("🚨 Inject Malicious Threat Scenario (u.lewis)", type="primary", width="stretch"):
                with st.spinner("Injecting attack scenario into BigQuery..."):
                    inject_threat_scenario(service, threat_type="malicious", user_id="u.lewis")
                    st.session_state.status_toast = "Injected Malicious APT scenario into BigQuery!"
                    st.rerun()
        with col_in2:
            if st.button("🛡️ Inject False Positive Scenario (l.taylor)", width="stretch"):
                with st.spinner("Injecting false positive scenario into BigQuery..."):
                    inject_threat_scenario(service, threat_type="false_positive", user_id="l.taylor")
                    st.session_state.status_toast = "Injected False Positive scenario into BigQuery!"
                    st.rerun()

    else:
        col_list, col_inspect = st.columns([1, 2], gap="large")

        with col_list:
            st.subheader(f"Queue ({len(new_tickets)})")

            valid_ids = [t.get("ticket_id") for t in new_tickets]
            if st.session_state.selected_ticket_id not in valid_ids:
                st.session_state.selected_ticket_id = valid_ids[0]

            for item in new_tickets:
                tid = item.get("ticket_id")
                user = item.get("user_id", "Unknown")
                score = item.get("threat_score", "N/A")
                sev = item.get("severity", "HIGH")

                is_selected = (tid == st.session_state.selected_ticket_id)
                btn_border = "primary" if is_selected else "secondary"

                label = f"🚨 {tid}\nUser: {user} | Score: {score} | {sev}"
                if st.button(label, key=f"q_{tid}", type=btn_border, width="stretch"):
                    st.session_state.selected_ticket_id = tid
                    st.session_state.response_comment = ""
                    st.rerun()

        with col_inspect:
            current_ticket = next((t for t in new_tickets if t.get("ticket_id") == st.session_state.selected_ticket_id), None)

            if not current_ticket:
                st.info("Select a ticket from the queue on the left.")
            else:
                tid = current_ticket.get("ticket_id")
                user = current_ticket.get("user_id", "Unknown")
                dev = current_ticket.get("device_id", "Unknown")
                ip = current_ticket.get("source_ip", "Unknown")
                score = current_ticket.get("threat_score", "N/A")
                sev = current_ticket.get("severity", "HIGH")
                reason = (
                    current_ticket.get("agent_reason")
                    or current_ticket.get("agent_reason_for_escalation")
                    or "Threat score threshold exceeded."
                )

                with st.container(border=True):
                    st.markdown(f"#### Incident Dossier: `{tid}`")

                    # Metadata badges
                    m_col1, m_col2, m_col3, m_col4 = st.columns(4)
                    m_col1.metric("Target Entity", user)
                    m_col2.metric("Workstation", dev)
                    m_col3.metric("Anomaly Score", score)
                    m_col4.metric("Severity", sev)

                    st.warning(f"**ADK Agent Rationale:** {reason}")

                    # Desktop Screenshot Evidence
                    screenshot_url = current_ticket.get("screenshot_url")
                    screenshot_path = os.path.join(SCREENSHOTS_DIR, f"{user}.png")
                    if os.path.exists(screenshot_path):
                        with st.expander("🖼️ Workstation Desktop Screenshot Evidence", expanded=True):
                            st.image(screenshot_path, caption=f"Forensic Screenshot captured from device {dev} (User: {user})", width="stretch")
                    elif screenshot_url and screenshot_url.startswith("http"):
                        with st.expander("🖼️ Workstation Desktop Screenshot Evidence", expanded=True):
                            st.image(screenshot_url, caption=f"Forensic Screenshot for User: {user}", width="stretch")

                    # Full Forensic Report
                    report_text = (
                        current_ticket.get("structured_report")
                        or current_ticket.get("context_for_human")
                        or "*No structured report content recorded.*"
                    )
                    with st.expander("📋 Full Multi-Agent Forensic Investigation Report", expanded=True):
                        st.markdown(report_text, unsafe_allow_html=True)

                    st.divider()
                    st.markdown("#### SOC Analyst Adjudication")

                    dec_choice = st.radio(
                        "Analyst Determination:",
                        ["Genuine Threat", "False Positive"],
                        key="triage_decision",
                        horizontal=True
                    )

                    comment = st.text_area(
                        "Analyst Resolution Notes:",
                        placeholder="Document remediation actions taken (e.g. host isolation, credential revocation) or rationale for false positive dismissal...",
                        key="triage_comment",
                        height=100
                    )

                    if st.button("Submit Resolution & Archive Incident", type="primary", width="stretch"):
                        service.record_human_verdict(tid, dec_choice, comment)
                        st.session_state.status_toast = f"Incident {tid} marked as '{dec_choice}' and archived to BigQuery history!"
                        st.session_state.selected_ticket_id = None
                        st.session_state.active_nav_tab = "Historic Tickets"
                        st.rerun()


# ==============================================================================
# VIEW 3: HISTORIC TICKETS (APPROVED THREATS & FALSE POSITIVES)
# ==============================================================================
elif st.session_state.active_nav_tab == "Historic Tickets":
    st.markdown('<div class="breadcrumb-title">> <span>SOC Portal</span> > <span class="breadcrumb-active">Historic Tickets Archive</span></div>', unsafe_allow_html=True)
    st.markdown("### 📜 Historic Incident Archive")
    st.caption("Complete historical repository of adjudicated security incidents, approved genuine threats, and dismissed false positives.")

    # KPI Summary Row
    total_hist = len(historic_tickets)
    approved_threats = len([t for t in historic_tickets if t.get("human_decision") == "Genuine Threat"])
    false_positives = len([t for t in historic_tickets if t.get("human_decision") == "False Positive"])
    threat_rate = (approved_threats / total_hist * 100) if total_hist > 0 else 0
    fp_rate = (false_positives / total_hist * 100) if total_hist > 0 else 0

    h_m1, h_m2, h_m3, h_m4 = st.columns(4)
    h_m1.metric("Total Archived Incidents", total_hist)
    h_m2.metric("Approved Threats", approved_threats, delta=f"{threat_rate:.1f}% ratio" if total_hist > 0 else None, delta_color="inverse")
    h_m3.metric("Dismissed False Positives", false_positives, delta=f"{fp_rate:.1f}% filtered" if total_hist > 0 else None, delta_color="normal")
    h_m4.metric("Avg Resolution Time (MTTR)", "18 mins" if total_hist > 0 else "0 mins")

    st.divider()

    # Search and Filters
    f_col1, f_col2, f_col3 = st.columns([2, 1, 1])
    with f_col1:
        search_query = st.text_input("🔍 Search Archive by User, Ticket ID, IP, or Notes", placeholder="e.g. u.lewis, Mimikatz, North Korea...")
    with f_col2:
        verdict_filter = st.selectbox("Filter by Verdict", ["All Verdicts", "Genuine Threat", "False Positive"])
    with f_col3:
        severity_filter = st.selectbox("Filter by Severity", ["All Severities", "CRITICAL", "HIGH", "MEDIUM", "LOW"])

    # Filter Logic
    filtered_tickets = historic_tickets
    if verdict_filter != "All Verdicts":
        filtered_tickets = [t for t in filtered_tickets if t.get("human_decision") == verdict_filter]
    if severity_filter != "All Severities":
        filtered_tickets = [t for t in filtered_tickets if t.get("severity") == severity_filter]
    if search_query:
        q = search_query.lower()
        filtered_tickets = [
            t for t in filtered_tickets if
            q in str(t.get("ticket_id", "")).lower() or
            q in str(t.get("user_id", "")).lower() or
            q in str(t.get("source_ip", "")).lower() or
            q in str(t.get("human_comment", "")).lower() or
            q in str(t.get("agent_reason", "")).lower()
        ]

    # Historical Data Table
    table_rows = []
    for t in filtered_tickets:
        table_rows.append({
            "Ticket ID": t.get("ticket_id"),
            "User": t.get("user_id"),
            "Origin IP": t.get("source_ip"),
            "Anomaly Score": t.get("threat_score"),
            "Severity": t.get("severity"),
            "Analyst Verdict": "🔴 Genuine Threat" if t.get("human_decision") == "Genuine Threat" else "🟢 False Positive",
            "Resolution Notes": t.get("human_comment") or "N/A",
            "Adjudicated At": str(t.get("adjudicated_at") or t.get("created_at"))[:19]
        })

    st.dataframe(
        pd.DataFrame(table_rows),
        width="stretch",
        hide_index=True
    )

    st.divider()

    # Detailed Audit Inspector
    st.markdown("#### 🔍 Historical Incident Dossier Inspector")
    if filtered_tickets:
        ticket_options = [f"{t.get('ticket_id')} ({t.get('user_id')} - {t.get('human_decision')})" for t in filtered_tickets]
        selected_option = st.selectbox("Select Historical Incident to Inspect", ticket_options)
        selected_tid = selected_option.split(" ")[0]

        inspect_item = next((t for t in filtered_tickets if t.get("ticket_id") == selected_tid), None)

        if inspect_item:
            with st.container(border=True):
                st.markdown(f"### Ticket Audit Record: `{selected_tid}`")

                i_c1, i_c2, i_c3 = st.columns(3)
                i_c1.markdown(f"**Entity / User:** `{inspect_item.get('user_id')}`")
                i_c2.markdown(f"**Originating IP:** `{inspect_item.get('source_ip')}` ({inspect_item.get('geo_country', 'External')})")
                i_c3.markdown(f"**Final Verdict:** `{'GENUINE THREAT' if inspect_item.get('human_decision') == 'Genuine Threat' else 'FALSE POSITIVE'}`")

                st.info(f"**Analyst Notes:** {inspect_item.get('human_comment', 'No notes entered.')}")

                # Screenshot preview
                h_user = inspect_item.get("user_id", "")
                h_screenshot = os.path.join(SCREENSHOTS_DIR, f"{h_user}.png")
                if os.path.exists(h_screenshot):
                    st.image(h_screenshot, caption=f"Archived Screenshot Evidence for {h_user}", width="stretch")

                st.markdown("##### Original Agent Investigation Report")
                st.markdown(inspect_item.get("structured_report", "*No report content.*"), unsafe_allow_html=True)
    else:
        st.info("No historical tickets match the selected filters.")
