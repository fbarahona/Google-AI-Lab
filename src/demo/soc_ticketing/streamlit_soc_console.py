"""
SOC As-A-Service Monitoring Console & Ticketing Portal
======================================================
Comprehensive enterprise SOC portal matching the SOC As-A-Service dashboard:
1. Monitoring Overview (Full KPI summary, Donut charts, category bars, trend lines, world threat map)
2. New Tickets (Active incident queue for human triage with multimodal screenshot forensics)
3. Historic Tickets (Archived repository of Approved Genuine Threats vs Dismissed False Positives)
"""

import os
import re
import json
import time
import pandas as pd
import streamlit as st
from datetime import datetime, timezone
from streamlit_autorefresh import st_autorefresh

import sys
from pathlib import Path

# Ensure directory is on sys.path if run directly via `streamlit run`
_CURRENT_DIR = Path(__file__).resolve().parent
if str(_CURRENT_DIR) not in sys.path:
    sys.path.insert(0, str(_CURRENT_DIR))
_SRC_DIR = _CURRENT_DIR.parent.parent
if str(_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(_SRC_DIR))

try:
    from .ticketing_service import SocTicketingService
    from .dashboard_charts import (
        create_donut_chart,
        create_category_bar_chart,
        create_log_rate_chart,
        create_log_breakdown_chart,
        create_threat_trend_chart,
        create_threat_map_deck
    )
except ImportError:
    from ticketing_service import SocTicketingService
    from dashboard_charts import (
        create_donut_chart,
        create_category_bar_chart,
        create_log_rate_chart,
        create_log_breakdown_chart,
        create_threat_trend_chart,
        create_threat_map_deck
    )

# Page configuration
st.set_page_config(
    page_title="SOC As-A-Service",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Enterprise Dark Theme CSS styling matching Fortinet SOC Dashboard
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

# Autorefresh every 8 seconds
st_autorefresh(interval=8 * 1000, key="soc_autorefresh")

# Service initialization
PROJECT_ID = os.getenv("GOOGLE_CLOUD_PROJECT", "local-demo")
DATASET_ID = os.getenv("BIGQUERY_DATASET", "Cymbal_Cyber")
SCREENSHOTS_DIR = "src/demo/user_screenshots"

@st.cache_resource
def get_service() -> SocTicketingService:
    return SocTicketingService(project_id=PROJECT_ID, dataset_id=DATASET_ID)

service = get_service()

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

# Fetch Data
new_tickets = service.fetch_new_tickets()
historic_tickets = service.fetch_historic_tickets()

# Toast Feedback
if st.session_state.status_toast:
    st.toast(st.session_state.status_toast, icon="✅")
    st.session_state.status_toast = None


# ==============================================================================
# SIDEBAR NAVIGATION
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

    st.markdown("##### System Status")
    mode_name = "Cloud Mode (GCP)" if service.is_cloud_enabled() else "Local Simulation Mode"
    st.markdown(f"**Mode:** `{mode_name}`")
    st.markdown(f"**Target Project:** `{PROJECT_ID}`")
    st.markdown(f"**Pending Queue:** `{len(new_tickets)} tickets`")
    st.markdown(f"**Historic Archive:** `{len(historic_tickets)} tickets`")

    st.divider()
    time_filter = st.selectbox(
        "Time Range Filter",
        ["Last 24 Hours", "Last 7 Days", "Last 30 Days", "Last 90 Days"],
        index=3
    )

    if not service.is_cloud_enabled():
        st.info("💡 Running locally. To inject a fresh threat scenario, run:\n`python -m src.demo.local_runner --threat malicious`")


# ==============================================================================
# VIEW 1: MONITORING OVERVIEW (MATCHING UPLOADED DASHBOARD)
# ==============================================================================
if st.session_state.active_nav_tab == "Monitoring Overview":
    
    # Top Breadcrumb and Time Bar
    col_bread, col_time = st.columns([3, 1])
    with col_bread:
        st.markdown(f'<div class="breadcrumb-title">> <span>SOC Monitoring Overview</span> <span class="brand-pill">{time_filter}</span></div>', unsafe_allow_html=True)
    with col_time:
        if st.button("🚨 View Open Alerts Queue", type="primary", width="stretch"):
            st.session_state.active_nav_tab = "New Tickets"
            st.rerun()

    st.markdown(" ")

    # 1. Top KPI Summary Funnel
    total_escalated = len(new_tickets) + len([t for t in historic_tickets if t.get("human_decision") == "Genuine Threat"])
    triaged_count = len(historic_tickets)
    
    kpi_html = f"""
    <div class="kpi-container">
        <div class="kpi-item">
            <div class="kpi-val">10</div>
            <div class="kpi-lbl">Monitored Devices</div>
        </div>
        <div class="kpi-divider">›</div>
        <div class="kpi-item">
            <div class="kpi-val">2.6K</div>
            <div class="kpi-lbl">Monitored Endpoints</div>
        </div>
        <div class="kpi-divider">›</div>
        <div class="kpi-item">
            <div class="kpi-val">2.6K</div>
            <div class="kpi-lbl">Monitored Users</div>
        </div>
        <div class="kpi-divider">›</div>
        <div class="kpi-item">
            <div class="kpi-val">166.6K</div>
            <div class="kpi-lbl">Processed Logs</div>
        </div>
        <div class="kpi-divider">›</div>
        <div class="kpi-item">
            <div class="kpi-val">160</div>
            <div class="kpi-lbl">Security Events</div>
        </div>
        <div class="kpi-divider">›</div>
        <div class="kpi-item">
            <div class="kpi-val" style="color: #ff9800;">{max(23, triaged_count)}</div>
            <div class="kpi-lbl">Triaged Alerts</div>
        </div>
        <div class="kpi-divider">›</div>
        <div class="kpi-item">
            <div class="kpi-val" style="color: #f44336;">{max(12, total_escalated)}</div>
            <div class="kpi-lbl">Escalated Alerts</div>
        </div>
    </div>
    """
    st.markdown(kpi_html, unsafe_allow_html=True)

    # 2. Mid Row: 3 Donut Charts + 1 Horizontal Bar Chart
    c_sev, c_stat, c_sla, c_cat = st.columns([1, 1, 1, 1.4], gap="medium")

    # Donut 1: Alerts by Severity
    with c_sev:
        with st.container(border=True):
            st.markdown("**ALERTS BY SEVERITY**")
            sev_data = [
                {"severity": "Critical", "count": 4},
                {"severity": "High", "count": 5},
                {"severity": "Medium", "count": 2},
                {"severity": "Low", "count": 1}
            ]
            sev_colors = {"Critical": "#f44336", "High": "#ff9800", "Medium": "#ffca28", "Low": "#00e5ff"}
            chart_sev = create_donut_chart(sev_data, "severity", "count", sev_colors, center_label="Alerts", center_total=12)
            st.altair_chart(chart_sev, width="stretch", alt="Alerts by severity breakdown")

    # Donut 2: Alerts by Status
    with c_stat:
        with st.container(border=True):
            st.markdown("**ALERTS BY STATUS**")
            stat_data = [
                {"status": "Open", "count": max(1, len(new_tickets))},
                {"status": "In Progress", "count": 2},
                {"status": "Closed", "count": 6},
                {"status": "Escalated", "count": 3}
            ]
            stat_colors = {"Open": "#00e5ff", "In Progress": "#ff9800", "Closed": "#00e676", "Escalated": "#f44336"}
            chart_stat = create_donut_chart(stat_data, "status", "count", stat_colors, center_label="Alerts", center_total=12)
            st.altair_chart(chart_stat, width="stretch", alt="Alerts by status breakdown")

    # Donut 3: Alerts by SLA
    with c_sla:
        with st.container(border=True):
            st.markdown("**ALERTS BY SLA**")
            sla_data = [
                {"sla": "Within SLA", "count": 9},
                {"sla": "Approaching SLA", "count": 2},
                {"sla": "Breached SLA", "count": 1}
            ]
            sla_colors = {"Within SLA": "#00e676", "Approaching SLA": "#ffca28", "Breached SLA": "#f44336"}
            chart_sla = create_donut_chart(sla_data, "sla", "count", sla_colors, center_label="Alerts", center_total=12)
            st.altair_chart(chart_sla, width="stretch", alt="Alerts by SLA status breakdown")

    # Horizontal Bar: Open Alerts by Category
    with c_cat:
        with st.container(border=True):
            st.markdown("**OPEN ALERTS BY CATEGORY**")
            cat_data = [
                {"category": "Risky Domain/URL", "count": 3},
                {"category": "Malware", "count": 2},
                {"category": "Data Leak", "count": 1},
                {"category": "Botnet", "count": 1},
                {"category": "PUP", "count": 1},
                {"category": "Recon", "count": 1}
            ]
            chart_cat = create_category_bar_chart(cat_data)
            st.altair_chart(chart_cat, width="stretch", alt="Open alerts category breakdown")

    # 3. Third Row: Log Rate + Log Collection Breakdown + Threat Detection Trend
    c_rate, c_break, c_trend = st.columns([1, 1.2, 1], gap="medium")

    with c_rate:
        with st.container(border=True):
            st.markdown("**AVERAGE LOG RATE (per second)**")
            st.altair_chart(create_log_rate_chart(), width="stretch", alt="Average log rate trend")

    with c_break:
        with st.container(border=True):
            st.markdown("**LOG COLLECTION BREAKDOWN**")
            st.altair_chart(create_log_breakdown_chart(), width="stretch", alt="Log collection breakdown by source")

    with c_trend:
        with st.container(border=True):
            st.markdown("**THREAT DETECTION TREND**")
            st.altair_chart(create_threat_trend_chart(), width="stretch", alt="Threat detection trend over time")

    # 4. Global Threat Map
    with st.container(border=True):
        st.markdown("**GEOGRAPHICAL THREAT ORIGINS & REPUTATION MAP**")
        threat_deck = create_threat_map_deck()
        st.pydeck_chart(threat_deck, width="stretch")

    # 5. Quick Preview of Recent Alerts
    with st.container(border=True):
        st.markdown(f"**ACTIVE ALERTS REQUIRING TRIAGE ({len(new_tickets)})**")
        if not new_tickets:
            st.success("🟢 No pending alerts in the active queue. All threats are currently mitigated.")
        else:
            preview_rows = []
            for t in new_tickets[:5]:
                preview_rows.append({
                    "Ticket ID": t.get("ticket_id"),
                    "User": t.get("user_id"),
                    "Device": t.get("device_id"),
                    "Threat Score": t.get("threat_score"),
                    "Severity": t.get("severity"),
                    "Timestamp": str(t.get("timestamp") or t.get("created_at"))[:19]
                })
            st.dataframe(pd.DataFrame(preview_rows), width="stretch", hide_index=True)


# ==============================================================================
# VIEW 2: NEW TICKETS (TRIAGE QUEUE & WORKFLOW)
# ==============================================================================
elif st.session_state.active_nav_tab == "New Tickets":
    st.markdown('<div class="breadcrumb-title">> <span>SOC Portal</span> > <span class="breadcrumb-active">New Tickets Triage Queue</span></div>', unsafe_allow_html=True)
    st.markdown("### 🚨 Pending Incident Triage")
    st.caption("Review active alerts escalated by the Google ADK multi-agent pipeline and submit analyst determinations.")

    if not new_tickets:
        st.info("🟢 No pending incident tickets in the queue. All alerts have been adjudicated!")
        if st.button("➕ Inject Test Threat Scenario (Local Runner)"):
            with st.spinner("Injecting attack scenario..."):
                from ..data_generator.log_generator import SyntheticLogEngine
                from ..soc_ticketing.models import SocTicket
                eng = SyntheticLogEngine()
                acc, net = eng.inject_threat(threat_type="malicious", user_id="u.lewis")
                new_t_id = f"SOC-TICKET-u.lewis-{int(time.time())}"
                t_obj = SocTicket(
                    ticket_id=new_t_id,
                    user_id="u.lewis",
                    device_id="ws-hr-05",
                    source_ip="175.45.176.10",
                    threat_score=1950,
                    severity="CRITICAL",
                    status="ESCALATED",
                    agent_decision="PERCEIVED_THREAT",
                    agent_reason="APT attack: Mimikatz detected, North Korea C2 connection.",
                    structured_report="### Security Incident Report\n* **User:** u.lewis\n* **Severity:** CRITICAL",
                    screenshot_url="src/demo/user_screenshots/u.lewis.png"
                )
                service.create_and_dispatch_ticket(t_obj)
                st.session_state.status_toast = f"Injected ticket {new_t_id}!"
                st.rerun()

    else:
        col_list, col_inspect = st.columns([1, 2], gap="large")

        with col_list:
            st.subheader(f"Queue ({len(new_tickets)})")
            
            # Select first by default if none selected
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
                reason = current_ticket.get("agent_reason_for_escalation", "Threat score threshold exceeded.")

                with st.container(border=True):
                    st.markdown(f"#### Incident Dossier: `{tid}`")
                    
                    # Metadata badges
                    m_col1, m_col2, m_col3, m_col4 = st.columns(4)
                    m_col1.metric("Target Entity", user)
                    m_col2.metric("Workstation", dev)
                    m_col3.metric("Anomaly Score", score)
                    m_col4.metric("Severity", sev)

                    st.warning(f"**ADK Agent Rationale:** {reason}")

                    # Desktop Screenshot Viewer
                    screenshot_path = os.path.join(SCREENSHOTS_DIR, f"{user}.png")
                    if os.path.exists(screenshot_path):
                        with st.expander("🖼️ Workstation Desktop Screenshot Evidence", expanded=True):
                            st.image(screenshot_path, caption=f"Forensic Screenshot captured from device {dev} (User: {user})", width="stretch")

                    # Structured Report
                    report_text = current_ticket.get("context_for_human", "")
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
                        st.session_state.status_toast = f"Incident {tid} marked as '{dec_choice}' and archived to history!"
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
    h_m2.metric("Approved Threats", approved_threats, delta=f"{threat_rate:.1f}% ratio", delta_color="inverse")
    h_m3.metric("Dismissed False Positives", false_positives, delta=f"{fp_rate:.1f}% filtered", delta_color="normal")
    h_m4.metric("Avg Resolution Time (MTTR)", "18 mins", delta="-25% vs target")

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
