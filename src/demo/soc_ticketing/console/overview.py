"""Page 1: the SOC monitoring overview (KPI funnel, charts, threat map, alerts)."""

from datetime import UTC, datetime

import pandas as pd
import streamlit as st

from src.demo.soc_ticketing.console.config import (
    DATASET_ID,
    PROJECT_ID,
    SEVERITY_ICONS,
    TIME_RANGE_LABELS,
    TIME_RANGES,
)
from src.demo.soc_ticketing.console.data import (
    inject,
    live_interval,
    load_metrics,
    load_new_tickets,
    stream_logs,
)
from src.demo.soc_ticketing.console.formatting import format_count, short_ts
from src.demo.soc_ticketing.console.navigation import registered_pages
from src.demo.soc_ticketing.dashboard_charts import (
    create_category_bar_chart,
    create_donut_chart,
    create_log_breakdown_chart,
    create_log_rate_chart,
    create_threat_map_deck,
    create_threat_trend_chart,
)


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
            format_func=lambda k: TIME_RANGE_LABELS.get(k, str(k)),
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
            st.switch_page(registered_pages()["triage"])

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
                st.switch_page(registered_pages()["triage"])

    st.caption(f"Last updated {datetime.now(UTC):%H:%M:%S} UTC")
