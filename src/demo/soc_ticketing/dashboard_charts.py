"""
Interactive Altair and Pydeck Charts for SOC Monitoring Dashboard.
Matches the enterprise SOC As-A-Service dashboard layout.
Fully dynamic: accepts real aggregated telemetry from BigQuery with clean empty-state fallbacks.
"""

from datetime import UTC, datetime, timedelta
from typing import Any

import altair as alt
import pandas as pd
import pydeck as pdk


def create_donut_chart(
    data: list[dict[str, Any]] | None,
    category_col: str,
    value_col: str,
    color_map: dict[str, str],
    center_label: str = "Alerts",
    center_total: int = 0
) -> alt.LayerChart:
    """
    Renders an enterprise ring/donut chart with centered total count text.
    Handles empty dataset with a muted placeholder ring.
    """
    df = pd.DataFrame(data) if data else pd.DataFrame()
    if df.empty or center_total == 0:
        df = pd.DataFrame({category_col: ["None"], value_col: [1]})
        display_color_map = {"None": "#334155"}
    else:
        display_color_map = color_map

    arc = alt.Chart(df).mark_arc(innerRadius=52, outerRadius=76, stroke="#0f172a", strokeWidth=2).encode(
        theta=alt.Theta(f"{value_col}:Q", stack=True),
        color=alt.Color(
            f"{category_col}:N",
            scale=alt.Scale(domain=list(display_color_map.keys()), range=list(display_color_map.values())),
            legend=alt.Legend(
                orient="bottom",
                title=None,
                labelColor="#cbd5e1",
                labelFontSize=11,
                columns=2,
                symbolType="circle"
            )
        ),
        tooltip=[alt.Tooltip(f"{category_col}:N", title="Category"), alt.Tooltip(f"{value_col}:Q", title="Count")]
    )

    center_num_df = pd.DataFrame([{"text": str(center_total)}])
    center_num = alt.Chart(center_num_df).mark_text(
        fontSize=24,
        fontWeight=700,
        color="#ffffff",
        dy=-6
    ).encode(text="text:N")

    center_lbl_df = pd.DataFrame([{"text": center_label}])
    center_lbl = alt.Chart(center_lbl_df).mark_text(
        fontSize=11,
        fontWeight=400,
        color="#94a3b8",
        dy=14
    ).encode(text="text:N")

    chart = (arc + center_num + center_lbl).properties(
        height=210
    ).configure_view(
        strokeWidth=0
    )

    return chart


def create_category_bar_chart(category_data: list[dict[str, Any]] | None = None) -> alt.Chart:
    """
    Horizontal bar chart displaying Open Alerts by Category.
    """
    df = pd.DataFrame(category_data) if category_data else pd.DataFrame()
    if df.empty:
        df = pd.DataFrame({
            "category": ["No Data"],
            "count": [0]
        })

    palette = {
        "Risky Domain/URL": "#c0ca33",
        "Malware": "#ff7043",
        "Data Leak": "#ff8a65",
        "Botnet": "#ffb74d",
        "PUP": "#81c784",
        "Recon": "#29b6f6",
        "Initial Access": "#ff5252",
        "Execution": "#ff7043",
        "Command and Control": "#ff9800",
        "Privilege Escalation": "#ab47bc",
        "Discovery": "#26a69a",
        "Collection": "#42a5f5",
        "Policy Violation": "#ab47bc",
        "No Data": "#475569"
    }

    bars = alt.Chart(df).mark_bar(
        cornerRadiusTopRight=4,
        cornerRadiusBottomRight=4,
        height=16
    ).encode(
        x=alt.X("count:Q", axis=alt.Axis(
            title=None,
            tickMinStep=1,
            grid=True,
            gridColor="#1e293b",
            labelColor="#94a3b8",
            labelFontSize=11
        )),
        y=alt.Y("category:N", sort="-x", axis=alt.Axis(
            title=None,
            labelColor="#e2e8f0",
            labelFontSize=11,
            labelLimit=140
        )),
        color=alt.Color(
            "category:N",
            scale=alt.Scale(domain=list(palette.keys()), range=list(palette.values())),
            legend=None
        ),
        tooltip=["category:N", "count:Q"]
    )

    text = bars.mark_text(
        align="left",
        baseline="middle",
        dx=5,
        color="#ffffff",
        fontSize=11,
        fontWeight=600
    ).encode(
        text="count:Q"
    )

    return (bars + text).properties(
        height=210
    ).configure_view(
        strokeWidth=0
    )


def create_log_rate_chart(rate_data: list[dict[str, Any]] | None = None) -> alt.Chart:
    """
    Area chart for Average Log Rate (per second).
    """
    if not rate_data:
        rate_data = [
            {"date": (datetime.now(UTC) - timedelta(days=i)).strftime("%m/%d"), "rate": 0.0}
            for i in reversed(range(7))
        ]
    df = pd.DataFrame(rate_data)

    chart = alt.Chart(df).mark_area(
        line={"color": "#00e5ff", "width": 2},
        color=alt.Gradient(
            gradient="linear",
            stops=[
                alt.GradientStop(color="rgba(0, 229, 255, 0.45)", offset=0),
                alt.GradientStop(color="rgba(0, 229, 255, 0.02)", offset=1)
            ],
            x1=1, x2=1, y1=1, y2=0
        )
    ).encode(
        x=alt.X("date:N", axis=alt.Axis(title=None, labelColor="#94a3b8", grid=False)),
        y=alt.Y("rate:Q", axis=alt.Axis(
            title=None,
            format="~s",
            labelColor="#94a3b8",
            grid=True,
            gridColor="#1e293b"
        )),
        tooltip=[alt.Tooltip("date:N", title="Date"), alt.Tooltip("rate:Q", title="Rate (events/s)")]
    ).properties(height=180).configure_view(strokeWidth=0)

    return chart


def create_log_breakdown_chart(breakdown_data: list[dict[str, Any]] | None = None) -> alt.Chart:
    """
    Stacked bar chart for Log Collection Breakdown.
    """
    if not breakdown_data:
        breakdown_data = [
            {"date": (datetime.now(UTC) - timedelta(days=i)).strftime("%m/%d"), "type": "No Data", "volume": 0}
            for i in reversed(range(5))
        ]
    df = pd.DataFrame(breakdown_data)
    types = list(df["type"].unique())
    palette_options = ["#ffb300", "#00b0ff", "#00e676", "#ab47bc", "#26a69a", "#64748b"]
    palette = palette_options[:len(types)]

    chart = alt.Chart(df).mark_bar(width=28).encode(
        x=alt.X("date:N", axis=alt.Axis(title=None, labelColor="#94a3b8")),
        y=alt.Y("volume:Q", axis=alt.Axis(
            title=None,
            labelColor="#94a3b8",
            grid=True,
            gridColor="#1e293b"
        ), stack="zero"),
        color=alt.Color(
            "type:N",
            scale=alt.Scale(domain=types, range=palette),
            legend=alt.Legend(orient="top", title=None, labelColor="#cbd5e1", labelFontSize=10, columns=3)
        ),
        tooltip=["date:N", "type:N", alt.Tooltip("volume:Q", title="Volume")]
    ).properties(height=180).configure_view(strokeWidth=0)

    return chart


def create_threat_trend_chart(trend_data: list[dict[str, Any]] | None = None) -> alt.Chart:
    """
    Multi-line chart for Threat Detection Trend over time.
    """
    if not trend_data:
        trend_data = [
            {"date": (datetime.now(UTC) - timedelta(days=i)).strftime("%m/%d"), "metric": "Security Events", "count": 0}
            for i in reversed(range(5))
        ]
    df = pd.DataFrame(trend_data)
    palette = {
        "Security Events": "#ffca28",
        "Triaged Alerts": "#ff9800",
        "Escalated Alerts": "#f44336"
    }

    chart = alt.Chart(df).mark_line(point=True, strokeWidth=2).encode(
        x=alt.X("date:N", axis=alt.Axis(title=None, labelColor="#94a3b8")),
        y=alt.Y("count:Q", axis=alt.Axis(title=None, labelColor="#94a3b8", grid=True, gridColor="#1e293b")),
        color=alt.Color(
            "metric:N",
            scale=alt.Scale(domain=list(palette.keys()), range=list(palette.values())),
            legend=alt.Legend(orient="top", title=None, labelColor="#cbd5e1", labelFontSize=10)
        ),
        tooltip=["date:N", "metric:N", "count:Q"]
    ).properties(height=180).configure_view(strokeWidth=0)

    return chart


def create_threat_map_deck(threat_points: list[dict[str, Any]] | None = None) -> pdk.Deck:
    """
    Interactive Global Threat Map matching the Fortinet world map style.
    """
    if not threat_points:
        df = pd.DataFrame(columns=["name", "lat", "lon", "threat", "score", "color"])
    else:
        df = pd.DataFrame(threat_points)

    view_state = pdk.ViewState(
        latitude=35.0,
        longitude=10.0,
        zoom=1.1,
        min_zoom=1,
        max_zoom=10,
        pitch=0
    )

    layers = []
    if not df.empty and "lat" in df.columns and "lon" in df.columns:
        scatter = pdk.Layer(
            "ScatterplotLayer",
            data=df,
            get_position=["lon", "lat"],
            get_color="color",
            get_radius=550000,
            radius_min_pixels=6,
            radius_max_pixels=25,
            pickable=True,
            auto_highlight=True
        )
        layers.append(scatter)

    deck = pdk.Deck(
        layers=layers,
        initial_view_state=view_state,
        map_style="https://basemaps.cartocdn.com/gl/dark-matter-gl-style/style.json",
        tooltip={"text": "🚨 {name}\nThreat: {threat}\nAnomaly Score: {score}"}
    )

    return deck
