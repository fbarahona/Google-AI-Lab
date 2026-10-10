"""
Interactive Altair and Pydeck Charts for SOC Monitoring Dashboard.
Matches the enterprise SOC As-A-Service dashboard layout.
"""

import pandas as pd
import altair as alt
import pydeck as pdk
from typing import Dict, Any, List


def create_donut_chart(
    data: List[Dict[str, Any]],
    category_col: str,
    value_col: str,
    color_map: Dict[str, str],
    center_label: str = "Alerts",
    center_total: int = 12
) -> alt.LayerChart:
    """
    Renders an enterprise ring/donut chart with centered total count text.
    """
    df = pd.DataFrame(data)
    if df.empty:
        df = pd.DataFrame({category_col: ["None"], value_col: [1]})
        color_map = {"None": "#475569"}

    # Base arc
    arc = alt.Chart(df).mark_arc(innerRadius=52, outerRadius=76, stroke="#0f172a", strokeWidth=2).encode(
        theta=alt.Theta(f"{value_col}:Q", stack=True),
        color=alt.Color(
            f"{category_col}:N",
            scale=alt.Scale(domain=list(color_map.keys()), range=list(color_map.values())),
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

    # Centered metric number
    center_num_df = pd.DataFrame([{"text": str(center_total)}])
    center_num = alt.Chart(center_num_df).mark_text(
        fontSize=24,
        fontWeight=700,
        color="#ffffff",
        dy=-6
    ).encode(text="text:N")

    # Centered metric subtitle
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


def create_category_bar_chart(category_data: List[Dict[str, Any]]) -> alt.Chart:
    """
    Horizontal bar chart displaying Open Alerts by Category.
    """
    df = pd.DataFrame(category_data)
    if df.empty:
        df = pd.DataFrame({
            "category": ["Risky Domain/URL", "Malware", "Data Leak", "Botnet", "PUP", "Recon"],
            "count": [3, 2, 1, 1, 1, 1]
        })

    palette = {
        "Risky Domain/URL": "#c0ca33",
        "Malware": "#ff7043",
        "Data Leak": "#ff8a65",
        "Botnet": "#ffb74d",
        "PUP": "#81c784",
        "Recon": "#29b6f6",
        "Policy Violation": "#ab47bc"
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


def create_log_rate_chart() -> alt.Chart:
    """
    Area chart for Average Log Rate (per second).
    """
    data = [
        {"date": "10/10", "rate": 1.2},
        {"date": "10/14", "rate": 1.9},
        {"date": "10/22", "rate": 3.6},
        {"date": "10/26", "rate": 2.4},
        {"date": "10/29", "rate": 1.5},
        {"date": "10/30", "rate": 3.1},
        {"date": "10/31", "rate": 2.2}
    ]
    df = pd.DataFrame(data)

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
            labelExpr="datum.value + 'M'",
            labelColor="#94a3b8",
            grid=True,
            gridColor="#1e293b"
        )),
        tooltip=[alt.Tooltip("date:N", title="Date"), alt.Tooltip("rate:Q", title="Rate (M/s)")]
    ).properties(height=180).configure_view(strokeWidth=0)

    return chart


def create_log_breakdown_chart() -> alt.Chart:
    """
    Stacked bar chart for Log Collection Breakdown.
    """
    rows = []
    dates = ["10/10", "10/22", "10/29", "10/30", "10/31"]
    types = ["Access Events", "Network Traffic", "DNS Queries", "VPN Sessions", "Firewall Rules"]
    volumes = [
        [3.0, 5.0, 2.0, 1.5, 1.8],
        [4.5, 7.2, 3.5, 2.0, 2.5],
        [4.0, 6.8, 3.2, 2.2, 2.1],
        [2.0, 3.5, 1.8, 1.0, 1.2],
        [2.2, 4.0, 2.0, 1.1, 1.3]
    ]

    for d_idx, d in enumerate(dates):
        for t_idx, t in enumerate(types):
            rows.append({"date": d, "type": t, "volume": volumes[d_idx][t_idx]})

    df = pd.DataFrame(rows)
    palette = ["#ffb300", "#00b0ff", "#00e676", "#ab47bc", "#26a69a"]

    chart = alt.Chart(df).mark_bar(width=28).encode(
        x=alt.X("date:N", axis=alt.Axis(title=None, labelColor="#94a3b8")),
        y=alt.Y("volume:Q", axis=alt.Axis(
            title=None,
            labelExpr="datum.value + 'M'",
            labelColor="#94a3b8",
            grid=True,
            gridColor="#1e293b"
        ), stack="zero"),
        color=alt.Color(
            "type:N",
            scale=alt.Scale(domain=types, range=palette),
            legend=alt.Legend(orient="top", title=None, labelColor="#cbd5e1", labelFontSize=10, columns=3)
        ),
        tooltip=["date:N", "type:N", alt.Tooltip("volume:Q", title="Volume (M)")]
    ).properties(height=180).configure_view(strokeWidth=0)

    return chart


def create_threat_trend_chart() -> alt.Chart:
    """
    Multi-line chart for Threat Detection Trend over time.
    """
    rows = []
    dates = ["10/10", "10/22", "10/29", "10/30", "10/31"]
    series = {
        "Security Events": [58, 42, 18, 16, 38],
        "Triaged Alerts": [18, 14, 8, 6, 12],
        "Escalated Alerts": [12, 10, 4, 3, 9]
    }

    for metric, vals in series.items():
        for d, v in zip(dates, vals):
            rows.append({"date": d, "metric": metric, "count": v})

    df = pd.DataFrame(rows)
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


def create_threat_map_deck(threat_points: List[Dict[str, Any]] = None) -> pdk.Deck:
    """
    Interactive Global Threat Map matching the Fortinet world map style.
    """
    if not threat_points:
        threat_points = [
            {"name": "Lazarus Group (Pyongyang)", "lat": 39.0392, "lon": 125.7625, "threat": "Critical C2 Beaconing", "score": 2400, "color": [244, 67, 54, 220]},
            {"name": "Moscow Malicious Host", "lat": 55.7558, "lon": 37.6173, "threat": "Payload Downloader", "score": 1950, "color": [244, 67, 54, 220]},
            {"name": "Tor Exit Node (Berlin)", "lat": 52.5200, "lon": 13.4050, "threat": "Port Scan / Botnet", "score": 1400, "color": [255, 152, 0, 200]},
            {"name": "Corporate HQ (New York)", "lat": 40.7128, "lon": -74.0060, "threat": "Data Exfil Probe", "score": 280, "color": [255, 193, 7, 200]},
            {"name": "Branch Office (San Francisco)", "lat": 37.7749, "lon": -122.4194, "threat": "Policy Anomaly", "score": 120, "color": [0, 230, 118, 180]},
            {"name": "Vancouver Endpoint", "lat": 49.2827, "lon": -123.1207, "threat": "VPN Spray", "score": 500, "color": [255, 152, 0, 200]}
        ]

    df = pd.DataFrame(threat_points)

    view_state = pdk.ViewState(
        latitude=35.0,
        longitude=10.0,
        zoom=1.1,
        min_zoom=1,
        max_zoom=10,
        pitch=0
    )

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

    deck = pdk.Deck(
        layers=[scatter],
        initial_view_state=view_state,
        map_style="https://basemaps.cartocdn.com/gl/dark-matter-gl-style/style.json",
        tooltip={"text": "🚨 {name}\nThreat: {threat}\nAnomaly Score: {score}"}
    )

    return deck

