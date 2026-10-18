"""Enterprise dark theme for the SOC console."""

CONSOLE_CSS = """
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
"""
