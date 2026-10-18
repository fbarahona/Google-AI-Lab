"""
Script to generate System Architecture Diagram as both SVG and PNG image files.
Based on docs/ARCHITECTURE.md & docs/SECURITY_ARCHITECTURE.md reference architecture for Google Cloud Platform (<PROJECT_ID>).
"""

import math
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

OUTPUT_DIR = Path(__file__).resolve().parent
SVG_PATH = OUTPUT_DIR / "system_architecture.svg"
PNG_PATH = OUTPUT_DIR / "system_architecture.png"


def get_font(font_type="sans", size=14, bold=False):
    """Safely load font with fallbacks."""
    font_candidates = []
    if font_type == "mono":
        if bold:
            font_candidates = [
                "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf",
                "/usr/share/fonts/truetype/liberation/LiberationMono-Bold.ttf",
            ]
        else:
            font_candidates = [
                "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
                "/usr/share/fonts/truetype/liberation/LiberationMono-Regular.ttf",
            ]
    else:
        if bold:
            font_candidates = [
                "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
                "/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf",
            ]
        else:
            font_candidates = [
                "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
                "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
            ]

    for cand in font_candidates:
        if Path(cand).exists():
            try:
                return ImageFont.truetype(cand, size)
            except Exception:
                continue
    return ImageFont.load_default()


def create_svg():
    svg_content = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1600 1560" width="1600" height="1560">
  <defs>
    <!-- Background Gradient -->
    <linearGradient id="bgGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#070a13"/>
      <stop offset="50%" stop-color="#0f172a"/>
      <stop offset="100%" stop-color="#090d16"/>
    </linearGradient>

    <!-- Card Gradients -->
    <linearGradient id="generatorGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#2e1065"/>
      <stop offset="100%" stop-color="#1e1b4b"/>
    </linearGradient>

    <linearGradient id="pubsubGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#0c4a6e"/>
      <stop offset="100%" stop-color="#082f49"/>
    </linearGradient>

    <linearGradient id="bqGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#1e3a8a"/>
      <stop offset="100%" stop-color="#0f172a"/>
    </linearGradient>

    <linearGradient id="detectGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#064e3b"/>
      <stop offset="100%" stop-color="#022c22"/>
    </linearGradient>

    <linearGradient id="alertTopicGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#042f2e"/>
      <stop offset="100%" stop-color="#0f172a"/>
    </linearGradient>

    <linearGradient id="dlqGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#4c0519"/>
      <stop offset="100%" stop-color="#1f131a"/>
    </linearGradient>

    <linearGradient id="adkGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#022c22"/>
      <stop offset="100%" stop-color="#064e3b"/>
    </linearGradient>

    <linearGradient id="agentSearchGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#0c4a6e"/>
      <stop offset="100%" stop-color="#082f49"/>
    </linearGradient>

    <linearGradient id="agentBqGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#312e81"/>
      <stop offset="100%" stop-color="#1e1b4b"/>
    </linearGradient>

    <linearGradient id="agentVisionGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#064e3b"/>
      <stop offset="100%" stop-color="#042f2e"/>
    </linearGradient>

    <linearGradient id="agentSocGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#7c2d12"/>
      <stop offset="100%" stop-color="#431407"/>
    </linearGradient>

    <linearGradient id="mcpGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#3b0764"/>
      <stop offset="100%" stop-color="#1e1035"/>
    </linearGradient>

    <linearGradient id="socConsoleGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#4c0519"/>
      <stop offset="100%" stop-color="#1f131a"/>
    </linearGradient>

    <!-- Filters -->
    <filter id="shadow" x="-10%" y="-10%" width="125%" height="125%">
      <feDropShadow dx="0" dy="6" stdDeviation="8" flood-color="#000000" flood-opacity="0.5"/>
    </filter>

    <filter id="cardGlowPurple" x="-10%" y="-10%" width="120%" height="120%">
      <feDropShadow dx="0" dy="0" stdDeviation="6" flood-color="#a855f7" flood-opacity="0.3"/>
    </filter>

    <filter id="cardGlowGreen" x="-10%" y="-10%" width="120%" height="120%">
      <feDropShadow dx="0" dy="0" stdDeviation="8" flood-color="#10b981" flood-opacity="0.35"/>
    </filter>

    <!-- Markers -->
    <marker id="arrowPurple" markerWidth="10" markerHeight="10" refX="7" refY="3.5" orient="auto">
      <polygon points="0 0, 8 3.5, 0 7" fill="#c084fc"/>
    </marker>
    <marker id="arrowBlue" markerWidth="10" markerHeight="10" refX="7" refY="3.5" orient="auto">
      <polygon points="0 0, 8 3.5, 0 7" fill="#38bdf8"/>
    </marker>
    <marker id="arrowYellow" markerWidth="10" markerHeight="10" refX="7" refY="3.5" orient="auto">
      <polygon points="0 0, 8 3.5, 0 7" fill="#f59e0b"/>
    </marker>
    <marker id="arrowGreen" markerWidth="10" markerHeight="10" refX="7" refY="3.5" orient="auto">
      <polygon points="0 0, 8 3.5, 0 7" fill="#10b981"/>
    </marker>
    <marker id="arrowRed" markerWidth="10" markerHeight="10" refX="7" refY="3.5" orient="auto">
      <polygon points="0 0, 8 3.5, 0 7" fill="#f43f5e"/>
    </marker>
  </defs>

  <style>
    .title { font-family: 'Inter', -apple-system, 'Segoe UI', Roboto, sans-serif; font-weight: 800; font-size: 26px; fill: #f8fafc; }
    .subtitle { font-family: 'Inter', -apple-system, 'Segoe UI', Roboto, sans-serif; font-weight: 500; font-size: 13.5px; fill: #94a3b8; }
    .card-title { font-family: 'Inter', -apple-system, 'Segoe UI', Roboto, sans-serif; font-weight: 700; font-size: 16px; fill: #ffffff; }
    .card-sub { font-family: 'Inter', -apple-system, 'Segoe UI', Roboto, sans-serif; font-weight: 500; font-size: 12px; fill: #cbd5e1; }
    .card-mono { font-family: 'DejaVu Sans Mono', Consolas, Monaco, monospace; font-size: 11px; fill: #93c5fd; }
    .badge { font-family: 'Inter', -apple-system, 'Segoe UI', Roboto, sans-serif; font-size: 11px; font-weight: 600; }
    .flow-label { font-family: 'Inter', -apple-system, 'Segoe UI', Roboto, sans-serif; font-weight: 600; font-size: 11.5px; }
    .agent-header { font-family: 'Inter', -apple-system, 'Segoe UI', Roboto, sans-serif; font-weight: 700; font-size: 14.5px; fill: #ffffff; }
    .agent-desc { font-family: 'Inter', -apple-system, 'Segoe UI', Roboto, sans-serif; font-size: 11px; fill: #cbd5e1; }
    .pill-text { font-family: 'DejaVu Sans Mono', Consolas, monospace; font-size: 10.5px; font-weight: 600; }
    .chip-text { font-family: 'Inter', -apple-system, 'Segoe UI', Roboto, sans-serif; font-size: 10px; font-weight: 700; }
  </style>

  <!-- Background -->
  <rect width="1600" height="1560" fill="url(#bgGrad)"/>

  <!-- Subtle Grid Pattern Lines -->
  <g opacity="0.04" stroke="#ffffff" stroke-width="1">
    <line x1="0" y1="120" x2="1600" y2="120"/>
    <line x1="0" y1="250" x2="1600" y2="250"/>
    <line x1="0" y1="395" x2="1600" y2="395"/>
    <line x1="0" y1="570" x2="1600" y2="570"/>
    <line x1="0" y1="705" x2="1600" y2="705"/>
    <line x1="0" y1="850" x2="1600" y2="850"/>
    <line x1="0" y1="1175" x2="1600" y2="1175"/>
    <line x1="0" y1="1405" x2="1600" y2="1405"/>
    <line x1="200" y1="0" x2="200" y2="1560"/>
    <line x1="800" y1="0" x2="800" y2="1560"/>
    <line x1="1400" y1="0" x2="1400" y2="1560"/>
  </g>

  <!-- ==================== HEADER ==================== -->
  <g transform="translate(100, 35)">
    <rect x="-10" y="-8" width="56" height="56" rx="14" fill="#1e293b" stroke="#334155" stroke-width="1.5"/>
    <text x="18" y="27" font-family="'Inter', sans-serif" font-weight="800" font-size="16" fill="#38bdf8" text-anchor="middle">SOC</text>
    <text x="65" y="20" class="title">Enterprise Real-Time Cybersecurity AI: Cloud Architecture &amp; ADK SOC</text>
    <text x="65" y="42" class="subtitle">Google Cloud Platform (<tspan fill="#38bdf8" font-weight="700">&lt;PROJECT_ID&gt;</tspan>) • BigQuery Security Lakehouse • ADK Multi-Agent Team • Model Context Protocol (MCP)</text>
  </g>

  <!-- ==================== TIER 1: SYNTHETIC LOG GENERATOR LAYER ==================== -->
  <g transform="translate(500, 115)" filter="url(#shadow)">
    <rect width="600" height="90" rx="16" fill="url(#generatorGrad)" stroke="#c084fc" stroke-width="2" filter="url(#cardGlowPurple)"/>
    <!-- Chip -->
    <rect x="25" y="16" width="48" height="18" rx="4" fill="#3b0764" stroke="#c084fc" stroke-width="1"/>
    <text x="49" y="29" class="chip-text" fill="#e9d5ff" text-anchor="middle">GEN</text>
    <text x="82" y="30" class="card-title">Synthetic Log Generator (CLI &amp; Threat Injection)</text>
    <text x="25" y="50" class="card-mono">src.demo.data_generator.log_generator • event_family: access | network</text>

    <!-- Pills for Generator modes -->
    <rect x="25" y="60" width="160" height="20" rx="5" fill="#4c0519" stroke="#f43f5e" stroke-width="1"/>
    <text x="35" y="74" class="badge" fill="#fecdd3">APT Malicious Scenario</text>

    <rect x="195" y="60" width="180" height="20" rx="5" fill="#422006" stroke="#f59e0b" stroke-width="1"/>
    <text x="205" y="74" class="badge" fill="#fef08a">Admin False-Positive Noise</text>

    <rect x="385" y="60" width="185" height="20" rx="5" fill="#3b0764" stroke="#c084fc" stroke-width="1"/>
    <text x="395" y="74" class="badge" fill="#e9d5ff">Continuous Benign Stream</text>
  </g>

  <!-- Connector from Generator down to Pub/Sub Raw Logs -->
  <path d="M 800 205 L 800 248" fill="none" stroke="#c084fc" stroke-width="2.5" marker-end="url(#arrowPurple)"/>
  <rect x="680" y="217" width="240" height="20" rx="5" fill="#1e1b4b" stroke="#c084fc" stroke-width="1"/>
  <text x="800" y="231" class="flow-label" fill="#e9d5ff" text-anchor="middle">Publishes JSON Security Telemetry</text>

  <!-- ==================== TIER 2: PUBSUB RAW LOGS EVENT BUS ==================== -->
  <g transform="translate(500, 250)" filter="url(#shadow)">
    <rect width="600" height="78" rx="14" fill="url(#pubsubGrad)" stroke="#38bdf8" stroke-width="2"/>
    <rect x="25" y="16" width="60" height="18" rx="4" fill="#082f49" stroke="#0ea5e9" stroke-width="1"/>
    <text x="55" y="29" class="chip-text" fill="#7dd3fc" text-anchor="middle">PUBSUB</text>
    <text x="94" y="30" class="card-title">Topic: cymbal_cyber_raw_logs</text>
    <text x="25" y="50" class="card-mono">Serverless Event Bus • Partitioned Telemetry Ingestion</text>
    <text x="25" y="66" class="card-sub" fill="#7dd3fc">Dual Direct BigQuery Subscriptions • Filtered by event_family attribute • $0 Compute</text>
  </g>

  <!-- Dual Connectors from Pub/Sub to BigQuery Tables -->
  <path d="M 620 328 L 620 360 L 450 360 L 450 393" fill="none" stroke="#38bdf8" stroke-width="2" marker-end="url(#arrowBlue)"/>
  <path d="M 980 328 L 980 360 L 1150 360 L 1150 393" fill="none" stroke="#38bdf8" stroke-width="2" marker-end="url(#arrowBlue)"/>

  <rect x="250" y="348" width="350" height="22" rx="5" fill="#0c4a6e" stroke="#38bdf8" stroke-width="1"/>
  <text x="425" y="363" class="flow-label" fill="#7dd3fc" text-anchor="middle">raw_access_to_bq [event_family="access"] ($0 Compute)</text>

  <rect x="990" y="348" width="350" height="22" rx="5" fill="#0c4a6e" stroke="#38bdf8" stroke-width="1"/>
  <text x="1165" y="363" class="flow-label" fill="#7dd3fc" text-anchor="middle">raw_network_to_bq [event_family="network"] ($0 Compute)</text>

  <!-- ==================== TIER 3: BIGQUERY LAKEHOUSE ==================== -->
  <g transform="translate(100, 395)" filter="url(#shadow)">
    <rect width="1400" height="125" rx="18" fill="url(#bqGrad)" stroke="#60a5fa" stroke-width="2"/>
    <rect x="30" y="18" width="44" height="18" rx="4" fill="#1e3a8a" stroke="#60a5fa" stroke-width="1"/>
    <text x="52" y="31" class="chip-text" fill="#93c5fd" text-anchor="middle">BQ</text>
    <text x="84" y="32" class="card-title">Enterprise Security Lakehouse (Dataset: <tspan fill="#93c5fd">Cymbal_Cyber</tspan>)</text>
    <text x="30" y="52" class="card-sub">Time-partitioned and clustered analytics tables • SSOT for Telemetry, Alerts &amp; SOC Tickets • $0 Continuous Slot Cost</text>

    <!-- Table badges -->
    <g transform="translate(25, 66)">
      <rect x="0" y="0" width="215" height="32" rx="8" fill="#1e293b" stroke="#3b82f6" stroke-width="1.2"/>
      <text x="12" y="20" class="pill-text" fill="#60a5fa">user_access_events [DAY]</text>

      <rect x="230" y="0" width="195" height="32" rx="8" fill="#1e293b" stroke="#3b82f6" stroke-width="1.2"/>
      <text x="12" y="20" class="pill-text" fill="#60a5fa">network_events [DAY]</text>

      <rect x="440" y="0" width="215" height="32" rx="8" fill="#1e293b" stroke="#38bdf8" stroke-width="1.2"/>
      <text x="12" y="20" class="pill-text" fill="#7dd3fc">alerts [DAY, Clustered]</text>

      <rect x="670" y="0" width="225" height="32" rx="8" fill="#3f0713" stroke="#f43f5e" stroke-width="1.2"/>
      <text x="12" y="20" class="pill-text" fill="#fda4af">alerts_dead_letter [DLQ]</text>

      <rect x="910" y="0" width="235" height="32" rx="8" fill="#1e293b" stroke="#34d399" stroke-width="1.2"/>
      <text x="12" y="20" class="pill-text" fill="#6ee7b7">adk_threat_assessment</text>

      <rect x="1160" y="0" width="190" height="32" rx="8" fill="#1e293b" stroke="#fb923c" stroke-width="1.2"/>
      <text x="12" y="20" class="pill-text" fill="#fdba74">soc_tickets [SSOT]</text>
    </g>
  </g>

  <!-- Connector from BigQuery down to Scheduled Detector -->
  <path d="M 800 520 L 800 568" fill="none" stroke="#f59e0b" stroke-width="2.5" marker-end="url(#arrowYellow)"/>
  <rect x="580" y="533" width="440" height="22" rx="5" fill="#1c1917" stroke="#f59e0b" stroke-width="1"/>
  <text x="800" y="548" class="flow-label" fill="#fde68a" text-anchor="middle">Cloud Scheduler (every 5m) • Closed 2m Tumbling Window MERGE</text>

  <!-- ==================== TIER 4: CLOUD RUN JOB: THREAT DETECTOR ==================== -->
  <g transform="translate(460, 570)" filter="url(#shadow)">
    <rect width="680" height="85" rx="14" fill="url(#detectGrad)" stroke="#10b981" stroke-width="2"/>
    <rect x="25" y="16" width="65" height="18" rx="4" fill="#064e3b" stroke="#10b981" stroke-width="1"/>
    <text x="57" y="29" class="chip-text" fill="#a7f3d0" text-anchor="middle">CR-JOB</text>
    <text x="100" y="28" class="card-title">threat-detector (Cloud Scheduler Triggered)</text>
    <text x="25" y="48" class="card-mono">adk_agent.threat_detector (TIMESTAMP_BUCKET 2m + MERGE)</text>
    <text x="25" y="68" class="card-sub" fill="#6ee7b7">Evaluates 2m tumbling windows • Scores &gt;= 100 • $0 continuous slot cost • Updates alerts table</text>
  </g>

  <!-- Connector from Threat Detector down to Alerts Topic -->
  <path d="M 720 655 L 720 680 L 600 680 L 600 703" fill="none" stroke="#10b981" stroke-width="2.5" marker-end="url(#arrowGreen)"/>
  <rect x="540" y="668" width="310" height="22" rx="5" fill="#064e3b" stroke="#10b981" stroke-width="1"/>
  <text x="695" y="683" class="flow-label" fill="#6ee7b7" text-anchor="middle">Publishes Alert Contract JSON (Score &gt;= 100)</text>

  <!-- ==================== TIER 5: ALERTS TOPIC & DEAD-LETTER QUEUE ==================== -->
  <!-- Primary Alert Topic -->
  <g transform="translate(280, 705)" filter="url(#shadow)">
    <rect width="640" height="85" rx="14" fill="url(#alertTopicGrad)" stroke="#34d399" stroke-width="2"/>
    <rect x="20" y="16" width="60" height="18" rx="4" fill="#042f2e" stroke="#34d399" stroke-width="1"/>
    <text x="50" y="29" class="chip-text" fill="#a7f3d0" text-anchor="middle">ALERTS</text>
    <text x="88" y="28" class="card-title">Topic: cymbal_cyber_alerts</text>
    <text x="20" y="48" class="card-sub" fill="#cbd5e1">Primary real-time alert dispatch bus • Delivers Alert Contract JSON to Orchestrator</text>
    <g transform="translate(20, 56)">
      <rect x="0" y="0" width="150" height="20" rx="5" fill="#064e3b" stroke="#10b981" stroke-width="1"/>
      <text x="10" y="14" class="badge" fill="#a7f3d0">Push Subscription</text>

      <rect x="160" y="0" width="185" height="20" rx="5" fill="#082f49" stroke="#0ea5e9" stroke-width="1"/>
      <text x="170" y="14" class="badge" fill="#bae6fd">roles/run.invoker (OIDC)</text>

      <rect x="355" y="0" width="235" height="20" rx="5" fill="#1e293b" stroke="#64748b" stroke-width="1"/>
      <text x="365" y="14" class="badge" fill="#f1f5f9">Native Cloud Run Auth Token</text>
    </g>
  </g>

  <!-- Dead-Letter Topic (DLQ) -->
  <g transform="translate(990, 705)" filter="url(#shadow)">
    <rect width="510" height="85" rx="14" fill="url(#dlqGrad)" stroke="#f43f5e" stroke-width="2"/>
    <rect x="20" y="16" width="46" height="18" rx="4" fill="#4c0519" stroke="#f43f5e" stroke-width="1"/>
    <text x="43" y="29" class="chip-text" fill="#fecdd3" text-anchor="middle">DLQ</text>
    <text x="74" y="28" class="card-title">Topic: cymbal_cyber_alerts_dlq</text>
    <text x="20" y="48" class="card-sub" fill="#fda4af">Dead-letter queue for failed push deliveries • Subscription -> DLQ Table</text>
    <g transform="translate(20, 56)">
      <rect x="0" y="0" width="180" height="20" rx="5" fill="#4c0519" stroke="#f43f5e" stroke-width="1"/>
      <text x="10" y="14" class="badge" fill="#fecdd3">Delivery Failed 5 Times</text>

      <rect x="190" y="0" width="260" height="20" rx="5" fill="#451a03" stroke="#ea580c" stroke-width="1"/>
      <text x="200" y="14" class="badge" fill="#fed7aa">Next Run: Auto-Escalate to SOC</text>
    </g>
  </g>

  <!-- Connectors in Tier 5 -->
  <!-- Main Alert to DLQ -->
  <path d="M 920 747 L 988 747" fill="none" stroke="#f43f5e" stroke-width="2" stroke-dasharray="4 3" marker-end="url(#arrowRed)"/>
  <rect x="926" y="725" width="56" height="18" rx="4" fill="#3f0713" stroke="#f43f5e" stroke-width="1"/>
  <text x="954" y="738" class="chip-text" fill="#fecdd3" text-anchor="middle">Failed 5x</text>

  <!-- Main Alert to Orchestrator -->
  <path d="M 600 790 L 600 848" fill="none" stroke="#10b981" stroke-width="2.5" marker-end="url(#arrowGreen)"/>
  <rect x="450" y="810" width="300" height="22" rx="5" fill="#064e3b" stroke="#10b981" stroke-width="1"/>
  <text x="600" y="825" class="flow-label" fill="#6ee7b7" text-anchor="middle">Push Webhook (Verified OIDC Bearer Token)</text>

  <!-- ==================== TIER 6: ADK MULTI-AGENT ORCHESTRATOR ==================== -->
  <g transform="translate(100, 850)" filter="url(#shadow)">
    <rect width="1400" height="270" rx="18" fill="url(#adkGrad)" stroke="#10b981" stroke-width="2.2" filter="url(#cardGlowGreen)"/>
    <rect x="30" y="18" width="50" height="18" rx="4" fill="#064e3b" stroke="#10b981" stroke-width="1"/>
    <text x="55" y="31" class="chip-text" fill="#a7f3d0" text-anchor="middle">ADK</text>
    <text x="90" y="30" class="card-title">ADK Multi-Agent Orchestrator (Cloud Run Webhook: FastAPI)</text>
    <text x="30" y="48" class="card-sub" fill="#a7f3d0">Autonomous Multi-Agent Investigation • Gemini 3.8 Flash • Checks alerts.status (!=DONE) • Transitions INVESTIGATING -> DONE</text>

    <!-- 4 Sub-Agent Cards -->
    <!-- Agent 1: google_search_agent -->
    <g transform="translate(20, 60)">
      <rect width="325" height="190" rx="12" fill="url(#agentSearchGrad)" stroke="#38bdf8" stroke-width="1.5"/>
      <rect x="16" y="14" width="52" height="16" rx="4" fill="#082f49" stroke="#38bdf8" stroke-width="1"/>
      <text x="42" y="26" class="chip-text" fill="#7dd3fc" text-anchor="middle">OSINT</text>
      <text x="76" y="26" class="agent-header">google_search_agent</text>
      <rect x="16" y="36" width="180" height="18" rx="4" fill="#082f49" stroke="#0ea5e9" stroke-width="1"/>
      <text x="24" y="49" class="badge" fill="#7dd3fc">OSINT Public Threat Intel</text>
      <line x1="16" y1="62" x2="309" y2="62" stroke="#0284c7" stroke-width="1"/>
      <text x="16" y="80" class="agent-desc"><tspan font-weight="700" fill="#ffffff">Role:</tspan> Investigates external IPs &amp; C2 domains</text>
      <text x="16" y="98" class="agent-desc"><tspan font-weight="700" fill="#ffffff">Intel:</tspan> Tor exit nodes, foreign ASN, malware</text>
      <text x="16" y="116" class="agent-desc"><tspan font-weight="700" fill="#ffffff">Type:</tspan> Native ADK Toolset (no database access)</text>
      <rect x="16" y="132" width="293" height="42" rx="6" fill="#082f49" stroke="#0ea5e9" stroke-width="1"/>
      <text x="26" y="152" class="pill-text" fill="#7dd3fc">Native Tool: google_search</text>
      <text x="26" y="166" class="card-sub" fill="#bae6fd">Zero Cloud Run dependency</text>
    </g>

    <!-- Agent 2: bq_investigation_agent -->
    <g transform="translate(365, 60)">
      <rect width="325" height="190" rx="12" fill="url(#agentBqGrad)" stroke="#818cf8" stroke-width="1.5"/>
      <rect x="16" y="14" width="36" height="16" rx="4" fill="#1e1b4b" stroke="#818cf8" stroke-width="1"/>
      <text x="34" y="26" class="chip-text" fill="#c7d2fe" text-anchor="middle">BQ</text>
      <text x="60" y="26" class="agent-header">bq_investigation_agent</text>
      <rect x="16" y="36" width="190" height="18" rx="4" fill="#1e1b4b" stroke="#6366f1" stroke-width="1"/>
      <text x="24" y="49" class="badge" fill="#c7d2fe">BigQuery Behavioral Baseline</text>
      <line x1="16" y1="62" x2="309" y2="62" stroke="#4338ca" stroke-width="1"/>
      <text x="16" y="80" class="agent-desc"><tspan font-weight="700" fill="#ffffff">Role:</tspan> Queries 24h entity telemetry profile</text>
      <text x="16" y="98" class="agent-desc"><tspan font-weight="700" fill="#ffffff">Audit:</tspan> Failed logins, privilege escalation, lateral move</text>
      <text x="16" y="116" class="agent-desc"><tspan font-weight="700" fill="#ffffff">Scope:</tspan> Parameterized queries (1GB ceiling)</text>
      <rect x="16" y="132" width="293" height="42" rx="6" fill="#1e1b4b" stroke="#6366f1" stroke-width="1"/>
      <text x="26" y="152" class="pill-text" fill="#a5b4fc">MCP: get_entity_behavioral_profile</text>
      <text x="26" y="166" class="card-sub" fill="#c7d2fe">Scoped via tool_filter</text>
    </g>

    <!-- Agent 3: visual_analysis_agent -->
    <g transform="translate(710, 60)">
      <rect width="325" height="190" rx="12" fill="url(#agentVisionGrad)" stroke="#34d399" stroke-width="1.5"/>
      <rect x="16" y="14" width="58" height="16" rx="4" fill="#042f2e" stroke="#34d399" stroke-width="1"/>
      <text x="45" y="26" class="chip-text" fill="#a7f3d0" text-anchor="middle">VISION</text>
      <text x="82" y="26" class="agent-header">visual_analysis_agent</text>
      <rect x="16" y="36" width="195" height="18" rx="4" fill="#042f2e" stroke="#10b981" stroke-width="1"/>
      <text x="24" y="49" class="badge" fill="#a7f3d0">Gemini Multimodal Vision OCR</text>
      <line x1="16" y1="62" x2="309" y2="62" stroke="#047857" stroke-width="1"/>
      <text x="16" y="80" class="agent-desc"><tspan font-weight="700" fill="#ffffff">Role:</tspan> Desktop screenshot forensic inspection</text>
      <text x="16" y="98" class="agent-desc"><tspan font-weight="700" fill="#ffffff">Detect:</tspan> Mimikatz, PowerShell, payload downloads</text>
      <text x="16" y="116" class="agent-desc"><tspan font-weight="700" fill="#ffffff">URLs:</tspan> Short-lived V4 signed URLs for analysts</text>
      <rect x="16" y="132" width="293" height="42" rx="6" fill="#042f2e" stroke="#10b981" stroke-width="1"/>
      <text x="26" y="152" class="pill-text" fill="#6ee7b7">MCP: Vision OCR &amp; Signed URLs</text>
      <text x="26" y="166" class="card-sub" fill="#a7f3d0">get_visual_analysis_for_user</text>
    </g>

    <!-- Agent 4: soc_ticketing_agent -->
    <g transform="translate(1055, 60)">
      <rect width="325" height="190" rx="12" fill="url(#agentSocGrad)" stroke="#fb923c" stroke-width="1.5"/>
      <rect x="16" y="14" width="40" height="16" rx="4" fill="#451a03" stroke="#fb923c" stroke-width="1"/>
      <text x="36" y="26" class="chip-text" fill="#fed7aa" text-anchor="middle">SOC</text>
      <text x="64" y="26" class="agent-header">soc_ticketing_agent</text>
      <rect x="16" y="36" width="180" height="18" rx="4" fill="#451a03" stroke="#ea580c" stroke-width="1"/>
      <text x="24" y="49" class="badge" fill="#fed7aa">Triage, Escalation &amp; Dispatch</text>
      <line x1="16" y1="62" x2="309" y2="62" stroke="#c2410c" stroke-width="1"/>
      <text x="16" y="80" class="agent-desc"><tspan font-weight="700" fill="#ffffff">Role:</tspan> Synthesizes evidence &amp; determines action</text>
      <text x="16" y="98" class="agent-desc"><tspan font-weight="700" fill="#ffffff">Action:</tspan> High-conf incident dispatch or FP closure</text>
      <text x="16" y="116" class="agent-desc"><tspan font-weight="700" fill="#ffffff">Safety:</tspan> Security gate verifies deterministic ID</text>
      <rect x="16" y="132" width="293" height="42" rx="6" fill="#451a03" stroke="#ea580c" stroke-width="1"/>
      <text x="26" y="152" class="pill-text" fill="#fdba74">MCP: dispatch_to_soc, log_fp</text>
      <text x="26" y="166" class="card-sub" fill="#fed7aa">Auditable ticket resolution</text>
    </g>
  </g>

  <!-- Connector from Orchestrator down to MCP Tool Service -->
  <path d="M 800 1120 L 800 1173" fill="none" stroke="#c084fc" stroke-width="2.5" marker-end="url(#arrowPurple)"/>
  <rect x="570" y="1136" width="460" height="22" rx="5" fill="#2e1065" stroke="#c084fc" stroke-width="1"/>
  <text x="800" y="1151" class="flow-label" fill="#e9d5ff" text-anchor="middle">MCP over HTTPS + ID token (agent SA: run.invoker only)</text>

  <!-- ==================== TIER 7: DECOUPLED MCP TOOL SERVICE ==================== -->
  <g transform="translate(100, 1175)" filter="url(#shadow)">
    <rect width="1400" height="180" rx="18" fill="url(#mcpGrad)" stroke="#c084fc" stroke-width="2"/>
    <rect x="30" y="18" width="50" height="18" rx="4" fill="#3b0764" stroke="#c084fc" stroke-width="1"/>
    <text x="55" y="31" class="chip-text" fill="#e9d5ff" text-anchor="middle">MCP</text>
    <text x="90" y="30" class="card-title">MCP Tool Service (Cloud Run: cymbal-cyber-mcp) — Principle of Least Privilege Boundary</text>
    <text x="30" y="48" class="card-sub" fill="#e9d5ff">Dedicated Tools SA: <tspan fill="#38bdf8" font-weight="700">cymbal-mcp-tools-sa</tspan> • Transports: HTTPS (Cloud Run) / stdio (Local) • Fixed Parameterized Operations (No free-form SQL)</text>

    <!-- 4 Tool Categories Pillars -->
    <!-- Pillar 1: BigQuery -->
    <g transform="translate(20, 60)">
      <rect width="325" height="105" rx="10" fill="#1e1b4b" stroke="#818cf8" stroke-width="1.2"/>
      <text x="16" y="24" class="card-title" font-size="13">BigQuery Telemetry</text>
      <text x="16" y="44" class="pill-text" fill="#a5b4fc">• get_entity_behavioral_profile</text>
      <text x="16" y="62" class="card-sub" fill="#cbd5e1">24h baseline query (user / IP)</text>
      <text x="16" y="80" class="card-sub" fill="#cbd5e1">1 GB maximum_bytes_billed ceiling</text>
      <text x="16" y="96" class="badge" fill="#818cf8">Read-Only Evidence Access</text>
    </g>

    <!-- Pillar 2: Vision -->
    <g transform="translate(365, 60)">
      <rect width="325" height="105" rx="10" fill="#042f2e" stroke="#34d399" stroke-width="1.2"/>
      <text x="16" y="24" class="card-title" font-size="13">Multimodal Vision OCR</text>
      <text x="16" y="44" class="pill-text" fill="#6ee7b7">• get_visual_analysis_for_user</text>
      <text x="16" y="60" class="pill-text" fill="#6ee7b7">• get_gcs_uri_for_user</text>
      <text x="16" y="76" class="pill-text" fill="#6ee7b7">• generate_signed_url (V4 signed)</text>
      <text x="16" y="96" class="badge" fill="#34d399">Gemini Vision on GCS Evidence</text>
    </g>

    <!-- Pillar 3: SOC Ticketing -->
    <g transform="translate(710, 60)">
      <rect width="325" height="105" rx="10" fill="#451a03" stroke="#ea580c" stroke-width="1.2"/>
      <text x="16" y="24" class="card-title" font-size="13">SOC Ticketing Operations</text>
      <text x="16" y="44" class="pill-text" fill="#fdba74">• dispatch_to_soc_ticketing_system</text>
      <text x="16" y="60" class="pill-text" fill="#fdba74">• log_false_positive (Archive FP)</text>
      <text x="16" y="76" class="pill-text" fill="#fdba74">• create_rich_ticket_id (Gate verified)</text>
      <text x="16" y="96" class="badge" fill="#fb923c">Auditable Ticket Writes</text>
    </g>

    <!-- Pillar 4: Security Guardrails -->
    <g transform="translate(1055, 60)">
      <rect width="325" height="105" rx="10" fill="#3f0713" stroke="#f43f5e" stroke-width="1.2"/>
      <text x="16" y="24" class="card-title" font-size="13">Platform Guardrails</text>
      <text x="16" y="44" class="pill-text" fill="#fda4af">• auto_escalate_unresolved_alert</text>
      <text x="16" y="62" class="card-sub" fill="#fecdd3">Fixed server-side (DEFAULT_DENY)</text>
      <text x="16" y="78" class="pill-text" fill="#fda4af">• escalate_to_human (GCS payload)</text>
      <text x="16" y="96" class="badge" fill="#f43f5e">Default-Deny Escalation</text>
    </g>
  </g>

  <!-- Connector from MCP Tool Service down to SOC Ticketing System -->
  <path d="M 800 1355 L 800 1403" fill="none" stroke="#f43f5e" stroke-width="2.5" marker-end="url(#arrowRed)"/>
  <rect x="580" y="1368" width="440" height="22" rx="5" fill="#3f0713" stroke="#f43f5e" stroke-width="1"/>
  <text x="800" y="1383" class="flow-label" fill="#fda4af" text-anchor="middle">Dispatches Incidents &amp; Writes soc_tickets Table</text>

  <!-- ==================== TIER 8: SOC TICKETING & ANALYST CONSOLE ==================== -->
  <g transform="translate(100, 1405)" filter="url(#shadow)">
    <rect width="1400" height="125" rx="18" fill="url(#socConsoleGrad)" stroke="#f43f5e" stroke-width="2"/>
    <rect x="30" y="18" width="50" height="18" rx="4" fill="#4c0519" stroke="#f43f5e" stroke-width="1"/>
    <text x="55" y="31" class="chip-text" fill="#fecdd3" text-anchor="middle">SOC</text>
    <text x="90" y="32" class="card-title">SOC Ticketing System &amp; Streamlit Analyst Console</text>
    <text x="30" y="52" class="card-mono">src.demo.soc_ticketing • streamlit_soc_console.py (Local port 8501)</text>

    <!-- 3 Pillars inside Console -->
    <g transform="translate(25, 66)">
      <rect x="0" y="0" width="430" height="42" rx="8" fill="#3f0713" stroke="#be123c" stroke-width="1.2"/>
      <text x="16" y="26" class="pill-text" fill="#fecdd3">Incident Queue: soc_tickets + GCS Escalations</text>

      <rect x="455" y="0" width="430" height="42" rx="8" fill="#3f0713" stroke="#be123c" stroke-width="1.2"/>
      <text x="16" y="26" class="pill-text" fill="#fecdd3">Webhook Integrations: Slack / Jira / ServiceNow</text>

      <rect x="910" y="0" width="455" height="42" rx="8" fill="#3f0713" stroke="#be123c" stroke-width="1.2"/>
      <text x="16" y="26" class="pill-text" fill="#fecdd3">Streamlit Console: Interactive Triage &amp; Evidence</text>
    </g>
  </g>
</svg>
"""
    with open(SVG_PATH, "w", encoding="utf-8") as f:
        f.write(svg_content)
    print(f"Generated SVG: {SVG_PATH}")


def draw_arrow(draw, points, color, width=2, arrow_size=7):
    """Draw a polyline path with an arrow head pointing in direction of last segment."""
    for i in range(len(points) - 1):
        draw.line([points[i], points[i + 1]], fill=color, width=width)

    x1, y1 = points[-2]
    x2, y2 = points[-1]
    angle = math.atan2(y2 - y1, x2 - x1)

    tip = (x2, y2)
    left = (
        x2 - arrow_size * 1.6 * math.cos(angle) + arrow_size * math.sin(angle),
        y2 - arrow_size * 1.6 * math.sin(angle) - arrow_size * math.cos(angle),
    )
    right = (
        x2 - arrow_size * 1.6 * math.cos(angle) - arrow_size * math.sin(angle),
        y2 - arrow_size * 1.6 * math.sin(angle) + arrow_size * math.cos(angle),
    )
    draw.polygon([tip, left, right], fill=color)


def draw_centered_text(draw, xy, text, font, fill):
    """Draw text centered at xy."""
    bbox = draw.textbbox((0, 0), text, font=font)
    w = bbox[2] - bbox[0]
    h = bbox[3] - bbox[1]
    x, y = xy
    draw.text((x - w / 2, y - h / 2), text, font=font, fill=fill)


def draw_badge(draw, box, text, font, bg_color, border_color, text_color, radius=5):
    """Draw rounded badge with centered text."""
    draw.rounded_rectangle(
        box, radius=radius, fill=bg_color, outline=border_color, width=1
    )
    bx1, by1, bx2, by2 = box
    draw_centered_text(
        draw, ((bx1 + bx2) / 2, (by1 + by2) / 2 - 1), text, font, text_color
    )


def create_png():
    width, height = 1600, 1560
    img = Image.new("RGBA", (width, height), (9, 13, 22, 255))
    draw = ImageDraw.Draw(img)

    # Fonts
    title_font = get_font("sans", 22, bold=True)
    sub_font = get_font("sans", 12.5, bold=False)
    card_title_font = get_font("sans", 15.5, bold=True)
    card_sub_font = get_font("sans", 11.5, bold=False)
    card_mono_font = get_font("mono", 10.5, bold=False)
    badge_font = get_font("sans", 10.5, bold=True)
    label_font = get_font("sans", 10.5, bold=True)
    pill_mono_font = get_font("mono", 10, bold=True)
    chip_font = get_font("sans", 9.5, bold=True)

    # Subtle grid background lines
    for y in [115, 250, 395, 570, 705, 850, 1175, 1405]:
        draw.line([(0, y), (width, y)], fill=(30, 41, 59, 70), width=1)
    for x in [200, 800, 1400]:
        draw.line([(x, 0), (x, height)], fill=(30, 41, 59, 70), width=1)

    # ==================== HEADER ====================
    draw.rounded_rectangle(
        [(90, 28), (145, 80)],
        radius=12,
        fill=(30, 41, 59),
        outline=(56, 189, 248),
        width=2,
    )
    draw_centered_text(
        draw, (117, 54), "SOC", get_font("sans", 16, bold=True), (56, 189, 248)
    )

    draw.text(
        (160, 32),
        "Enterprise Real-Time Cybersecurity AI: Cloud Architecture & ADK SOC",
        fill=(248, 250, 252),
        font=title_font,
    )
    draw.text(
        (160, 62),
        "Google Cloud Platform (<PROJECT_ID>) • BigQuery Security Lakehouse • ADK Multi-Agent Team • Model Context Protocol (MCP)",
        fill=(148, 163, 184),
        font=sub_font,
    )

    # ==================== TIER 1: SYNTHETIC LOG GENERATOR LAYER ====================
    draw.rounded_rectangle(
        [(500, 115), (1100, 205)],
        radius=16,
        fill=(30, 27, 75),
        outline=(192, 132, 252),
        width=2,
    )
    draw_badge(
        draw,
        (525, 126, 575, 144),
        "GEN",
        chip_font,
        (59, 7, 100),
        (192, 132, 252),
        (233, 213, 255),
        radius=4,
    )
    draw.text(
        (585, 126),
        "Synthetic Log Generator (CLI & Threat Injection)",
        fill=(255, 255, 255),
        font=card_title_font,
    )
    draw.text(
        (525, 148),
        "src.demo.data_generator.log_generator • event_family: access | network",
        fill=(216, 180, 254),
        font=card_mono_font,
    )

    draw_badge(
        draw,
        (525, 172, 690, 194),
        "APT Malicious Scenario",
        badge_font,
        (76, 5, 25),
        (244, 63, 94),
        (254, 205, 211),
    )
    draw_badge(
        draw,
        (700, 172, 885, 194),
        "Admin False-Positive Noise",
        badge_font,
        (66, 32, 6),
        (245, 158, 11),
        (254, 240, 138),
    )
    draw_badge(
        draw,
        (895, 172, 1075, 194),
        "Continuous Benign Stream",
        badge_font,
        (59, 7, 100),
        (192, 132, 252),
        (233, 213, 255),
    )

    # Connector to Pub/Sub Raw Logs
    draw_arrow(
        draw,
        [(800, 205), (800, 250)],
        color=(192, 132, 252),
        width=2,
        arrow_size=7,
    )
    draw_badge(
        draw,
        (675, 217, 925, 239),
        "Publishes JSON Security Telemetry",
        label_font,
        (30, 27, 75),
        (192, 132, 252),
        (233, 213, 255),
        radius=5,
    )

    # ==================== TIER 2: PUBSUB RAW LOGS EVENT BUS ====================
    draw.rounded_rectangle(
        [(500, 250), (1100, 328)],
        radius=14,
        fill=(12, 74, 110),
        outline=(56, 189, 248),
        width=2,
    )
    draw_badge(
        draw,
        (525, 260, 590, 278),
        "PUBSUB",
        chip_font,
        (8, 47, 73),
        (56, 189, 248),
        (125, 211, 252),
        radius=4,
    )
    draw.text(
        (600, 260),
        "Topic: cymbal_cyber_raw_logs",
        fill=(255, 255, 255),
        font=card_title_font,
    )
    draw.text(
        (525, 282),
        "Serverless Event Bus • Partitioned Telemetry Ingestion",
        fill=(186, 230, 253),
        font=card_mono_font,
    )
    draw.text(
        (525, 302),
        "Dual Direct BigQuery Subscriptions • Filtered by event_family attribute • $0 Compute",
        fill=(147, 197, 253),
        font=card_sub_font,
    )

    # Dual Connectors to BigQuery
    draw_arrow(
        draw,
        [(620, 328), (620, 360), (450, 360), (450, 395)],
        color=(56, 189, 248),
        width=2,
        arrow_size=7,
    )
    draw_arrow(
        draw,
        [(980, 328), (980, 360), (1150, 360), (1150, 395)],
        color=(56, 189, 248),
        width=2,
        arrow_size=7,
    )

    draw_badge(
        draw,
        (250, 348, 600, 372),
        'raw_access_to_bq [event_family="access"] ($0 Ingest)',
        label_font,
        (12, 74, 110),
        (56, 189, 248),
        (125, 211, 252),
        radius=5,
    )
    draw_badge(
        draw,
        (990, 348, 1340, 372),
        'raw_network_to_bq [event_family="network"] ($0 Ingest)',
        label_font,
        (12, 74, 110),
        (56, 189, 248),
        (125, 211, 252),
        radius=5,
    )

    # ==================== TIER 3: BIGQUERY LAKEHOUSE ====================
    draw.rounded_rectangle(
        [(100, 395), (1500, 520)],
        radius=18,
        fill=(15, 23, 42),
        outline=(96, 165, 250),
        width=2,
    )
    draw_badge(
        draw,
        (130, 408, 175, 426),
        "BQ",
        chip_font,
        (30, 58, 138),
        (96, 165, 250),
        (147, 197, 253),
        radius=4,
    )
    draw.text(
        (185, 408),
        "Enterprise Security Lakehouse (Dataset: Cymbal_Cyber)",
        fill=(255, 255, 255),
        font=card_title_font,
    )
    draw.text(
        (130, 430),
        "Time-partitioned and clustered analytics tables • SSOT for Telemetry, Alerts & SOC Tickets • $0 Continuous Slot Cost",
        fill=(148, 163, 184),
        font=card_sub_font,
    )

    bq_tables = [
        (
            "user_access_events [DAY]",
            125,
            215,
            (30, 41, 59),
            (59, 130, 246),
            (96, 165, 250),
        ),
        (
            "network_events [DAY]",
            355,
            195,
            (30, 41, 59),
            (59, 130, 246),
            (96, 165, 250),
        ),
        (
            "alerts [DAY, Clustered]",
            565,
            215,
            (30, 41, 59),
            (56, 189, 248),
            (125, 211, 252),
        ),
        (
            "alerts_dead_letter [DLQ]",
            795,
            225,
            (63, 7, 19),
            (244, 63, 94),
            (254, 205, 211),
        ),
        (
            "adk_threat_assessment",
            1035,
            225,
            (30, 41, 59),
            (16, 185, 129),
            (110, 231, 183),
        ),
        (
            "soc_tickets [SSOT]",
            1275,
            200,
            (30, 41, 59),
            (251, 146, 60),
            (253, 186, 116),
        ),
    ]
    for tbl, tx, tw, bg_c, stroke_c, text_c in bq_tables:
        draw_badge(
            draw,
            (tx, 460, tx + tw, 495),
            tbl,
            pill_mono_font,
            bg_c,
            stroke_c,
            text_c,
            radius=8,
        )

    # Connector to Threat Detector
    draw_arrow(
        draw,
        [(800, 520), (800, 570)],
        color=(245, 158, 11),
        width=2,
        arrow_size=7,
    )
    draw_badge(
        draw,
        (560, 533, 1040, 557),
        "Cloud Scheduler (every 5m) • Closed 2m Tumbling Window MERGE",
        label_font,
        (28, 25, 23),
        (245, 158, 11),
        (253, 230, 138),
        radius=5,
    )

    # ==================== TIER 4: CLOUD RUN JOB: THREAT DETECTOR ====================
    draw.rounded_rectangle(
        [(460, 570), (1140, 655)],
        radius=14,
        fill=(6, 78, 59),
        outline=(16, 185, 129),
        width=2,
    )
    draw_badge(
        draw,
        (485, 582, 550, 600),
        "CR-JOB",
        chip_font,
        (2, 44, 34),
        (16, 185, 129),
        (167, 243, 208),
        radius=4,
    )
    draw.text(
        (560, 582),
        "threat-detector (Cloud Scheduler Triggered)",
        fill=(255, 255, 255),
        font=card_title_font,
    )
    draw.text(
        (485, 604),
        "adk_agent.threat_detector (TIMESTAMP_BUCKET 2m + MERGE)",
        fill=(110, 231, 183),
        font=card_mono_font,
    )
    draw.text(
        (485, 624),
        "Evaluates 2m tumbling windows • Scores >= 100 • $0 continuous slot cost • Updates alerts table",
        fill=(167, 243, 208),
        font=card_sub_font,
    )

    # Connector from Threat Detector down to Alerts Topic
    draw_arrow(
        draw,
        [(720, 655), (720, 680), (600, 680), (600, 705)],
        color=(16, 185, 129),
        width=2,
        arrow_size=7,
    )
    draw_badge(
        draw,
        (530, 668, 850, 692),
        "Publishes Alert Contract JSON (Score >= 100)",
        label_font,
        (6, 78, 59),
        (16, 185, 129),
        (167, 243, 208),
        radius=5,
    )

    # ==================== TIER 5: ALERTS TOPIC & DEAD-LETTER QUEUE ====================
    # Primary Alert Topic
    draw.rounded_rectangle(
        [(280, 705), (920, 790)],
        radius=14,
        fill=(4, 47, 46),
        outline=(52, 211, 153),
        width=2,
    )
    draw_badge(
        draw,
        (300, 716, 365, 734),
        "ALERTS",
        chip_font,
        (2, 44, 34),
        (52, 211, 153),
        (167, 243, 208),
        radius=4,
    )
    draw.text(
        (375, 716),
        "Topic: cymbal_cyber_alerts",
        fill=(255, 255, 255),
        font=card_title_font,
    )
    draw.text(
        (300, 737),
        "Primary real-time alert dispatch bus • Delivers Alert Contract JSON to Orchestrator",
        fill=(203, 213, 225),
        font=card_sub_font,
    )
    draw_badge(
        draw,
        (300, 758, 445, 780),
        "Push Subscription",
        badge_font,
        (6, 78, 59),
        (16, 185, 129),
        (167, 243, 208),
    )
    draw_badge(
        draw,
        (455, 758, 645, 780),
        "roles/run.invoker (OIDC)",
        badge_font,
        (8, 47, 73),
        (14, 165, 233),
        (186, 230, 253),
    )
    draw_badge(
        draw,
        (655, 758, 895, 780),
        "Native Cloud Run Auth Token",
        badge_font,
        (30, 41, 59),
        (100, 116, 139),
        (241, 245, 249),
    )

    # Dead-Letter Topic (DLQ)
    draw.rounded_rectangle(
        [(990, 705), (1500, 790)],
        radius=14,
        fill=(63, 7, 19),
        outline=(244, 63, 94),
        width=2,
    )
    draw_badge(
        draw,
        (1010, 716, 1055, 734),
        "DLQ",
        chip_font,
        (76, 5, 25),
        (244, 63, 94),
        (254, 205, 211),
        radius=4,
    )
    draw.text(
        (1065, 716),
        "Topic: cymbal_cyber_alerts_dlq",
        fill=(255, 255, 255),
        font=card_title_font,
    )
    draw.text(
        (1010, 737),
        "Dead-letter queue for failed push deliveries • Subscription -> DLQ Table",
        fill=(254, 205, 211),
        font=card_sub_font,
    )
    draw_badge(
        draw,
        (1010, 758, 1195, 780),
        "Delivery Failed 5 Times",
        badge_font,
        (76, 5, 25),
        (244, 63, 94),
        (254, 205, 211),
    )
    draw_badge(
        draw,
        (1205, 758, 1475, 780),
        "Next Run: Auto-Escalate to SOC",
        badge_font,
        (69, 26, 3),
        (234, 88, 12),
        (254, 215, 170),
    )

    # Connector: Main Alert to DLQ
    draw_arrow(
        draw,
        [(920, 747), (990, 747)],
        color=(244, 63, 94),
        width=2,
        arrow_size=6,
    )
    draw_badge(
        draw,
        (926, 725, 984, 743),
        "Failed 5x",
        chip_font,
        (63, 7, 19),
        (244, 63, 94),
        (254, 205, 211),
        radius=4,
    )

    # Connector: Main Alert to Orchestrator
    draw_arrow(
        draw,
        [(600, 790), (600, 850)],
        color=(16, 185, 129),
        width=2,
        arrow_size=7,
    )
    draw_badge(
        draw,
        (450, 810, 750, 834),
        "Push Webhook (Verified OIDC Bearer Token)",
        label_font,
        (6, 78, 59),
        (16, 185, 129),
        (167, 243, 208),
        radius=5,
    )

    # ==================== TIER 6: ADK MULTI-AGENT ORCHESTRATOR ====================
    draw.rounded_rectangle(
        [(100, 850), (1500, 1120)],
        radius=18,
        fill=(2, 44, 34),
        outline=(16, 185, 129),
        width=2,
    )
    draw_badge(
        draw,
        (130, 862, 180, 880),
        "ADK",
        chip_font,
        (6, 78, 59),
        (16, 185, 129),
        (167, 243, 208),
        radius=4,
    )
    draw.text(
        (190, 862),
        "ADK Multi-Agent Orchestrator (Cloud Run Webhook: FastAPI)",
        fill=(255, 255, 255),
        font=card_title_font,
    )
    draw.text(
        (130, 884),
        "Autonomous Multi-Agent Investigation • Gemini 3.8 Flash • Checks alerts.status (!=DONE) • Transitions INVESTIGATING -> DONE",
        fill=(167, 243, 208),
        font=card_sub_font,
    )

    # 4 Sub-Agents Cards
    agents = [
        (
            120,
            "OSINT",
            "google_search_agent",
            "OSINT Public Threat Intel",
            "Investigates external IPs & C2 domains",
            "Tor exit nodes, foreign ASN, malware",
            "Native ADK Toolset (no database access)",
            "Native Tool: google_search",
            "Zero Cloud Run dependency",
            (8, 47, 73),
            (56, 189, 248),
            (125, 211, 252),
        ),
        (
            465,
            "BQ",
            "bq_investigation_agent",
            "BigQuery Behavioral Baseline",
            "Queries 24h entity telemetry profile",
            "Failed logins, sudo escalations, lateral moves",
            "Parameterized queries (1GB ceiling)",
            "MCP: get_entity_behavioral_profile",
            "Scoped via tool_filter",
            (30, 27, 75),
            (129, 140, 248),
            (199, 210, 254),
        ),
        (
            810,
            "VISION",
            "visual_analysis_agent",
            "Gemini Multimodal Vision OCR",
            "Desktop screenshot forensic inspection",
            "Mimikatz, PowerShell, payload downloads",
            "Short-lived V4 signed URLs for analysts",
            "MCP: Vision OCR & Signed URLs",
            "get_visual_analysis_for_user",
            (4, 47, 46),
            (52, 211, 153),
            (167, 243, 208),
        ),
        (
            1155,
            "SOC",
            "soc_ticketing_agent",
            "Triage, Escalation & Dispatch",
            "Synthesizes evidence & determines action",
            "High-conf incident dispatch or FP closure",
            "Security gate verifies deterministic ID",
            "MCP: dispatch_to_soc, log_fp",
            "Auditable ticket resolution",
            (67, 20, 7),
            (251, 146, 60),
            (254, 215, 170),
        ),
    ]

    for (
        ax,
        chip_tag,
        name,
        badge_text,
        desc1,
        desc2,
        desc3,
        tool_text,
        tool_sub,
        bg_c,
        stroke_c,
        text_c,
    ) in agents:
        draw.rounded_rectangle(
            [(ax, 910), (ax + 325, 1100)],
            radius=12,
            fill=bg_c,
            outline=stroke_c,
            width=1,
        )
        draw_badge(
            draw,
            (ax + 14, 920, ax + 14 + len(chip_tag) * 9 + 12, 936),
            chip_tag,
            chip_font,
            bg_c,
            stroke_c,
            text_c,
            radius=4,
        )
        draw.text(
            (ax + 20 + len(chip_tag) * 9 + 12, 920),
            name,
            fill=(255, 255, 255),
            font=get_font("sans", 13, bold=True),
        )
        draw_badge(
            draw,
            (ax + 14, 944, ax + 215, 964),
            badge_text,
            get_font("sans", 9.5, bold=True),
            bg_c,
            stroke_c,
            text_c,
            radius=4,
        )
        draw.line([(ax + 14, 972), (ax + 311, 972)], fill=(71, 85, 105), width=1)
        draw.text(
            (ax + 14, 980), f"Role: {desc1}", fill=(241, 245, 249), font=card_sub_font
        )
        draw.text(
            (ax + 14, 998), f"Intel: {desc2}", fill=(203, 213, 225), font=card_sub_font
        )
        draw.text(
            (ax + 14, 1016), f"Scope: {desc3}", fill=(148, 163, 184), font=card_sub_font
        )

        # Tool Box inside Agent
        draw.rounded_rectangle(
            [(ax + 14, 1038), (ax + 311, 1086)],
            radius=6,
            fill=(15, 23, 42),
            outline=stroke_c,
            width=1,
        )
        draw.text((ax + 20, 1046), tool_text, fill=text_c, font=pill_mono_font)
        draw.text((ax + 20, 1065), tool_sub, fill=(148, 163, 184), font=card_sub_font)

    # Connector from Orchestrator down to MCP Tool Service
    draw_arrow(
        draw,
        [(800, 1120), (800, 1175)],
        color=(192, 132, 252),
        width=2,
        arrow_size=7,
    )
    draw_badge(
        draw,
        (560, 1136, 1040, 1160),
        "MCP over HTTPS + ID token (agent SA: run.invoker only)",
        label_font,
        (46, 16, 101),
        (192, 132, 252),
        (233, 213, 255),
        radius=5,
    )

    # ==================== TIER 7: DECOUPLED MCP TOOL SERVICE ====================
    draw.rounded_rectangle(
        [(100, 1175), (1500, 1355)],
        radius=18,
        fill=(46, 16, 101),
        outline=(192, 132, 252),
        width=2,
    )
    draw_badge(
        draw,
        (130, 1187, 180, 1205),
        "MCP",
        chip_font,
        (59, 7, 100),
        (192, 132, 252),
        (233, 213, 255),
        radius=4,
    )
    draw.text(
        (190, 1187),
        "MCP Tool Service (Cloud Run: cymbal-cyber-mcp) — Principle of Least Privilege Boundary",
        fill=(255, 255, 255),
        font=card_title_font,
    )
    draw.text(
        (130, 1209),
        "Dedicated Tools SA: cymbal-mcp-tools-sa • Transports: HTTPS (Cloud Run) / stdio (Local) • Fixed Parameterized Operations (No free-form SQL)",
        fill=(233, 213, 255),
        font=card_sub_font,
    )

    # 4 MCP Tool Pillars
    pillars = [
        (
            120,
            "BigQuery Telemetry",
            "• get_entity_behavioral_profile",
            "24h baseline query (user / IP)",
            "1 GB maximum_bytes_billed ceiling",
            "Read-Only Evidence Access",
            (30, 27, 75),
            (129, 140, 248),
            (199, 210, 254),
        ),
        (
            465,
            "Multimodal Vision OCR",
            "• get_visual_analysis_for_user",
            "• get_gcs_uri_for_user",
            "• generate_signed_url (V4 signed)",
            "Gemini Vision on GCS Evidence",
            (4, 47, 46),
            (52, 211, 153),
            (167, 243, 208),
        ),
        (
            810,
            "SOC Ticketing Operations",
            "• dispatch_to_soc_ticketing_system",
            "• log_false_positive (Archive FP)",
            "• create_rich_ticket_id (Gate verified)",
            "Auditable Ticket Writes",
            (69, 26, 3),
            (234, 88, 12),
            (254, 215, 170),
        ),
        (
            1155,
            "Platform Guardrails",
            "• auto_escalate_unresolved_alert",
            "Fixed server-side (DEFAULT_DENY)",
            "• escalate_to_human (GCS payload)",
            "Default-Deny Escalation",
            (63, 7, 19),
            (244, 63, 94),
            (254, 205, 211),
        ),
    ]

    for px, ptitle, pt1, pt2, pt3, pbadge, bg_c, stroke_c, text_c in pillars:
        draw.rounded_rectangle(
            [(px, 1235), (px + 325, 1340)],
            radius=10,
            fill=bg_c,
            outline=stroke_c,
            width=1,
        )
        draw.text(
            (px + 14, 1245),
            ptitle,
            fill=(255, 255, 255),
            font=get_font("sans", 12.5, bold=True),
        )
        draw.text((px + 14, 1267), pt1, fill=text_c, font=pill_mono_font)
        draw.text((px + 14, 1285), pt2, fill=(203, 213, 225), font=card_sub_font)
        draw.text((px + 14, 1301), pt3, fill=(148, 163, 184), font=card_sub_font)
        draw_badge(
            draw,
            (px + 14, 1318, px + 210, 1334),
            pbadge,
            get_font("sans", 8.5, bold=True),
            bg_c,
            stroke_c,
            text_c,
            radius=3,
        )

    # Connector from MCP Tool Service down to SOC Ticketing System
    draw_arrow(
        draw,
        [(800, 1355), (800, 1405)],
        color=(244, 63, 94),
        width=2,
        arrow_size=7,
    )
    draw_badge(
        draw,
        (570, 1368, 1030, 1392),
        "Dispatches Incidents & Writes soc_tickets Table",
        label_font,
        (63, 7, 19),
        (244, 63, 94),
        (254, 205, 211),
        radius=5,
    )

    # ==================== TIER 8: SOC TICKETING & ANALYST CONSOLE ====================
    draw.rounded_rectangle(
        [(100, 1405), (1500, 1530)],
        radius=18,
        fill=(31, 19, 26),
        outline=(244, 63, 94),
        width=2,
    )
    draw_badge(
        draw,
        (130, 1417, 180, 1435),
        "SOC",
        chip_font,
        (76, 5, 25),
        (244, 63, 94),
        (254, 205, 211),
        radius=4,
    )
    draw.text(
        (190, 1417),
        "SOC Ticketing System & Streamlit Analyst Console",
        fill=(255, 255, 255),
        font=card_title_font,
    )
    draw.text(
        (130, 1439),
        "src.demo.soc_ticketing • streamlit_soc_console.py (Local port 8501)",
        fill=(251, 113, 133),
        font=card_mono_font,
    )

    soc_boxes = [
        ("Incident Queue: soc_tickets + GCS Escalations", 125, 430),
        ("Webhook Integrations: Slack / Jira / ServiceNow", 575, 430),
        ("Streamlit Console: Interactive Triage & Evidence", 1025, 450),
    ]
    for stext, sx, sw in soc_boxes:
        draw_badge(
            draw,
            (sx, 1465, sx + sw, 1510),
            stext,
            pill_mono_font,
            (63, 7, 19),
            (190, 18, 60),
            (254, 205, 211),
            radius=8,
        )

    img.save(PNG_PATH, "PNG")
    print(f"Generated PNG: {PNG_PATH}")


def main():
    create_svg()
    create_png()


if __name__ == "__main__":
    main()
