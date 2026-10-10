"""
Script to generate System Architecture Diagram as both SVG and PNG image files.
Based on src/demo/README_REFACTORED.md for Google Cloud Platform (oso-ai-503519).
"""

import os
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont

OUTPUT_DIR = Path("/workspaces/Google/src/demo")
SVG_PATH = OUTPUT_DIR / "system_architecture.svg"
PNG_PATH = OUTPUT_DIR / "system_architecture.png"

def create_svg():
    svg_content = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1560 1200" width="1560" height="1200">
  <defs>
    <!-- Background Gradient -->
    <linearGradient id="bgGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#0b0f19"/>
      <stop offset="50%" stop-color="#111827"/>
      <stop offset="100%" stop-color="#090d16"/>
    </linearGradient>

    <!-- Card Gradients -->
    <linearGradient id="generatorGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#2e1065"/>
      <stop offset="100%" stop-color="#1e1b4b"/>
    </linearGradient>

    <linearGradient id="pipelineGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#1e293b"/>
      <stop offset="100%" stop-color="#0f172a"/>
    </linearGradient>

    <linearGradient id="bqGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#1e3a8a"/>
      <stop offset="100%" stop-color="#0f172a"/>
    </linearGradient>

    <linearGradient id="detectGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#3b2d12"/>
      <stop offset="100%" stop-color="#1c1917"/>
    </linearGradient>

    <linearGradient id="adkGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#064e3b"/>
      <stop offset="100%" stop-color="#022c22"/>
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
      <stop offset="100%" stop-color="#451a03"/>
    </linearGradient>

    <linearGradient id="socConsoleGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#881337"/>
      <stop offset="100%" stop-color="#1f131a"/>
    </linearGradient>

    <!-- Drop Shadow Filters -->
    <filter id="shadow" x="-10%" y="-10%" width="125%" height="125%">
      <feDropShadow dx="0" dy="6" stdDeviation="8" flood-color="#000000" flood-opacity="0.5"/>
    </filter>

    <filter id="cardGlowPurple" x="-10%" y="-10%" width="120%" height="120%">
      <feDropShadow dx="0" dy="0" stdDeviation="6" flood-color="#a855f7" flood-opacity="0.3"/>
    </filter>

    <filter id="cardGlowGreen" x="-10%" y="-10%" width="120%" height="120%">
      <feDropShadow dx="0" dy="0" stdDeviation="8" flood-color="#10b981" flood-opacity="0.35"/>
    </filter>

    <!-- Markers for arrows -->
    <marker id="arrowPurple" markerWidth="10" markerHeight="10" refX="7" refY="3.5" orient="auto">
      <polygon points="0 0, 8 3.5, 0 7" fill="#a855f7"/>
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
    <marker id="arrowOrange" markerWidth="10" markerHeight="10" refX="7" refY="3.5" orient="auto">
      <polygon points="0 0, 8 3.5, 0 7" fill="#fb923c"/>
    </marker>
  </defs>

  <style>
    .title { font-family: 'Inter', -apple-system, 'Segoe UI', Roboto, sans-serif; font-weight: 800; font-size: 27px; fill: #f8fafc; }
    .subtitle { font-family: 'Inter', -apple-system, 'Segoe UI', Roboto, sans-serif; font-weight: 500; font-size: 14px; fill: #94a3b8; }
    .card-title { font-family: 'Inter', -apple-system, 'Segoe UI', Roboto, sans-serif; font-weight: 700; font-size: 17px; fill: #ffffff; }
    .card-sub { font-family: 'Inter', -apple-system, 'Segoe UI', Roboto, sans-serif; font-weight: 500; font-size: 12px; fill: #cbd5e1; }
    .card-mono { font-family: 'DejaVu Sans Mono', Consolas, Monaco, monospace; font-size: 11.5px; fill: #93c5fd; }
    .badge { font-family: 'Inter', -apple-system, 'Segoe UI', Roboto, sans-serif; font-size: 11px; font-weight: 600; }
    .flow-label { font-family: 'Inter', -apple-system, 'Segoe UI', Roboto, sans-serif; font-weight: 600; font-size: 11.5px; fill: #cbd5e1; }
    .agent-header { font-family: 'Inter', -apple-system, 'Segoe UI', Roboto, sans-serif; font-weight: 700; font-size: 15px; fill: #ffffff; }
    .agent-desc { font-family: 'Inter', -apple-system, 'Segoe UI', Roboto, sans-serif; font-size: 11.5px; fill: #cbd5e1; }
    .pill-text { font-family: 'DejaVu Sans Mono', Consolas, monospace; font-size: 10.5px; font-weight: 600; }
  </style>

  <!-- Background -->
  <rect width="1560" height="1200" fill="url(#bgGrad)"/>
  
  <!-- Subtle Grid Pattern Lines -->
  <g opacity="0.05" stroke="#ffffff" stroke-width="1">
    <line x1="0" y1="150" x2="1560" y2="150"/>
    <line x1="0" y1="330" x2="1560" y2="330"/>
    <line x1="0" y1="520" x2="1560" y2="520"/>
    <line x1="0" y1="670" x2="1560" y2="670"/>
    <line x1="0" y1="920" x2="1560" y2="920"/>
    <line x1="260" y1="0" x2="260" y2="1200"/>
    <line x1="780" y1="0" x2="780" y2="1200"/>
    <line x1="1300" y1="0" x2="1300" y2="1200"/>
  </g>

  <!-- ==================== HEADER ==================== -->
  <g transform="translate(60, 45)">
    <rect x="-10" y="-8" width="56" height="56" rx="14" fill="#1e293b" stroke="#334155" stroke-width="1.5"/>
    <text x="5" y="28" font-size="28">🛡️</text>
    <text x="65" y="20" class="title">Enterprise Real-Time Cybersecurity AI: Cloud Architecture &amp; ADK SOC</text>
    <text x="65" y="42" class="subtitle">Google Cloud Platform (<tspan fill="#38bdf8" font-weight="700">oso-ai-503519</tspan>) • BigQuery Continuous Lakehouse • Google ADK Multi-Agent System • Gemini Vision</text>
  </g>

  <!-- ==================== 1. SYNTHETIC LOG GENERATOR LAYER ==================== -->
  <g transform="translate(540, 115)" filter="url(#shadow)">
    <rect width="480" height="92" rx="16" fill="url(#generatorGrad)" stroke="#a855f7" stroke-width="2" filter="url(#cardGlowPurple)"/>
    <text x="25" y="32" class="card-title">⚙️ Synthetic Log Generator &amp; Threat Injector</text>
    <text x="25" y="54" class="card-mono">src.demo.data_generator.log_generator</text>
    
    <!-- Pills for Generator modes -->
    <rect x="25" y="64" width="86" height="20" rx="6" fill="#3b0764" stroke="#c084fc" stroke-width="1"/>
    <text x="35" y="78" class="badge" fill="#e9d5ff">Benign Mode</text>

    <rect x="119" y="64" width="102" height="20" rx="6" fill="#3b0764" stroke="#c084fc" stroke-width="1"/>
    <text x="127" y="78" class="badge" fill="#e9d5ff">Continuous Stream</text>

    <rect x="229" y="64" width="112" height="20" rx="6" fill="#4c0519" stroke="#f43f5e" stroke-width="1"/>
    <text x="237" y="78" class="badge" fill="#fecdd3">Malicious Scenario</text>

    <rect x="349" y="64" width="105" height="20" rx="6" fill="#422006" stroke="#f59e0b" stroke-width="1"/>
    <text x="357" y="78" class="badge" fill="#fef08a">False-Positive Test</text>
  </g>

  <!-- Connectors from Generator to 3 Sinks -->
  <path d="M 620 207 L 620 235 L 290 235 L 290 265" fill="none" stroke="#a855f7" stroke-width="2" stroke-dasharray="5 3" marker-end="url(#arrowPurple)"/>
  <path d="M 780 207 L 780 265" fill="none" stroke="#a855f7" stroke-width="2.5" marker-end="url(#arrowPurple)"/>
  <path d="M 940 207 L 940 235 L 1270 235 L 1270 265" fill="none" stroke="#a855f7" stroke-width="2" stroke-dasharray="5 3" marker-end="url(#arrowPurple)"/>

  <text x="295" y="248" class="flow-label" fill="#c084fc">Batch Uploads</text>
  <text x="790" y="244" class="flow-label" fill="#c084fc">Pub/Sub Ingestion</text>
  <text x="1150" y="248" class="flow-label" fill="#c084fc">Direct Streaming</text>

  <!-- ==================== 2. INGESTION & PIPELINE LAYER ==================== -->
  <!-- Sink 1: Google Cloud Storage -->
  <g transform="translate(100, 270)" filter="url(#shadow)">
    <rect width="380" height="100" rx="14" fill="url(#pipelineGrad)" stroke="#38bdf8" stroke-width="1.8"/>
    <text x="20" y="30" class="card-title">🗄️ Google Cloud Storage</text>
    <text x="20" y="52" class="card-mono">gs://cymbal-cyber-raw-logs_oso-ai-503519</text>
    <rect x="20" y="65" width="340" height="24" rx="6" fill="#082f49" stroke="#0284c7" stroke-width="1"/>
    <text x="30" y="81" class="card-sub" fill="#7dd3fc">⚡ Batch Loader: <tspan class="card-mono" fill="#bae6fd">gcs_to_bigquery_loader.py</tspan></text>
  </g>

  <!-- Sink 2: Cloud Pub/Sub -->
  <g transform="translate(590, 270)" filter="url(#shadow)">
    <rect width="380" height="100" rx="14" fill="url(#pipelineGrad)" stroke="#0ea5e9" stroke-width="1.8"/>
    <text x="20" y="30" class="card-title">📨 Cloud Pub/Sub Topic</text>
    <text x="20" y="52" class="card-mono">cymbal_cyber_raw_logs</text>
    <rect x="20" y="65" width="340" height="24" rx="6" fill="#082f49" stroke="#0284c7" stroke-width="1"/>
    <text x="30" y="81" class="card-sub" fill="#7dd3fc">⚡ Dataflow: <tspan class="card-mono" fill="#bae6fd">pubsub_to_bigquery_dataflow.py</tspan></text>
  </g>

  <!-- Sink 3: Direct BigQuery Streaming -->
  <g transform="translate(1080, 270)" filter="url(#shadow)">
    <rect width="380" height="100" rx="14" fill="url(#pipelineGrad)" stroke="#06b6d4" stroke-width="1.8"/>
    <text x="20" y="30" class="card-title">⚡ Direct BQ Streaming</text>
    <text x="20" y="52" class="card-mono">BigQuery Storage Write API</text>
    <rect x="20" y="65" width="340" height="24" rx="6" fill="#042f2e" stroke="#0d9488" stroke-width="1"/>
    <text x="30" y="81" class="card-sub" fill="#5eead4">🚀 Ultra-low latency micro-batch ingestion</text>
  </g>

  <!-- Connectors from Sinks to BigQuery Lakehouse -->
  <path d="M 290 370 L 290 410 L 460 410 L 460 435" fill="none" stroke="#38bdf8" stroke-width="2" marker-end="url(#arrowBlue)"/>
  <path d="M 780 370 L 780 435" fill="none" stroke="#38bdf8" stroke-width="2.5" marker-end="url(#arrowBlue)"/>
  <path d="M 1270 370 L 1270 410 L 1100 410 L 1100 435" fill="none" stroke="#38bdf8" stroke-width="2" marker-end="url(#arrowBlue)"/>

  <!-- ==================== 3. BIGQUERY CENTRAL LAKEHOUSE ==================== -->
  <g transform="translate(200, 440)" filter="url(#shadow)">
    <rect width="1160" height="110" rx="18" fill="url(#bqGrad)" stroke="#60a5fa" stroke-width="2"/>
    <text x="30" y="35" class="card-title">📊 BigQuery Enterprise Security Lakehouse (Dataset: <tspan fill="#93c5fd">Cymbal_Cyber</tspan>)</text>
    <text x="30" y="57" class="card-sub">Time-partitioned and clustered analytics tables for real-time threat intelligence and investigation</text>

    <!-- Table badges -->
    <g transform="translate(30, 68)">
      <!-- Table 1 -->
      <rect x="0" y="0" width="200" height="30" rx="8" fill="#1e293b" stroke="#3b82f6" stroke-width="1.2"/>
      <text x="12" y="19" class="pill-text" fill="#60a5fa">📄 user_access_events</text>

      <!-- Table 2 -->
      <rect x="215" y="0" width="180" height="30" rx="8" fill="#1e293b" stroke="#3b82f6" stroke-width="1.2"/>
      <text x="12" y="19" class="pill-text" fill="#60a5fa">🌐 network_events</text>

      <!-- Table 3 -->
      <rect x="410" y="0" width="230" height="30" rx="8" fill="#1e293b" stroke="#38bdf8" stroke-width="1.2"/>
      <text x="12" y="19" class="pill-text" fill="#7dd3fc">🛡️ adk_threat_assessment</text>

      <!-- Table 4 -->
      <rect x="655" y="0" width="165" height="30" rx="8" fill="#1e293b" stroke="#f43f5e" stroke-width="1.2"/>
      <text x="12" y="19" class="pill-text" fill="#fda4af">🎟️ soc_tickets</text>

      <!-- Table 5 -->
      <rect x="835" y="0" width="260" height="30" rx="8" fill="#1e293b" stroke="#a855f7" stroke-width="1.2"/>
      <text x="12" y="19" class="pill-text" fill="#d8b4fe">🖼️ user_screenshots_view</text>
    </g>
  </g>

  <!-- Connectors from BigQuery to Detection Engines -->
  <path d="M 520 550 L 520 585" fill="none" stroke="#f59e0b" stroke-width="2.5" marker-end="url(#arrowYellow)"/>
  <path d="M 1040 550 L 1040 585" fill="none" stroke="#f59e0b" stroke-width="2.5" marker-end="url(#arrowYellow)"/>

  <!-- ==================== 4. DETECTION & STREAM ANALYTICS ENGINES ==================== -->
  <!-- Engine 1: Continuous Query -->
  <g transform="translate(240, 590)" filter="url(#shadow)">
    <rect width="500" height="85" rx="14" fill="url(#detectGrad)" stroke="#f59e0b" stroke-width="1.8"/>
    <text x="25" y="30" class="card-title">⚡ BigQuery Continuous Query</text>
    <text x="25" y="50" class="card-mono">continuous_query.sql</text>
    <text x="25" y="70" class="card-sub" fill="#fde68a">Temporal tumbling window (2m) • Exports alerts &gt;= 100 to Pub/Sub</text>
  </g>

  <!-- Engine 2: BigQuery Threat Scanner -->
  <g transform="translate(820, 590)" filter="url(#shadow)">
    <rect width="500" height="85" rx="14" fill="url(#detectGrad)" stroke="#f59e0b" stroke-width="1.8"/>
    <text x="25" y="30" class="card-title">🔍 BigQuery Threat Scanner</text>
    <text x="25" y="50" class="card-mono">src.demo.adk_agent.threat_scanner</text>
    <text x="25" y="70" class="card-sub" fill="#fde68a">Active background daemon polling BQ for anomalous threat thresholds</text>
  </g>

  <!-- Connectors from Detection Engines to ADK Orchestrator -->
  <path d="M 490 675 L 490 705 L 670 705 L 670 725" fill="none" stroke="#10b981" stroke-width="2.5" marker-end="url(#arrowGreen)"/>
  <path d="M 1070 675 L 1070 705 L 890 705 L 890 725" fill="none" stroke="#10b981" stroke-width="2.5" marker-end="url(#arrowGreen)"/>
  <text x="740" y="715" class="badge" fill="#6ee7b7" text-anchor="middle">Dispatches Alert Triggers</text>

  <!-- ==================== 5. ADK MULTI-AGENT ORCHESTRATOR ==================== -->
  <g transform="translate(420, 730)" filter="url(#shadow)">
    <rect width="720" height="82" rx="18" fill="url(#adkGrad)" stroke="#10b981" stroke-width="2.2" filter="url(#cardGlowGreen)"/>
    <text x="30" y="33" class="card-title">🤖 Google ADK Multi-Agent Orchestrator</text>
    <text x="30" y="53" class="card-sub" fill="#a7f3d0">Autonomous coordination of specialized agent tools, session state, and investigation memory</text>
    <text x="30" y="70" class="card-mono" fill="#6ee7b7">Framework: google-adk &gt;= 2.11.0 • Gemini 1.5/2.0 on Vertex AI</text>
  </g>

  <!-- Connectors from Orchestrator down to 4 Sub-Agents -->
  <path d="M 520 812 L 520 840 L 220 840 L 220 865" fill="none" stroke="#38bdf8" stroke-width="2" marker-end="url(#arrowBlue)"/>
  <path d="M 670 812 L 670 840 L 590 840 L 590 865" fill="none" stroke="#818cf8" stroke-width="2" marker-end="url(#arrowBlue)"/>
  <path d="M 870 812 L 870 840 L 970 840 L 970 865" fill="none" stroke="#34d399" stroke-width="2" marker-end="url(#arrowGreen)"/>
  <path d="M 1040 812 L 1040 840 L 1340 840 L 1340 865" fill="none" stroke="#fb923c" stroke-width="2" marker-end="url(#arrowOrange)"/>

  <!-- ==================== 6. THE 4 SPECIALIZED SUB-AGENTS ==================== -->
  <!-- Agent 1: google_search_agent -->
  <g transform="translate(60, 870)" filter="url(#shadow)">
    <rect width="320" height="155" rx="14" fill="url(#agentSearchGrad)" stroke="#38bdf8" stroke-width="1.8"/>
    <text x="18" y="28" class="agent-header">🔎 google_search_agent</text>
    <text x="18" y="48" class="badge" fill="#bae6fd">OSINT &amp; Public Threat Intelligence</text>
    <line x1="18" y1="58" x2="302" y2="58" stroke="#0284c7" stroke-width="1"/>
    
    <text x="18" y="78" class="agent-desc"><tspan font-weight="700" fill="#ffffff">Role:</tspan> Investigates external IPs &amp; C2 domains</text>
    <text x="18" y="96" class="agent-desc"><tspan font-weight="700" fill="#ffffff">Target:</tspan> Geolocation, foreign ASN, Tor exits</text>
    
    <rect x="18" y="112" width="284" height="28" rx="6" fill="#082f49" stroke="#0ea5e9" stroke-width="1"/>
    <text x="28" y="130" class="pill-text" fill="#7dd3fc">🛠️ Tool: google_search</text>
  </g>

  <!-- Agent 2: bq_investigation_agent -->
  <g transform="translate(430, 870)" filter="url(#shadow)">
    <rect width="320" height="155" rx="14" fill="url(#agentBqGrad)" stroke="#818cf8" stroke-width="1.8"/>
    <text x="18" y="28" class="agent-header">🗄️ bq_investigation_agent</text>
    <text x="18" y="48" class="badge" fill="#c7d2fe">BigQuery Historical Profiling</text>
    <line x1="18" y1="58" x2="302" y2="58" stroke="#4338ca" stroke-width="1"/>
    
    <text x="18" y="78" class="agent-desc"><tspan font-weight="700" fill="#ffffff">Role:</tspan> Queries 24h behavioural activity baseline</text>
    <text x="18" y="96" class="agent-desc"><tspan font-weight="700" fill="#ffffff">Target:</tspan> Failed auth, privilege esc, lateral move</text>
    
    <rect x="18" y="112" width="284" height="28" rx="6" fill="#1e1b4b" stroke="#6366f1" stroke-width="1"/>
    <text x="28" y="130" class="pill-text" fill="#a5b4fc">🛠️ Tools: BigQueryToolset, SQL</text>
  </g>

  <!-- Agent 3: visual_analysis_agent -->
  <g transform="translate(800, 870)" filter="url(#shadow)">
    <rect width="320" height="155" rx="14" fill="url(#agentVisionGrad)" stroke="#34d399" stroke-width="1.8"/>
    <text x="18" y="28" class="agent-header">👁️ visual_analysis_agent</text>
    <text x="18" y="48" class="badge" fill="#a7f3d0">Gemini Multimodal Forensic OCR</text>
    <line x1="18" y1="58" x2="302" y2="58" stroke="#047857" stroke-width="1"/>
    
    <text x="18" y="78" class="agent-desc"><tspan font-weight="700" fill="#ffffff">Role:</tspan> Forensics on user workstation screenshots</text>
    <text x="18" y="96" class="agent-desc"><tspan font-weight="700" fill="#ffffff">Target:</tspan> Mimikatz, PowerShell, payload downloads</text>
    
    <rect x="18" y="112" width="284" height="28" rx="6" fill="#022c22" stroke="#10b981" stroke-width="1"/>
    <text x="28" y="130" class="pill-text" fill="#6ee7b7">🛠️ Tools: Vision OCR, Signed URLs</text>
  </g>

  <!-- Agent 4: soc_ticketing_agent -->
  <g transform="translate(1180, 870)" filter="url(#shadow)">
    <rect width="320" height="155" rx="14" fill="url(#agentSocGrad)" stroke="#fb923c" stroke-width="1.8"/>
    <text x="18" y="28" class="agent-header">📋 soc_ticketing_agent</text>
    <text x="18" y="48" class="badge" fill="#fed7aa">Triage, Escalation &amp; Dispatch</text>
    <line x1="18" y1="58" x2="302" y2="58" stroke="#c2410c" stroke-width="1"/>
    
    <text x="18" y="78" class="agent-desc"><tspan font-weight="700" fill="#ffffff">Role:</tspan> Synthesizes evidence &amp; determines action</text>
    <text x="18" y="96" class="agent-desc"><tspan font-weight="700" fill="#ffffff">Target:</tspan> Dispatches incident ticket or flags FP</text>
    
    <rect x="18" y="112" width="284" height="28" rx="6" fill="#451a03" stroke="#ea580c" stroke-width="1"/>
    <text x="28" y="130" class="pill-text" fill="#fdba74">🛠️ Tools: dispatch_to_soc, log_fp</text>
  </g>

  <!-- Connector from SOC Agent down to Ticketing & Console -->
  <path d="M 1340 1025 L 1340 1055 L 1050 1055 L 1050 1075" fill="none" stroke="#f43f5e" stroke-width="2.5" marker-end="url(#arrowRed)"/>
  <text x="1200" y="1050" class="flow-label" fill="#fda4af">Dispatches Incident Package</text>

  <!-- ==================== 7. SOC TICKETING & ANALYST CONSOLE ==================== -->
  <g transform="translate(180, 1080)" filter="url(#shadow)">
    <rect width="1200" height="95" rx="16" fill="url(#socConsoleGrad)" stroke="#f43f5e" stroke-width="2"/>
    <text x="25" y="32" class="card-title">🚨 SOC Ticketing System &amp; Streamlit Analyst Console</text>
    <text x="25" y="52" class="card-mono">src.demo.soc_ticketing • streamlit_soc_console.py</text>
    
    <g transform="translate(25, 62)">
      <rect x="0" y="0" width="360" height="24" rx="6" fill="#3f0713" stroke="#be123c" stroke-width="1"/>
      <text x="10" y="16" class="pill-text" fill="#fecdd3">📦 Storage: soc_tickets + GCS Escalations</text>

      <rect x="380" y="0" width="360" height="24" rx="6" fill="#3f0713" stroke="#be123c" stroke-width="1"/>
      <text x="10" y="16" class="pill-text" fill="#fecdd3">🔗 Webhooks: Slack / Jira / ServiceNow</text>

      <rect x="760" y="0" width="380" height="24" rx="6" fill="#3f0713" stroke="#be123c" stroke-width="1"/>
      <text x="10" y="16" class="pill-text" fill="#fecdd3">🖥️ Console: Forensic Triage &amp; Signed Screens</text>
    </g>
  </g>
</svg>
"""
    with open(SVG_PATH, "w", encoding="utf-8") as f:
        f.write(svg_content)
    print(f"Generated SVG: {SVG_PATH}")

def draw_arrow(draw, points, color, width=2, arrow_size=8, direction="down"):
    # Draw line segments
    for i in range(len(points) - 1):
        draw.line([points[i], points[i+1]], fill=color, width=width)
    
    # Draw arrowhead at the end point
    end_x, end_y = points[-1]
    if direction == "down":
        arrow = [(end_x - arrow_size, end_y - arrow_size * 1.3),
                 (end_x + arrow_size, end_y - arrow_size * 1.3),
                 (end_x, end_y)]
    elif direction == "up":
        arrow = [(end_x - arrow_size, end_y + arrow_size * 1.3),
                 (end_x + arrow_size, end_y + arrow_size * 1.3),
                 (end_x, end_y)]
    elif direction == "right":
        arrow = [(end_x - arrow_size * 1.3, end_y - arrow_size),
                 (end_x - arrow_size * 1.3, end_y + arrow_size),
                 (end_x, end_y)]
    elif direction == "left":
        arrow = [(end_x + arrow_size * 1.3, end_y - arrow_size),
                 (end_x + arrow_size * 1.3, end_y + arrow_size),
                 (end_x, end_y)]
    draw.polygon(arrow, fill=color)

def create_png():
    width, height = 1560, 1220
    img = Image.new("RGBA", (width, height), (11, 15, 25, 255))
    draw = ImageDraw.Draw(img)

    # Fonts
    font_sans = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
    font_bold = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"
    font_mono = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"

    title_font = ImageFont.truetype(font_bold, 23)
    sub_font = ImageFont.truetype(font_sans, 13)
    card_title_font = ImageFont.truetype(font_bold, 16)
    card_sub_font = ImageFont.truetype(font_sans, 12)
    card_mono_font = ImageFont.truetype(font_mono, 11)
    badge_font = ImageFont.truetype(font_bold, 11)
    label_font = ImageFont.truetype(font_bold, 11)

    # Grid background lines
    for y in [150, 330, 520, 670, 920]:
        draw.line([(0, y), (width, y)], fill=(30, 41, 59, 100), width=1)
    for x in [260, 780, 1300]:
        draw.line([(x, 0), (x, height)], fill=(30, 41, 59, 100), width=1)

    # Header
    draw.rounded_rectangle([(60, 35), (120, 85)], radius=12, fill=(30, 41, 59), outline=(56, 189, 248), width=2)
    draw.text((72, 47), "SOC", fill=(56, 189, 248), font=ImageFont.truetype(font_bold, 18))
    draw.text((140, 38), "Enterprise Real-Time Cybersecurity AI: Cloud Architecture & ADK SOC", fill=(248, 250, 252), font=title_font)
    draw.text((140, 68), "Google Cloud Platform (oso-ai-503519) | BigQuery Lakehouse | Google ADK Multi-Agent System | Gemini Vision", fill=(148, 163, 184), font=sub_font)

    # 1. Synthetic Log Generator Layer
    draw.rounded_rectangle([(520, 115), (1040, 210)], radius=16, fill=(30, 27, 75), outline=(168, 85, 247), width=2)
    draw.text((545, 125), "Synthetic Log Generator & Threat Injector", fill=(255, 255, 255), font=card_title_font)
    draw.text((545, 148), "src.demo.data_generator.log_generator", fill=(192, 132, 252), font=card_mono_font)
    
    # Badges
    badges = [
        ("Benign Mode", 545, 95, (59, 7, 100), (233, 213, 255)),
        ("Continuous Stream", 650, 125, (59, 7, 100), (233, 213, 255)),
        ("Malicious Scenario", 785, 125, (76, 5, 25), (254, 205, 211)),
        ("False-Positive Test", 920, 110, (66, 32, 6), (254, 240, 138)),
    ]
    for text, bx, bw, bg, fg in badges:
        draw.rounded_rectangle([(bx, 172), (bx + bw, 195)], radius=5, fill=bg, outline=fg, width=1)
        draw.text((bx + 8, 177), text, fill=fg, font=badge_font)

    # Flow lines from Generator
    draw_arrow(draw, [(610, 210), (610, 235), (290, 235), (290, 270)], color=(168, 85, 247), width=2, direction="down")
    draw_arrow(draw, [(780, 210), (780, 270)], color=(168, 85, 247), width=3, direction="down")
    draw_arrow(draw, [(950, 210), (950, 235), (1270, 235), (1270, 270)], color=(168, 85, 247), width=2, direction="down")

    draw.text((300, 242), "Batch Uploads", fill=(192, 132, 252), font=label_font)
    draw.text((790, 242), "Pub/Sub Streaming", fill=(192, 132, 252), font=label_font)
    draw.text((1150, 242), "Direct Streaming", fill=(192, 132, 252), font=label_font)

    # 2. Ingestion & Pipeline Layer
    # GCS
    draw.rounded_rectangle([(100, 270), (480, 370)], radius=14, fill=(15, 23, 42), outline=(56, 189, 248), width=2)
    draw.text((120, 282), "Google Cloud Storage", fill=(255, 255, 255), font=card_title_font)
    draw.text((120, 308), "gs://cymbal-cyber-raw-logs_oso-ai-503519", fill=(147, 197, 253), font=card_mono_font)
    draw.rounded_rectangle([(120, 332), (460, 356)], radius=6, fill=(8, 47, 73), outline=(2, 132, 199), width=1)
    draw.text((130, 337), "Batch Loader: gcs_to_bigquery_loader.py", fill=(186, 230, 253), font=card_mono_font)

    # PubSub
    draw.rounded_rectangle([(590, 270), (970, 370)], radius=14, fill=(15, 23, 42), outline=(14, 165, 233), width=2)
    draw.text((610, 282), "Cloud Pub/Sub Topic", fill=(255, 255, 255), font=card_title_font)
    draw.text((610, 308), "cymbal_cyber_raw_logs", fill=(147, 197, 253), font=card_mono_font)
    draw.rounded_rectangle([(610, 332), (950, 356)], radius=6, fill=(8, 47, 73), outline=(2, 132, 199), width=1)
    draw.text((620, 337), "Dataflow: pubsub_to_bigquery_dataflow.py", fill=(186, 230, 253), font=card_mono_font)

    # Direct BQ
    draw.rounded_rectangle([(1080, 270), (1460, 370)], radius=14, fill=(15, 23, 42), outline=(6, 182, 212), width=2)
    draw.text((1100, 282), "Direct BQ Streaming", fill=(255, 255, 255), font=card_title_font)
    draw.text((1100, 308), "BigQuery Storage Write API", fill=(147, 197, 253), font=card_mono_font)
    draw.rounded_rectangle([(1100, 332), (1440, 356)], radius=6, fill=(4, 47, 46), outline=(13, 148, 136), width=1)
    draw.text((1110, 337), "Ultra-low latency micro-batch streaming", fill=(94, 234, 212), font=card_mono_font)

    # Connectors to BigQuery
    draw_arrow(draw, [(290, 370), (290, 410), (460, 410), (460, 440)], color=(56, 189, 248), width=2, direction="down")
    draw_arrow(draw, [(780, 370), (780, 440)], color=(56, 189, 248), width=3, direction="down")
    draw_arrow(draw, [(1270, 370), (1270, 410), (1100, 410), (1100, 440)], color=(56, 189, 248), width=2, direction="down")

    # 3. BigQuery Lakehouse
    draw.rounded_rectangle([(200, 440), (1360, 550)], radius=18, fill=(15, 23, 42), outline=(96, 165, 250), width=2)
    draw.text((230, 452), "BigQuery Enterprise Security Lakehouse (Dataset: Cymbal_Cyber)", fill=(255, 255, 255), font=card_title_font)
    draw.text((230, 476), "Time-partitioned and clustered analytics tables for real-time threat intelligence", fill=(148, 163, 184), font=card_sub_font)
    
    bq_tables = [
        ("user_access_events", 230, 190, (59, 130, 246)),
        ("network_events", 440, 165, (59, 130, 246)),
        ("adk_threat_assessment", 625, 215, (56, 189, 248)),
        ("soc_tickets", 860, 140, (244, 63, 94)),
        ("user_screenshots_view", 1020, 220, (168, 85, 247)),
    ]
    for tbl, tx, tw, stroke_col in bq_tables:
        draw.rounded_rectangle([(tx, 502), (tx + tw, 532)], radius=8, fill=(30, 41, 59), outline=stroke_col, width=1)
        draw.text((tx + 12, 512), tbl, fill=(241, 245, 249), font=card_mono_font)

    # Connectors to Detection Engines
    draw_arrow(draw, [(520, 550), (520, 590)], color=(245, 158, 11), width=3, direction="down")
    draw_arrow(draw, [(1040, 550), (1040, 590)], color=(245, 158, 11), width=3, direction="down")

    # 4. Detection Engines
    # Continuous Query
    draw.rounded_rectangle([(240, 590), (740, 675)], radius=14, fill=(28, 25, 23), outline=(245, 158, 11), width=2)
    draw.text((265, 602), "BigQuery Continuous Query", fill=(255, 255, 255), font=card_title_font)
    draw.text((265, 626), "continuous_query.sql", fill=(253, 230, 138), font=card_mono_font)
    draw.text((265, 648), "Tumbling window (2m) -> Exports alerts >= 100 to Pub/Sub", fill=(214, 211, 209), font=card_sub_font)

    # Threat Scanner
    draw.rounded_rectangle([(820, 590), (1320, 675)], radius=14, fill=(28, 25, 23), outline=(245, 158, 11), width=2)
    draw.text((845, 602), "BigQuery Threat Scanner", fill=(255, 255, 255), font=card_title_font)
    draw.text((845, 626), "src.demo.adk_agent.threat_scanner", fill=(253, 230, 138), font=card_mono_font)
    draw.text((845, 648), "Active daemon polling BQ for anomalous threat thresholds", fill=(214, 211, 209), font=card_sub_font)

    # Connectors to ADK Orchestrator
    draw_arrow(draw, [(490, 675), (490, 705), (670, 705), (670, 730)], color=(16, 185, 129), width=3, direction="down")
    draw_arrow(draw, [(1070, 675), (1070, 705), (890, 705), (890, 730)], color=(16, 185, 129), width=3, direction="down")
    draw.text((700, 692), "Dispatches Alert Triggers", fill=(110, 231, 183), font=label_font)

    # 5. ADK Multi-Agent Orchestrator
    draw.rounded_rectangle([(420, 730), (1140, 812)], radius=18, fill=(2, 44, 34), outline=(16, 185, 129), width=2)
    draw.text((450, 742), "Google ADK Multi-Agent Orchestrator", fill=(255, 255, 255), font=card_title_font)
    draw.text((450, 766), "Coordinates specialized agents, session state, and investigation memory", fill=(167, 243, 208), font=card_sub_font)
    draw.text((450, 786), "Framework: google-adk >= 2.11.0 | Gemini Models on Vertex AI", fill=(110, 231, 183), font=card_mono_font)

    # Connectors to 4 Sub-Agents
    draw_arrow(draw, [(520, 812), (520, 840), (220, 840), (220, 870)], color=(56, 189, 248), width=2, direction="down")
    draw_arrow(draw, [(670, 812), (670, 840), (590, 840), (590, 870)], color=(129, 140, 248), width=2, direction="down")
    draw_arrow(draw, [(870, 812), (870, 840), (960, 840), (960, 870)], color=(52, 211, 153), width=2, direction="down")
    draw_arrow(draw, [(1040, 812), (1040, 840), (1340, 840), (1340, 870)], color=(251, 146, 60), width=2, direction="down")

    # 6. Four Sub-Agents
    agents_info = [
        (60, "google_search_agent", "OSINT Threat Intelligence", "Investigates IPs & C2 domains", "Tool: google_search", (8, 47, 73), (56, 189, 248)),
        (430, "bq_investigation_agent", "Behavioral Profiling", "Queries 24h user activity logs", "Tools: BigQueryToolset, SQL", (30, 27, 75), (129, 140, 248)),
        (800, "visual_analysis_agent", "Gemini Multimodal OCR", "Forensics on desktop screenshots", "Tools: Vision OCR, Signed URLs", (4, 47, 46), (52, 211, 153)),
        (1180, "soc_ticketing_agent", "Triage & Escalation", "Synthesizes evidence & dispatches", "Tools: dispatch_to_soc, log_fp", (69, 26, 3), (251, 146, 60)),
    ]

    for ax, name, role_badge, desc, tools, bg_col, stroke_col in agents_info:
        draw.rounded_rectangle([(ax, 870), (ax + 320, 1025)], radius=14, fill=bg_col, outline=stroke_col, width=2)
        draw.text((ax + 16, 882), name, fill=(255, 255, 255), font=card_title_font)
        draw.text((ax + 16, 908), role_badge, fill=stroke_col, font=badge_font)
        draw.line([(ax + 16, 924), (ax + 304, 924)], fill=(100, 116, 139), width=1)
        draw.text((ax + 16, 934), desc, fill=(226, 232, 240), font=card_sub_font)
        
        # Tool box
        draw.rounded_rectangle([(ax + 16, 970), (ax + 304, 1005)], radius=6, fill=(15, 23, 42), outline=stroke_col, width=1)
        draw.text((ax + 26, 982), tools, fill=stroke_col, font=card_mono_font)

    # Connector from SOC Agent to Ticketing System
    draw_arrow(draw, [(1340, 1025), (1340, 1050), (1050, 1050), (1050, 1075)], color=(244, 63, 94), width=3, direction="down")
    draw.text((1110, 1035), "Dispatches Incident Package", fill=(254, 205, 211), font=label_font)

    # 7. SOC Ticketing & Console
    draw.rounded_rectangle([(180, 1075), (1380, 1175)], radius=16, fill=(31, 19, 26), outline=(244, 63, 94), width=2)
    draw.text((205, 1088), "SOC Ticketing System & Streamlit Analyst Console", fill=(255, 255, 255), font=card_title_font)
    draw.text((205, 1110), "src.demo.soc_ticketing | streamlit_soc_console.py", fill=(251, 113, 133), font=card_mono_font)

    pills = [
        ("Storage: soc_tickets + GCS Escalations", 205, 360),
        ("Webhooks: Slack / Jira / ServiceNow", 585, 360),
        ("Console: Forensic Triage & Screenshots", 965, 390)
    ]
    for ptext, px, pw in pills:
        draw.rounded_rectangle([(px, 1134), (px + pw, 1158)], radius=6, fill=(63, 7, 19), outline=(190, 18, 60), width=1)
        draw.text((px + 10, 1140), ptext, fill=(254, 205, 211), font=card_mono_font)

    img.save(PNG_PATH, "PNG")
    print(f"Generated PNG: {PNG_PATH}")

if __name__ == "__main__":
    create_svg()
    create_png()
