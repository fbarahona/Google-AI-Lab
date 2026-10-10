"""
Modern Security Operations Center (SOC) Analyst Console
========================================================
Interactive web console for human SOC analysts to review, analyze,
and adjudicate incident tickets escalated by the Google ADK multi-agent workflow.

Dual-Mode Support:
- Cloud Mode: Reads from Google Cloud Storage bucket
- Local Mode: Reads from local directory (./local_demo_data/escalations) with offline screenshot rendering
"""

import os
import glob
import json
import time
import re
import streamlit as st
from datetime import datetime, timezone
from streamlit_autorefresh import st_autorefresh

# Project configuration
PROJECT_ID = os.getenv("GOOGLE_CLOUD_PROJECT", "oso-ai-503519")
ESCALATION_BUCKET_NAME = os.getenv(
    "ESCALATION_BUCKET",
    f"cymbal-cyber-adk-escalations-bucket_{PROJECT_ID}"
)
LOCAL_QUEUE_DIR = os.getenv("LOCAL_QUEUE_DIR", "./local_demo_data/escalations")
LOCAL_SCREENSHOTS_DIR = os.getenv("LOCAL_SCREENSHOTS_DIR", "src/demo/user_screenshots")
ESCALATION_POLL_INTERVAL = 4

st.set_page_config(
    page_title="Cymbal Cyber SOC Console",
    page_icon="🛡️",
    layout="wide"
)

# Initialize Session State
if "escalations" not in st.session_state:
    st.session_state.escalations = []
if "selected_ticket_id" not in st.session_state:
    st.session_state.selected_ticket_id = None
if "alert_data" not in st.session_state:
    st.session_state.alert_data = None
if "last_escalation_poll" not in st.session_state:
    st.session_state.last_escalation_poll = 0
if "response_comment" not in st.session_state:
    st.session_state.response_comment = ""
if "decision_choice" not in st.session_state:
    st.session_state.decision_choice = "Genuine Threat"
if "status_toast" not in st.session_state:
    st.session_state.status_toast = None
if "is_local_mode" not in st.session_state:
    st.session_state.is_local_mode = False

# Auto refresh every 5 seconds
st_autorefresh(interval=5 * 1000, key="soc_autorefresh")


@st.cache_resource
def get_storage_client():
    if os.getenv("LOCAL_MODE", "false").lower() == "true":
        return None
    try:
        from google.cloud import storage
        client = storage.Client(project=PROJECT_ID)
        # Test access
        client.bucket(ESCALATION_BUCKET_NAME)
        return client
    except Exception:
        return None


def fetch_escalations(client, force=False):
    now = time.time()
    if not force and (now - st.session_state.last_escalation_poll < ESCALATION_POLL_INTERVAL):
        return

    items = []
    # 1. Cloud GCS mode if client is valid
    if client is not None:
        try:
            bucket = client.bucket(ESCALATION_BUCKET_NAME)
            blobs = list(bucket.list_blobs())
            for b in blobs:
                if b.name.startswith("human_escalation_information_") and b.name.endswith(".json"):
                    try:
                        payload = json.loads(b.download_as_text())
                        items.append({
                            "ticket_id": payload.get("ticket_id", b.name),
                            "blob_name": b.name,
                            "data": payload
                        })
                    except Exception:
                        pass
            st.session_state.is_local_mode = False
        except Exception:
            client = None

    # 2. Local File Queue fallback
    if client is None:
        st.session_state.is_local_mode = True
        os.makedirs(LOCAL_QUEUE_DIR, exist_ok=True)
        files = glob.glob(os.path.join(LOCAL_QUEUE_DIR, "human_escalation_information_*.json"))
        for filepath in files:
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    payload = json.load(f)
                    items.append({
                        "ticket_id": payload.get("ticket_id", os.path.basename(filepath)),
                        "blob_name": os.path.basename(filepath),
                        "file_path": filepath,
                        "data": payload
                    })
            except Exception:
                pass

    st.session_state.escalations = items
    st.session_state.last_escalation_poll = now


def select_ticket(ticket_id, blob_name, data):
    st.session_state.selected_ticket_id = ticket_id
    st.session_state.alert_data = data
    st.session_state.response_comment = ""
    st.session_state.decision_choice = "Genuine Threat"


def submit_verdict(storage_client):
    ticket_id = st.session_state.selected_ticket_id
    data = st.session_state.alert_data
    if not ticket_id or not data:
        return

    decision = st.session_state.decision_choice
    comment = st.session_state.response_comment

    response_payload = {
        "ticket_id": ticket_id,
        "human_decision": decision,
        "human_comment": comment,
        "timestamp": time.time()
    }

    try:
        if storage_client is not None and not st.session_state.is_local_mode:
            bucket = storage_client.bucket(ESCALATION_BUCKET_NAME)
            response_blob = bucket.blob(f"human_escalation_response_{ticket_id}.json")
            response_blob.upload_from_string(
                json.dumps(response_payload, indent=2),
                content_type="application/json"
            )
        else:
            os.makedirs(LOCAL_QUEUE_DIR, exist_ok=True)
            out_file = os.path.join(LOCAL_QUEUE_DIR, f"human_escalation_response_{ticket_id}.json")
            with open(out_file, "w", encoding="utf-8") as f:
                json.dump(response_payload, f, indent=2)
            # Remove the pending escalation request in local mode
            req_file = os.path.join(LOCAL_QUEUE_DIR, f"human_escalation_information_{ticket_id}.json")
            if os.path.exists(req_file):
                os.remove(req_file)

        st.session_state.status_toast = f"Verdict logged: {decision} for ticket {ticket_id}."
        st.session_state.selected_ticket_id = None
        st.session_state.alert_data = None
        st.session_state.response_comment = ""
        fetch_escalations(storage_client, force=True)
    except Exception as e:
        st.error(f"Error submitting decision: {e}")


# --- Header & Metrics ---
storage_client = get_storage_client()
fetch_escalations(storage_client)

st.title("🛡️ Cymbal Cyber — Level 1/2 SOC Analyst Console")

mode_badge = "💻 Local Simulation Mode" if st.session_state.is_local_mode else "☁️ Cloud GCS Mode"
queue_info = LOCAL_QUEUE_DIR if st.session_state.is_local_mode else f"gs://{ESCALATION_BUCKET_NAME}"
st.caption(f"Status: **{mode_badge}** | Active Queue: `{queue_info}` | Target Project: `{PROJECT_ID}`")

if st.session_state.status_toast:
    st.toast(st.session_state.status_toast, icon="✅")
    st.session_state.status_toast = None

# Metrics Row
m1, m2, m3, m4 = st.columns(4)
pending_count = len(st.session_state.escalations)
m1.metric("Pending Escalations", pending_count, delta=f"{pending_count} awaiting triage", delta_color="inverse")
m2.metric("Environment", "Local Testing" if st.session_state.is_local_mode else "GCP Production")
m3.metric("Multi-Agent Framework", "Google ADK 2.11.0")
m4.metric("Incident Response", "Ready")

st.divider()

col_queue, col_detail = st.columns([1, 2], gap="large")

with col_queue:
    st.subheader(f"Incident Queue ({len(st.session_state.escalations)})")
    if not st.session_state.escalations:
        st.info("🟢 No pending escalations in the queue. All clear!")
        if st.session_state.is_local_mode:
            st.caption("💡 To inject a test threat locally, run: `python -m src.demo.local_runner --threat malicious`")
    else:
        for item in st.session_state.escalations:
            t_id = item["ticket_id"]
            d = item["data"]
            user = d.get("user_id", "Unknown")
            score = d.get("threat_score", "N/A")
            btn_label = f"🚨 {t_id}\nUser: {user} | Threat Score: {score}"
            st.button(
                btn_label,
                key=f"btn_{t_id}",
                use_container_width=True,
                on_click=select_ticket,
                args=(t_id, item["blob_name"], d)
            )

with col_detail:
    if not st.session_state.selected_ticket_id:
        st.info("👈 Select a pending ticket from the queue on the left to review forensic analysis and take action.")
    else:
        alert = st.session_state.alert_data
        ticket_id = st.session_state.selected_ticket_id
        target_user = alert.get("user_id", "unknown_user")

        st.subheader(f"Ticket: `{ticket_id}`")
        badge_col1, badge_col2, badge_col3 = st.columns(3)
        badge_col1.markdown(f"**Entity / User:** `{target_user}`")
        badge_col2.markdown(f"**Endpoint / Device:** `{alert.get('device_id', 'Unknown')}`")
        badge_col3.markdown(f"**Anomaly Score:** `{alert.get('threat_score', 'N/A')}`")

        st.warning(f"**ADK Agent Reason:** {alert.get('agent_reason_for_escalation', 'Suspicious activity detected.')}")

        # Local screenshot preview if available
        local_img_path = os.path.join(LOCAL_SCREENSHOTS_DIR, f"{target_user}.png")
        if os.path.exists(local_img_path):
            with st.expander("🖼️ Workstation Screenshot Evidence (Local Forensics)", expanded=True):
                st.image(local_img_path, caption=f"Desktop Screenshot for {target_user} ({local_img_path})", use_container_width=True)

        # Structured Report
        report_text = alert.get("context_for_human", "")
        url_match = re.search(r"(https://storage\.googleapis\.com/[^\s\)]+)", report_text)
        if url_match:
            found_url = url_match.group(1)
            report_text = report_text.replace(found_url, f"[🔍 Open Signed Screenshot Evidence]({found_url})")

        with st.expander("📋 Full Multi-Agent Forensic Investigation Report", expanded=True):
            st.markdown(report_text, unsafe_allow_html=True)

        st.divider()
        st.subheader("Human Analyst Adjudication")

        st.radio(
            "Verdict:",
            options=["Genuine Threat", "False Positive"],
            key="decision_choice",
            horizontal=True
        )

        st.text_area(
            "Analyst Notes & Actions Taken:",
            placeholder="Document remediation steps or reasoning for false positive dismissal...",
            key="response_comment",
            height=120
        )

        c_submit, _ = st.columns([1, 2])
        with c_submit:
            st.button(
                "Submit Resolution & Close Ticket",
                type="primary",
                use_container_width=True,
                on_click=submit_verdict,
                args=(storage_client,)
            )
