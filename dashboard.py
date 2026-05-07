"""
AI-SOC Triage Console — dashboard.py
L1 Analyst Decision-Support Dashboard

Usage:
    streamlit run dashboard.py

Upload:  output/alerts_summary.csv
Columns: incident_id, timestamp, status, source_file, risk_level,
         mitre_technique, confidence, false_positive_likelihood,
         enriched_ip, country, city, asn_org, hosting, proxy,
         vt_status, vt_malicious, vt_suspicious, vt_harmless,
         vt_undetected, vt_reputation, vt_verdict,
         analyst_insight, recommended_action
"""

import io
import os
import sys
import shutil
import subprocess
from pathlib import Path
from datetime import datetime

import streamlit as st
import pandas as pd
import streamlit.components.v1 as components
from identityguard.identity_dashboard import render_identity_guard_tab


BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / "uploaded_logs"
OUTPUT_DIR = BASE_DIR / "output"
CSV_PATH = OUTPUT_DIR / "alerts_summary.csv"
SPLUNK_RUNTIME_DIR = BASE_DIR / "runtime" / "splunk_imports"


def save_uploaded_log(uploaded_log) -> Path:
    """
    Save uploaded raw log into uploaded_logs/.
    """
    UPLOAD_DIR.mkdir(exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_name = uploaded_log.name.replace(" ", "_")
    saved_path = UPLOAD_DIR / f"{timestamp}_{safe_name}"

    with open(saved_path, "wb") as f:
        f.write(uploaded_log.getbuffer())

    return saved_path


def run_triage_from_dashboard(log_path: Path) -> tuple[bool, str]:
    """
    Run triage.py against a raw uploaded log file.
    """
    command = [
        sys.executable,
        str(BASE_DIR / "triage.py"),
        "--log",
        str(log_path),
        "--save",
        "--json",
        "--quiet",
    ]

    try:
        result = subprocess.run(
            command,
            cwd=BASE_DIR,
            capture_output=True,
            text=True,
            timeout=180,
        )

        if result.returncode == 0:
            return True, result.stdout or "AI triage completed successfully."

        return False, result.stderr or result.stdout or "AI triage failed."

    except subprocess.TimeoutExpired:
        return False, "AI triage timed out after 180 seconds."

    except Exception as e:
        return False, f"Dashboard triage execution failed: {e}"

def build_splunk_log_bundle(row: dict, row_num: int) -> str:
    """
    Convert one Splunk CSV row into a triage-ready log bundle.
    This lets the dashboard process Splunk exports without requiring the analyst
    to manually convert rows into .txt files.
    """
    def get_field(name, fallback="N/A"):
        value = row.get(name, fallback)
        if value is None:
            return fallback
        value = str(value).strip()
        return value if value else fallback

    event_id = get_field("event_id", f"SPL-{row_num:03d}")
    timestamp = get_field("_time")
    index = get_field("index")
    sourcetype = get_field("sourcetype")
    host = get_field("host")
    source = get_field("source")
    signature = get_field("signature", "Splunk Alert")
    severity = get_field("severity")
    user = get_field("user")
    src_ip = get_field("src_ip")
    dest_ip = get_field("dest_ip")
    process_name = get_field("process_name")
    command_line = get_field("command_line")
    url = get_field("url")
    file_hash = get_field("file_hash")
    action = get_field("action")
    raw = get_field("raw")

    return f"""Splunk Alert Export - AI-SOC Triage Input

Alert Metadata:
Event ID: {event_id}
Timestamp: {timestamp}
Signature: {signature}
Severity: {severity}
Action: {action}

Splunk Context:
Index: {index}
Sourcetype: {sourcetype}
Source: {source}
Host: {host}

Entities / Indicators:
User: {user}
Source IP: {src_ip}
Destination IP: {dest_ip}
Process Name: {process_name}
Command Line: {command_line}
URL: {url}
File Hash: {file_hash}

Raw Event:
{raw}

Analyst Instruction:
Review this Splunk alert export row as one security incident. Classify the risk level, map the activity to MITRE ATT&CK where possible, estimate confidence and false-positive likelihood, identify important indicators, and recommend next SOC validation steps.
"""


def save_splunk_export_as_log_bundles(uploaded_csv) -> tuple[Path, int]:
    """
    Save an uploaded Splunk alert export CSV as triage-ready .txt event bundles.
    Each CSV row becomes one temporary .txt file for batch AI triage.
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    batch_dir = SPLUNK_RUNTIME_DIR / f"splunk_export_{timestamp}"
    batch_dir.mkdir(parents=True, exist_ok=True)

    df_splunk = pd.read_csv(uploaded_csv)
    df_splunk.columns = [c.strip().lower() for c in df_splunk.columns]

    if df_splunk.empty:
        raise ValueError("The uploaded Splunk export CSV has no rows.")

    created = 0

    for idx, row in df_splunk.iterrows():
        row_num = idx + 1
        event_id = str(row.get("event_id", f"SPL-{row_num:03d}")).strip()
        safe_event_id = (
            event_id.lower()
            .replace(" ", "_")
            .replace("/", "_")
            .replace("\\", "_")
            .replace(":", "_")
        )

        output_file = batch_dir / f"splunk_alert_{row_num:03d}_{safe_event_id}.txt"
        log_bundle = build_splunk_log_bundle(row.to_dict(), row_num)

        with open(output_file, "w", encoding="utf-8") as f:
            f.write(log_bundle)

        created += 1

    return batch_dir, created


def run_batch_triage_from_dashboard(batch_dir: Path) -> tuple[bool, str]:
    """
    Run triage.py in batch mode against generated Splunk alert log bundles.
    """
    command = [
        sys.executable,
        str(BASE_DIR / "triage.py"),
        "--batch",
        str(batch_dir),
        "--save",
        "--json",
        "--quiet",
    ]

    try:
        result = subprocess.run(
            command,
            cwd=BASE_DIR,
            capture_output=True,
            text=True,
            timeout=300,
        )

        if result.returncode == 0:
            return True, result.stdout or "Splunk export triage completed successfully."

        return False, result.stderr or result.stdout or "Splunk export triage failed."

    except subprocess.TimeoutExpired:
        return False, "Splunk export triage timed out after 300 seconds."

    except Exception as e:
        return False, f"Dashboard Splunk export triage failed: {e}"
def update_incident_status_in_csv(incident_id: str, new_status: str) -> tuple[bool, str]:
    """
    Update the analyst-controlled status for a selected incident in alerts_summary.csv.
    """
    try:
        if not CSV_PATH.exists():
            return False, "alerts_summary.csv does not exist yet. Run AI triage or upload processed data first."

        df_status = pd.read_csv(CSV_PATH)
        df_status.columns = [c.strip().lower().replace(" ", "_") for c in df_status.columns]

        if "incident_id" not in df_status.columns:
            return False, "alerts_summary.csv does not contain an incident_id column."

        if "status" not in df_status.columns:
            df_status["status"] = "NEW"

        match = df_status["incident_id"].astype(str) == str(incident_id)

        if not match.any():
            return False, f"Incident {incident_id} was not found in alerts_summary.csv."

        df_status.loc[match, "status"] = new_status
        df_status.to_csv(CSV_PATH, index=False)

        return True, f"Updated {incident_id} status to {new_status}."

    except Exception as e:
        return False, f"Failed to update incident status: {e}"
    
def clear_dashboard_runtime_data() -> tuple[bool, str]:
    """
    Clear runtime dashboard/triage output files without deleting source logs or code.
    """
    deleted_count = 0

    try:
        OUTPUT_DIR.mkdir(exist_ok=True)
        UPLOAD_DIR.mkdir(exist_ok=True)
        SPLUNK_RUNTIME_DIR.mkdir(parents=True, exist_ok=True)

        # Delete generated CSV, JSON alerts, and text reports.
        for pattern in ["alerts_summary.csv", "*.json", "*.txt"]:
            for file_path in OUTPUT_DIR.glob(pattern):
                if file_path.is_file():
                    file_path.unlink()
                    deleted_count += 1

        # Delete uploaded raw logs.
        for file_path in UPLOAD_DIR.glob("*"):
            if file_path.is_file():
                file_path.unlink()
                deleted_count += 1
            elif file_path.is_dir():
                shutil.rmtree(file_path)
                deleted_count += 1

        # Delete temporary Splunk import bundles.
        runtime_root = BASE_DIR / "runtime"
        if runtime_root.exists():
            shutil.rmtree(runtime_root)
            deleted_count += 1

        return True, f"Cleared {deleted_count} runtime file(s)."

    except Exception as e:
        return False, f"Failed to clear runtime data: {e}"
# ─────────────────────────────────────────────
# PAGE CONFIG
# ─────────────────────────────────────────────

st.set_page_config(
    page_title="AI-SOC Triage Console",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ─────────────────────────────────────────────
# STYLING
# ─────────────────────────────────────────────
st.markdown("""
<style>
/* ── Global dark-mode SOC feel ── */
html, body, [data-testid="stAppViewContainer"] {
    background-color: #0d1117;
    color: #e6edf3;
}
[data-testid="stSidebar"] {
    background-color: #161b22;
    border-right: 1px solid #30363d;
}
[data-testid="stSidebar"] label,
[data-testid="stSidebar"] .stSelectbox label,
[data-testid="stSidebar"] .stTextInput label,
[data-testid="stSidebar"] .stCheckbox label {
    color: #7d8590 !important;
    font-size: 0.75rem !important;
    letter-spacing: 0.08em;
    text-transform: uppercase;
}

/* ── KPI metric cards ── */
[data-testid="metric-container"] {
    background-color: #161b22;
    border: 1px solid #30363d;
    border-radius: 6px;
    padding: 14px 18px;
}
[data-testid="metric-container"] label {
    color: #7d8590 !important;
    font-size: 0.7rem !important;
    text-transform: uppercase;
    letter-spacing: 0.1em;
}
[data-testid="metric-container"] [data-testid="stMetricValue"] {
    font-size: 1.6rem !important;
    font-family: 'Courier New', monospace !important;
}

/* ── Alert queue table ── */
.soc-table-wrapper {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 6px;
    overflow-x: auto;
    margin-top: 8px;
}
table.soc-table {
    width: 100%;
    border-collapse: collapse;
    font-family: 'Courier New', monospace;
    font-size: 0.75rem;
}
table.soc-table th {
    background: #0d1117;
    color: #7d8590;
    font-size: 0.65rem;
    letter-spacing: 0.1em;
    text-transform: uppercase;
    padding: 8px 10px;
    border-bottom: 1px solid #30363d;
    white-space: nowrap;
    text-align: left;
}
table.soc-table td {
    padding: 7px 10px;
    border-bottom: 1px solid #21262d;
    white-space: nowrap;
    color: #c9d1d9;
    vertical-align: middle;
}
table.soc-table tr:hover td { background: #1c2128; }
table.soc-table tr.selected td { background: rgba(56,139,253,0.12); }

/* ── Severity badges ── */
.badge {
    display: inline-block;
    padding: 2px 7px;
    border-radius: 4px;
    font-size: 0.65rem;
    font-weight: 600;
    letter-spacing: 0.07em;
    text-transform: uppercase;
    font-family: 'Courier New', monospace;
}
.badge-critical      { background: rgba(248,81,73,0.18);  color: #f85149; border: 1px solid rgba(248,81,73,0.3); }
.badge-high          { background: rgba(240,136,62,0.18); color: #f0883e; border: 1px solid rgba(240,136,62,0.3); }
.badge-medium        { background: rgba(210,153,34,0.18); color: #d29922; border: 1px solid rgba(210,153,34,0.3); }
.badge-low           { background: rgba(63,185,80,0.18);  color: #3fb950; border: 1px solid rgba(63,185,80,0.3); }
/* VT verdict — covers all known values incl. "Low Reputation" */
.badge-malicious         { background: rgba(248,81,73,0.15);  color: #f85149; border: 1px solid rgba(248,81,73,0.25); }
.badge-suspicious        { background: rgba(240,136,62,0.15); color: #f0883e; border: 1px solid rgba(240,136,62,0.25); }
.badge-lowreputation     { background: rgba(240,136,62,0.12); color: #f0883e; border: 1px solid rgba(240,136,62,0.2); }
.badge-clean             { background: rgba(63,185,80,0.15);  color: #3fb950; border: 1px solid rgba(63,185,80,0.25); }
.badge-harmless          { background: rgba(63,185,80,0.12);  color: #3fb950; border: 1px solid rgba(63,185,80,0.2); }
.badge-unknown           { background: rgba(125,133,144,0.15);color: #7d8590; border: 1px solid rgba(125,133,144,0.25); }
.badge-undetected        { background: rgba(125,133,144,0.12);color: #7d8590; border: 1px solid rgba(125,133,144,0.2); }
/* Status — covers OPEN, Open, Investigating, Closed, Resolved, etc. */
.badge-open              { background: rgba(56,139,253,0.15);  color: #388bfd; border: 1px solid rgba(56,139,253,0.25); }
.badge-investigating     { background: rgba(188,140,255,0.15); color: #bc8cff; border: 1px solid rgba(188,140,255,0.25); }
.badge-inprogress        { background: rgba(188,140,255,0.12); color: #bc8cff; border: 1px solid rgba(188,140,255,0.2); }
.badge-closed            { background: rgba(125,133,144,0.15); color: #7d8590; border: 1px solid rgba(125,133,144,0.25); }
.badge-resolved          { background: rgba(63,185,80,0.15);   color: #3fb950; border: 1px solid rgba(63,185,80,0.25); }
.badge-escalated         { background: rgba(248,81,73,0.15);   color: #f85149; border: 1px solid rgba(248,81,73,0.25); }
.badge-falsepositive     { background: rgba(125,133,144,0.12); color: #7d8590; border: 1px solid rgba(125,133,144,0.2); }
/* Generic fallback for any unlisted value */
.badge-default           { background: rgba(125,133,144,0.1);  color: #7d8590; border: 1px solid rgba(125,133,144,0.2); }

/* ── Detail panels ── */
.detail-panel {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 6px;
    padding: 14px 16px;
    margin-bottom: 12px;
}
.detail-panel.accent { border-color: rgba(56,139,253,0.45); }
.detail-panel.green  { border-color: rgba(63,185,80,0.4); }
.detail-panel.red    { border-color: rgba(248,81,73,0.4); }
.panel-title {
    font-family: 'Courier New', monospace;
    font-size: 0.65rem;
    letter-spacing: 0.12em;
    text-transform: uppercase;
    color: #7d8590;
    padding-bottom: 8px;
    margin-bottom: 10px;
    border-bottom: 1px solid #21262d;
}
.field-row {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    padding: 3px 0;
    gap: 8px;
}
.field-label { color: #7d8590; font-size: 0.72rem; font-family: 'Courier New', monospace; flex-shrink: 0; }
.field-value { color: #e6edf3; font-size: 0.75rem; font-family: 'Courier New', monospace; text-align: right; }

.field-value.path-wrap {
    max-width: 62%;
    white-space: normal;
    overflow-wrap: anywhere;
    word-break: break-word;
    text-align: right;
    line-height: 1.45;
}

.field-value.accent  { color: #388bfd; }
.field-value.red     { color: #f85149; }
.field-value.orange  { color: #f0883e; }
.field-value.green   { color: #3fb950; }
.field-value.purple  { color: #bc8cff; }
.field-value.muted   { color: #7d8590; }

/* ── Insight & action boxes ── */
.insight-box {
    background: #0d1117;
    border: 1px solid #30363d;
    border-radius: 4px;
    padding: 12px 14px;
    font-size: 0.82rem;
    line-height: 1.7;
    color: #c9d1d9;
    font-family: 'IBM Plex Sans', sans-serif;
}
.action-box {
    background: #0d1117;
    border: 1px solid rgba(63,185,80,0.25);
    border-radius: 4px;
    padding: 12px 14px;
}
.action-item {
    display: flex;
    align-items: flex-start;
    gap: 10px;
    margin-bottom: 6px;
    font-size: 0.78rem;
    font-family: 'Courier New', monospace;
    color: #c9d1d9;
}
.action-bullet { color: #3fb950; margin-top: 2px; flex-shrink: 0; }

/* ── Decision hint boxes ── */
.decision-escalate  { background: rgba(248,81,73,0.08); border-left: 3px solid #f85149; color: #f0a8a5; padding: 10px 14px; border-radius: 4px; font-family: 'Courier New', monospace; font-size: 0.8rem; line-height: 1.5; }
.decision-validate  { background: rgba(240,136,62,0.08); border-left: 3px solid #f0883e; color: #f0c08a; padding: 10px 14px; border-radius: 4px; font-family: 'Courier New', monospace; font-size: 0.8rem; line-height: 1.5; }
.decision-monitor   { background: rgba(210,153,34,0.08); border-left: 3px solid #d29922; color: #e0c080; padding: 10px 14px; border-radius: 4px; font-family: 'Courier New', monospace; font-size: 0.8rem; line-height: 1.5; }
.decision-internal  { background: rgba(56,139,253,0.08); border-left: 3px solid #388bfd; color: #80b0f8; padding: 10px 14px; border-radius: 4px; font-family: 'Courier New', monospace; font-size: 0.8rem; line-height: 1.5; }
.decision-review    { background: rgba(125,133,144,0.12); border-left: 3px solid #7d8590; color: #7d8590; padding: 10px 14px; border-radius: 4px; font-family: 'Courier New', monospace; font-size: 0.8rem; line-height: 1.5; }

/* ── FP likelihood bar ── */
.fp-bar-bg { background: #30363d; border-radius: 3px; height: 5px; margin-top: 3px; }
.fp-bar-fill { height: 5px; border-radius: 3px; }

/* ── Section headers ── */
.section-hdr {
    font-family: 'Courier New', monospace;
    font-size: 0.68rem;
    letter-spacing: 0.12em;
    text-transform: uppercase;
    color: #7d8590;
    margin: 16px 0 8px 0;
    display: flex;
    align-items: center;
    gap: 8px;
}
.section-hdr span { color: #388bfd; }

/* ── Divider ── */
hr.soc-divider { border-color: #30363d; margin: 16px 0; }

/* ── VT count chips ── */
.vt-chip {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 3px;
    font-size: 0.68rem;
    font-family: 'Courier New', monospace;
    margin-right: 5px;
}

/* ── Title area ── */
.console-title {
    font-family: 'Courier New', monospace;
    font-size: 1.1rem;
    font-weight: 600;
    color: #388bfd;
    letter-spacing: 0.08em;
    text-transform: uppercase;
}
.console-sub {
    font-family: 'Courier New', monospace;
    font-size: 0.72rem;
    color: #7d8590;
    letter-spacing: 0.05em;
    margin-top: 2px;
}

/* ── Streamlit overrides ── */
div[data-testid="stSelectbox"] > div,
div[data-testid="stTextInput"] > div > div > input {
    background-color: #0d1117!important;
    color: #e6edf3!important;
    border: 1px solid #30363d!important;
    border-radius: 4px!important;
    font-family: 'Courier New', monospace!important;
    font-size: 0.78rem!important;
}

div[data-testid="stFileUploader"] {
    background: #161b22;
    border: 1px dashed #30363d;
    border-radius: 6px;
    padding: 12px;
}
.stButton > button {
    background: transparent!important;
    border: 1px solid #30363d!important;
    color: #7d8590!important;
    font-family: 'Courier New', monospace!important;
    font-size: 0.72rem!important;
    border-radius: 4px!important;
}
.stButton > button:hover { border-color: #388bfd!important; color: #388bfd!important; }
</style>
""", unsafe_allow_html=True)


# ─────────────────────────────────────────────
# DEMO DATA (fallback when no CSV is uploaded)
# ─────────────────────────────────────────────
DEMO_DATA = [
    {
        "incident_id": "INC-001", "timestamp": "2025-07-12 02:14:33", "status": "Open",
        "source_file": "endpoint_edr.csv", "risk_level": "CRITICAL",
        "mitre_technique": "T1059 - Command and Scripting Interpreter",
        "confidence": 92, "false_positive_likelihood": 8,
        "enriched_ip": "185.220.101.47", "country": "Germany", "city": "Frankfurt",
        "asn_org": "AS24940 Hetzner", "hosting": True, "proxy": False,
        "vt_status": "completed", "vt_malicious": 67, "vt_suspicious": 12,
        "vt_harmless": 3, "vt_undetected": 10, "vt_reputation": -85, "vt_verdict": "Malicious",
        "analyst_insight": "High-confidence alert. PowerShell was invoked with encoded commands and contacted a known Hetzner exit node frequently used in C2 infrastructure. The script spawned cmd.exe and attempted registry modification. The IP has 67 malicious detections on VirusTotal. This pattern strongly resembles Cobalt Strike staging behavior.",
        "recommended_action": "Escalate to IR team immediately. Isolate endpoint. Capture memory dump. Block IP at perimeter firewall. Review lateral movement from this host.",
    },
    {
        "incident_id": "INC-002", "timestamp": "2025-07-12 03:28:11", "status": "Investigating",
        "source_file": "auth_logs.csv", "risk_level": "HIGH",
        "mitre_technique": "T1078 - Valid Accounts",
        "confidence": 74, "false_positive_likelihood": 35,
        "enriched_ip": "103.21.244.12", "country": "Singapore", "city": "Singapore",
        "asn_org": "AS13335 Cloudflare", "hosting": True, "proxy": True,
        "vt_status": "completed", "vt_malicious": 8, "vt_suspicious": 15,
        "vt_harmless": 40, "vt_undetected": 20, "vt_reputation": -22, "vt_verdict": "Suspicious",
        "analyst_insight": "Logon from a Cloudflare proxy IP to a privileged account outside business hours. The account has not authenticated from Singapore before. Could be VPN use by a remote employee, but the proxy flag and off-hours access increase risk. Validate with the account owner before escalating.",
        "recommended_action": "Contact account owner to verify travel or VPN usage. Check HR records. If no business justification, disable account and escalate.",
    },
    {
        "incident_id": "INC-003", "timestamp": "2025-07-12 04:01:55", "status": "Open",
        "source_file": "firewall_logs.csv", "risk_level": "HIGH",
        "mitre_technique": "T1110 - Brute Force",
        "confidence": 88, "false_positive_likelihood": 15,
        "enriched_ip": "91.108.56.200", "country": "Russia", "city": "Moscow",
        "asn_org": "AS57604 Telegram", "hosting": False, "proxy": False,
        "vt_status": "completed", "vt_malicious": 34, "vt_suspicious": 7,
        "vt_harmless": 20, "vt_undetected": 30, "vt_reputation": -55, "vt_verdict": "Malicious",
        "analyst_insight": "Rapid sequential login attempts from a Russian IP with 34 malicious VT detections. 240 failed attempts in 90 seconds targeting the VPN gateway. Classic brute force signature. No successful authentications recorded.",
        "recommended_action": "Block IP immediately at firewall. Review VPN logs for any successful login from this subnet. Enable account lockout policy if not already configured.",
    },
    {
        "incident_id": "INC-004", "timestamp": "2025-07-12 06:44:22", "status": "Open",
        "source_file": "dns_logs.csv", "risk_level": "MEDIUM",
        "mitre_technique": "T1071 - Application Layer Protocol",
        "confidence": 61, "false_positive_likelihood": 52,
        "enriched_ip": "8.8.8.8", "country": "United States", "city": "Mountain View",
        "asn_org": "AS15169 Google", "hosting": False, "proxy": False,
        "vt_status": "completed", "vt_malicious": 0, "vt_suspicious": 0,
        "vt_harmless": 80, "vt_undetected": 10, "vt_reputation": 0, "vt_verdict": "Clean",
        "analyst_insight": "DNS queries to Google's public resolver at unusual volume from a workstation. High false positive likelihood. This pattern commonly appears in developer environments using tools that bypass corporate DNS. Validate with the endpoint owner before any action.",
        "recommended_action": "Review DNS query volume against baseline. Validate with endpoint owner. If benign business use, add to allowlist and close.",
    },
    {
        "incident_id": "INC-005", "timestamp": "2025-07-12 07:12:09", "status": "Open",
        "source_file": "edr_telemetry.csv", "risk_level": "CRITICAL",
        "mitre_technique": "T1486 - Data Encrypted for Impact",
        "confidence": 97, "false_positive_likelihood": 3,
        "enriched_ip": "10.0.2.45", "country": "", "city": "",
        "asn_org": "Internal", "hosting": False, "proxy": False,
        "vt_status": "n/a", "vt_malicious": 0, "vt_suspicious": 0,
        "vt_harmless": 0, "vt_undetected": 0, "vt_reputation": 0, "vt_verdict": "Unknown",
        "analyst_insight": "File encryption activity detected across multiple directories simultaneously. The process is writing .locked extension files and deleting shadow copies via vssadmin. No external IP — this is internal host activity. This is extremely high confidence ransomware behavior. Immediate containment required.",
        "recommended_action": "IMMEDIATE: Isolate host from network. Engage IR team. Do not reboot — preserve volatile memory. Snapshot the disk. Identify patient zero and check for lateral spread.",
    },
    {
        "incident_id": "INC-006", "timestamp": "2025-07-12 08:33:40", "status": "Closed",
        "source_file": "web_logs.csv", "risk_level": "LOW",
        "mitre_technique": "T1190 - Exploit Public-Facing Application",
        "confidence": 42, "false_positive_likelihood": 78,
        "enriched_ip": "172.217.14.110", "country": "United States", "city": "Chicago",
        "asn_org": "AS15169 Google", "hosting": False, "proxy": False,
        "vt_status": "completed", "vt_malicious": 0, "vt_suspicious": 0,
        "vt_harmless": 80, "vt_undetected": 10, "vt_reputation": 0, "vt_verdict": "Clean",
        "analyst_insight": "Scanner activity detected against a public-facing web app from a Google IP. Given the clean VT reputation and Google's ASN, this is almost certainly Googlebot or a security scanner. Low confidence, high FP likelihood. Closed as false positive.",
        "recommended_action": "Confirmed false positive. No action required. Add Google IP range to scanner allowlist.",
    },
    {
        "incident_id": "INC-007", "timestamp": "2025-07-12 09:55:17", "status": "Open",
        "source_file": "endpoint_edr.csv", "risk_level": "HIGH",
        "mitre_technique": "T1003 - OS Credential Dumping",
        "confidence": 83, "false_positive_likelihood": 12,
        "enriched_ip": "45.33.32.156", "country": "United States", "city": "Fremont",
        "asn_org": "AS63949 Linode", "hosting": True, "proxy": False,
        "vt_status": "completed", "vt_malicious": 22, "vt_suspicious": 9,
        "vt_harmless": 15, "vt_undetected": 20, "vt_reputation": -41, "vt_verdict": "Malicious",
        "analyst_insight": "LSASS memory access detected by EDR. A non-standard process attempted to read LSASS — classic credential harvesting. The host made outbound connections to a Linode-hosted IP with 22 malicious VT detections post-event, suggesting exfiltration may have already occurred.",
        "recommended_action": "Escalate to IR. Isolate endpoint. Reset all credentials for accounts that logged into this host. Block outbound IP. Audit recent authentications.",
    },
    {
        "incident_id": "INC-008", "timestamp": "2025-07-12 11:20:03", "status": "Investigating",
        "source_file": "email_gateway.csv", "risk_level": "MEDIUM",
        "mitre_technique": "T1566 - Phishing",
        "confidence": 68, "false_positive_likelihood": 40,
        "enriched_ip": "192.168.1.100", "country": "", "city": "",
        "asn_org": "Internal", "hosting": False, "proxy": False,
        "vt_status": "n/a", "vt_malicious": 0, "vt_suspicious": 0,
        "vt_harmless": 0, "vt_undetected": 0, "vt_reputation": 0, "vt_verdict": "Unknown",
        "analyst_insight": "Macro-enabled document opened from an email impersonating HR. The document made DNS requests to a newly registered domain. Internal IP only — no external C2 confirmed yet. FP possible if user opened a legitimate HR attachment.",
        "recommended_action": "Sandbox the document. Interview the user. Check DNS logs for follow-up connections from this host. Review email headers for spoofing indicators.",
    },
    {
        "incident_id": "INC-009", "timestamp": "2025-07-12 12:05:44", "status": "Open",
        "source_file": "endpoint_edr.csv", "risk_level": "HIGH",
        "mitre_technique": "T1003 - OS Credential Dumping",
        "confidence": 86, "false_positive_likelihood": 10,
        "enriched_ip": "45.33.32.156", "country": "United States", "city": "Fremont",
        "asn_org": "AS63949 Linode", "hosting": True, "proxy": False,
        "vt_status": "completed", "vt_malicious": 22, "vt_suspicious": 9,
        "vt_harmless": 15, "vt_undetected": 20, "vt_reputation": -41, "vt_verdict": "Malicious",
        "analyst_insight": "Follow-up EDR alert from the same Linode-associated indicator seen in another credential dumping case. LSASS access behavior was detected again, suggesting repeated credential harvesting activity or lateral movement from the same campaign. Because this shares the same enriched IP and MITRE technique as another alert, analysts should correlate both incidents before closing.",
        "recommended_action": "Correlate with INC-007. Review process lineage, affected user accounts, and outbound connections. Isolate the endpoint if LSASS access is confirmed. Reset credentials for users active on the affected host.",
    },
]


# ─────────────────────────────────────────────
# HELPER FUNCTIONS
# ─────────────────────────────────────────────

RISK_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
ANALYST_STATUS_OPTIONS = [
    "NEW",
    "REVIEWING",
    "ESCALATED",
    "CLOSED - TRUE POSITIVE",
    "CLOSED - FALSE POSITIVE",
    "CLOSED - BENIGN",
]


def normalize_analyst_status(value):
    """
    Normalize old AI/default statuses into analyst-controlled review states.
    AI should not decide operational status, so unknown/legacy statuses become NEW.
    """
    raw = safe_str(value, "NEW").strip().upper()

    if raw in ANALYST_STATUS_OPTIONS:
        return raw

    legacy_status_map = {
        "OPEN": "NEW",
        "INVESTIGATING": "NEW",
        "IN PROGRESS": "NEW",
        "CLOSED": "NEW",
        "RESOLVED": "NEW",
    }

    return legacy_status_map.get(raw, "NEW")
def normalize_vt_verdict(value):
    """
    Normalize VirusTotal verdict values so filtering works consistently across
    demo data, Splunk-generated output, and AI-generated CSVs.
    """
    raw = safe_str(value, "Unknown").strip()

    if raw in ("", "—", "n/a", "N/A", "None"):
        return "Unknown"

    raw_upper = raw.upper()

    if raw_upper in ["MALICIOUS"]:
        return "Malicious"

    if raw_upper in ["SUSPICIOUS", "LOW REPUTATION"]:
        return "Suspicious"

    if raw_upper in ["CLEAN", "HARMLESS"]:
        return "Clean"

    if raw_upper in ["UNKNOWN", "UNDETECTED", "CLEAN / UNKNOWN", "CLEAN/UNKNOWN"]:
        return "Unknown"

    return raw.title()
def safe_str(val, fallback="—"):
    if val is None or (isinstance(val, float) and pd.isna(val)):
        return fallback
    return str(val).strip() or fallback

def safe_int(val, fallback=0):
    try:
        return int(val)
    except (TypeError, ValueError):
        return fallback

def safe_float(val, fallback=0.0):
    try:
        return float(val)
    except (TypeError, ValueError):
        return fallback

def badge_slug(val):
    """Convert any raw value to a CSS badge class slug.
    Strips spaces, lowercases, so 'Low Reputation' → 'lowreputation',
    'OPEN' → 'open', 'In Progress' → 'inprogress', etc.
    Falls back to 'default' for anything unrecognised.
    """
    if not val or str(val).strip() in ("", "—"):
        return "default"
    return str(val).strip().lower().replace(" ", "").replace("_", "").replace("-", "")

def risk_badge(risk):
    slug = badge_slug(risk)
    label = str(risk).strip() if risk and str(risk).strip() not in ("", "—") else "—"
    return f'<span class="badge badge-{slug}">{label}</span>'

def vt_badge(verdict):
    slug = badge_slug(verdict)
    label = str(verdict).strip() if verdict and str(verdict).strip() not in ("", "—") else "—"
    return f'<span class="badge badge-{slug}">{label}</span>'

def status_badge(status):
    slug = badge_slug(status)
    label = str(status).strip() if status and str(status).strip() not in ("", "—") else "—"
    return f'<span class="badge badge-{slug}">{label}</span>'

def fp_bar_html(pct):
    pct = safe_float(pct)
    color = "#3fb950" if pct >= 60 else "#d29922" if pct >= 35 else "#f85149"
    return (
        f'<div style="font-family:\'Courier New\',monospace;font-size:0.72rem;color:{color}">{pct:.0f}%</div>'
        f'<div class="fp-bar-bg"><div class="fp-bar-fill" style="width:{min(pct,100):.0f}%;background:{color}"></div></div>'
    )

def is_internal_ip(ip):
    ip = str(ip or "")
    return (
        ip.startswith("10.") or
        ip.startswith("192.168.") or
        ip.startswith("172.1") or
        ip.startswith("172.2") or
        ip.startswith("172.3") or
        ip.lower() in ("internal", "n/a", "", "—") or
        not ip
    )

def triage_decision(row):
    risk = safe_str(row.get("risk_level", ""), "").upper()
    vt   = safe_str(row.get("vt_verdict", ""), "").lower()
    fp   = safe_float(row.get("false_positive_likelihood", 0))
    ip   = safe_str(row.get("enriched_ip", ""), "")

    if (risk in ("CRITICAL", "HIGH")) and (vt == "malicious"):
        return ("decision-escalate", "[!] Escalate immediately — High/Critical risk with Malicious VT verdict confirmed.")
    if risk == "CRITICAL" and fp < 10:
        return ("decision-escalate", "[!] Escalate immediately — Critical severity with very low false positive likelihood.")
    if risk == "HIGH" and vt in ("suspicious", "low reputation"):
        return ("decision-validate", "[?] Validate with endpoint/proxy logs before escalation — suspicious but not confirmed malicious.")
    if fp > 50:
        return ("decision-review", "[~] Review business context first — false positive likelihood exceeds 50%. Avoid premature escalation.")
    if is_internal_ip(ip):
        return ("decision-internal", "[i] Internal-only event — no public IP. Validate with host authentication and application logs.")
    return ("decision-monitor", "[●] Monitor and gather more context — does not meet immediate escalation threshold.")

def action_items_html(text):
    if not text or str(text).strip() in ("", "—"):
        return "<em style='color:#7d8590'>No recommended action recorded.</em>"
    import re
    # Split on sentence boundaries or numbered lists
    parts = re.split(r'(?<=[.!?])\s+(?=[A-Z\[\(])', str(text).strip())
    parts = [p.strip() for p in parts if p.strip()]
    items = "".join(
        f'<div class="action-item"><span class="action-bullet">▸</span><span>{p}</span></div>'
        for p in parts
    )
    return f'<div class="action-box">{items}</div>'

IDENTITY_PIVOT_KEYWORDS = [
    "mfa",
    "mfa_fatigue",
    "impossible travel",
    "oauth",
    "mailbox",
    "forwarding",
    "account takeover",
    "suspicious sign-in",
    "sign-in",
    "login",
    "new device",
    "unmanaged device",
    "password reset",
    "privileged",
    "admin",
    "valid accounts",
    "t1078",
    "t1621",
    "t1098",
    "t1114",
    "t1550.001",
]

def has_identity_pivot_signal(row) -> bool:
    fields = [
        "incident_id",
        "mitre_technique",
        "ai_summary",
        "analyst_insight",
        "recommended_action",
        "source_file",
        "raw",
        "context",
        "description",
        "alert",
        "message",
    ]
    text = " ".join(safe_str(row.get(field), "") for field in fields).lower()
    return any(keyword in text for keyword in IDENTITY_PIVOT_KEYWORDS)

def build_splunk_searches(row) -> dict:
    """
    Build suggested Splunk SPL validation searches for the selected alert.
    These searches prioritize raw indicator matching because field names vary
    across Splunk environments.
    """
    import re

    def valid_value(value):
        value = safe_str(value, "")
        invalid_values = {"", "—", "n/a", "N/A", "None", "Unknown", "Internal"}
        return value not in invalid_values

    searches = {}

    enriched_ip = safe_str(row.get("enriched_ip"), "")
    source_file = safe_str(row.get("source_file"), "")
    mitre = safe_str(row.get("mitre_technique"), "")
    incident_id = safe_str(row.get("incident_id"), "")

    # Extract MITRE ID if present, such as T1059 or T1110.001
    mitre_match = re.search(r"T\d{4}(?:\.\d{3})?", mitre)
    mitre_id = mitre_match.group(0) if mitre_match else ""

    # Clean behavior text from MITRE string
    behavior_text = mitre
    if mitre_id:
        behavior_text = mitre.replace(mitre_id, "").replace("-", " ").replace("—", " ").strip()

    # 1. Broad raw indicator search
    if valid_value(enriched_ip):
        searches["Broad Indicator Search"] = (
            f'index=* "{enriched_ip}" earliest=-24h latest=now'
        )
    elif valid_value(source_file):
        searches["Broad Source Search"] = (
            f'index=* "{source_file}" earliest=-24h latest=now'
        )
    elif valid_value(mitre_id):
        searches["Broad MITRE Search"] = (
            f'index=* "{mitre_id}" earliest=-24h latest=now'
        )

    # 2. Correlation search using available values
    correlation_terms = []

    for value in [enriched_ip, mitre_id, behavior_text, source_file, incident_id]:
        if valid_value(value):
            correlation_terms.append(f'"{value}"')

    if correlation_terms:
        searches["Broad Correlation Search"] = (
            f'index=* ({" OR ".join(correlation_terms)}) earliest=-24h latest=now'
        )

    # 3. Optional field-based IP template
    # This is intentionally labeled as optional because Splunk field names vary.
    if valid_value(enriched_ip):
        searches["Optional Field-Based IP Template"] = (
            f'index=* (src_ip="{enriched_ip}" OR dest_ip="{enriched_ip}" OR '
            f'src="{enriched_ip}" OR dest="{enriched_ip}" OR '
            f'clientip="{enriched_ip}" OR ip="{enriched_ip}") '
            f'earliest=-24h latest=now'
        )

    # 4. Behavior / MITRE validation search
    behavior_terms = []

    if valid_value(mitre_id):
        behavior_terms.append(f'"{mitre_id}"')

    if valid_value(behavior_text):
        behavior_terms.append(f'"{behavior_text}"')

    # Add common behavior pivots based on the MITRE text
    lower_mitre = mitre.lower()

    if "powershell" in lower_mitre or "command" in lower_mitre or "scripting" in lower_mitre:
        behavior_terms.extend(['"powershell"', '"cmd.exe"', '"encodedcommand"'])

    if "brute" in lower_mitre or "password" in lower_mitre:
        behavior_terms.extend(['"failed"', '"invalid password"', '"authentication failure"'])

    if "valid accounts" in lower_mitre or "account" in lower_mitre:
        behavior_terms.extend(['"successful login"', '"new session"', '"privileged account"'])

    if "exfiltration" in lower_mitre or "transfer" in lower_mitre:
        behavior_terms.extend(['"bytes_out"', '"data transfer"', '"upload"', '"large outbound"'])

    if "credential" in lower_mitre or "dumping" in lower_mitre:
        behavior_terms.extend(['"lsass"', '"credential"', '"mimikatz"', '"dump"'])

    # Remove duplicates while preserving order
    behavior_terms = list(dict.fromkeys(behavior_terms))

    if behavior_terms:
        searches["Behavior / MITRE Validation Search"] = (
            f'index=* ({" OR ".join(behavior_terms)}) earliest=-7d latest=now'
        )

    return searches
def load_csv(file_obj):
    """Load CSV from a file-like object and normalize column names."""
    df = pd.read_csv(file_obj)
    df.columns = [c.strip().lower().replace(" ", "_") for c in df.columns]

    # Fill common text columns
    for col in [
        "status",
        "risk_level",
        "vt_verdict",
        "analyst_insight",
        "recommended_action",
        "enriched_ip",
        "country",
        "city",
        "asn_org",
        "mitre_technique",
        "source_file",
    ]:
        if col in df.columns:
            df[col] = df[col].fillna("").astype(str)

    # Normalize numeric columns
    for col in [
        "false_positive_likelihood",
        "vt_malicious",
        "vt_suspicious",
        "vt_harmless",
        "vt_undetected",
        "vt_reputation",
    ]:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0)

    # Normalize boolean enrichment fields
    for col in ["hosting", "proxy"]:
        if col in df.columns:
            df[col] = df[col].map(
                lambda x: str(x).strip().lower() in ("true", "1", "yes", "t")
            )

    # Analyst-controlled status normalization
    if "status" not in df.columns:
        df["status"] = "NEW"

    df["status"] = df["status"].apply(normalize_analyst_status)

    # VirusTotal verdict normalization
    if "vt_verdict" not in df.columns:
        df["vt_verdict"] = "Unknown"

    df["vt_verdict"] = df["vt_verdict"].apply(normalize_vt_verdict)

    return df

# ─────────────────────────────────────────────
# MAIN APP
# ─────────────────────────────────────────────

# ── Title ──
col_t1, col_t2 = st.columns([3, 1])
with col_t1:
    st.markdown("""
        <div class="console-title">⬡ AI-SOC Triage Console</div>
        <div class="console-sub">L1 Analyst Decision-Support Dashboard &bull; alerts_summary.csv</div>
    """, unsafe_allow_html=True)

st.markdown("<hr class='soc-divider'>", unsafe_allow_html=True)

# ── Tabs are created early so each workflow owns its controls ──
st.info(
    "Workflow: Use SOC Triage for broad alert intake. "
    "Use IdentityGuard AI when the alert involves account takeover, MFA, OAuth, mailbox, device, or privileged-access risk."
)
with st.expander("Data Intake Guide", expanded=False):
    st.markdown("""
    - **SOC Triage:** Upload general alerts, Splunk exports, single log bundles, or `alerts_summary.csv`.
    - **IdentityGuard AI:** Upload structured identity telemetry for account-takeover review.
    - **Production note:** SOAR could route identity alerts automatically; this prototype supports manual CSV/JSON upload.
    """)

tab_soc, tab_ig = st.tabs(["  SOC Triage  ", "  IdentityGuard AI  "])

with tab_ig:
    render_identity_guard_tab()

# ── Minimal global sidebar ──
with st.sidebar:
    st.markdown(
        "<div style='color:#388bfd;font-family:Courier New,monospace;font-size:0.8rem;letter-spacing:0.1em;text-transform:uppercase;margin-bottom:12px'>⬡ SOC Console</div>",
        unsafe_allow_html=True,
    )
    st.caption(
        "Global console controls. SOC and IdentityGuard workflows now live inside their own tabs."
    )

    st.markdown("---")

    st.markdown(
        "<div style='font-family:Courier New,monospace;font-size:0.68rem;color:#7d8590;letter-spacing:0.08em;text-transform:uppercase'>Dashboard Data Controls</div>",
        unsafe_allow_html=True,
    )

    confirm_clear = st.checkbox("Confirm clear runtime data")

    if st.button("🧹 Clear Runtime Dashboard Data", use_container_width=True):
        if not confirm_clear:
            st.warning("Check the confirmation box first.")
        else:
            success, message = clear_dashboard_runtime_data()
            if success:
                st.success(message)
                st.cache_data.clear()
                st.rerun()
            else:
                st.error(message)

# ── SOC intake controls — rendered before data loading so uploads are available ──
with tab_soc:
    st.markdown('<div class="section-hdr">SOC Intake</div>', unsafe_allow_html=True)
    intake_col1, intake_col2, intake_col3 = st.columns(3)

    with intake_col1:
        st.markdown(
            "<div style='font-family:Courier New,monospace;font-size:0.68rem;color:#7d8590;letter-spacing:0.08em;text-transform:uppercase'>Processed Alerts</div>",
            unsafe_allow_html=True,
        )
        uploaded = st.file_uploader(
            "Upload processed alerts_summary.csv",
            type=["csv"],
            key="soc_processed_alerts_upload",
        )

        alerts_summary_template = (
            "incident_id,timestamp,status,source_file,risk_level,mitre_technique,"
            "confidence,false_positive_likelihood,enriched_ip,country,city,asn_org,"
            "hosting,proxy,vt_status,vt_malicious,vt_suspicious,vt_harmless,"
            "vt_undetected,vt_reputation,vt_verdict,analyst_insight,recommended_action\n"
            "INC-001,2025-07-12 02:14:33,NEW,endpoint_edr.csv,CRITICAL,"
            "T1059 - Command and Scripting Interpreter,92,8,185.220.101.47,"
            "Germany,Frankfurt,AS24940 Hetzner,True,False,completed,67,12,3,10,"
            "-85,Malicious,"
            "\"Brief analyst assessment goes here.\","
            "\"Recommended analyst action goes here.\"\n"
        )

        st.download_button(
            "Download alerts_summary.csv Template",
            data=alerts_summary_template.encode("utf-8"),
            file_name="alerts_summary_template.csv",
            mime="text/csv",
            use_container_width=True,
            key="soc_alerts_summary_template",
        )

        st.caption(
            "Use this template for processed SOC dashboard alerts. "
            "For identity-event telemetry, use the IdentityGuard CSV/JSON templates."
        )

    with intake_col2:
        st.markdown(
            "<div style='font-family:Courier New,monospace;font-size:0.68rem;color:#7d8590;letter-spacing:0.08em;text-transform:uppercase'>Single Incident</div>",
            unsafe_allow_html=True,
        )
        uploaded_log = st.file_uploader(
            "Upload single-incident log (.txt)",
            type=["txt"],
            key="soc_raw_log_upload",
        )
        run_triage_button = st.button(
            "🚀 Run AI Triage",
            use_container_width=True,
            key="soc_run_ai_triage",
        )

        if run_triage_button:
            if uploaded_log is None:
                st.error("Upload a .txt log before running triage.")
            else:
                saved_log_path = save_uploaded_log(uploaded_log)

                with st.spinner("Running AI triage on uploaded log..."):
                    success, message = run_triage_from_dashboard(saved_log_path)

                if success:
                    st.success("Triage complete. Dashboard data updated.")
                    st.cache_data.clear()
                    st.rerun()
                else:
                    st.error("Triage failed.")
                    st.code(message)

    with intake_col3:
        st.markdown(
            "<div style='font-family:Courier New,monospace;font-size:0.68rem;color:#7d8590;letter-spacing:0.08em;text-transform:uppercase'>Splunk Alert Export</div>",
            unsafe_allow_html=True,
        )
        uploaded_splunk_csv = st.file_uploader(
            "Upload Splunk alert export (.csv)",
            type=["csv"],
            key="soc_splunk_export_upload",
        )
        run_splunk_button = st.button(
            "⚡ Run Splunk Export Triage",
            use_container_width=True,
            key="soc_run_splunk_triage",
        )

        if run_splunk_button:
            if uploaded_splunk_csv is None:
                st.error("Upload a Splunk alert export CSV before running triage.")
            else:
                try:
                    with st.spinner("Preparing Splunk export rows for AI triage..."):
                        splunk_batch_dir, splunk_event_count = save_splunk_export_as_log_bundles(uploaded_splunk_csv)

                    with st.spinner(f"Running AI triage on {splunk_event_count} Splunk alert row(s)..."):
                        success, message = run_batch_triage_from_dashboard(splunk_batch_dir)

                    if success:
                        st.success(f"Splunk export triage complete. Processed {splunk_event_count} alert row(s).")
                        st.cache_data.clear()
                        st.rerun()
                    else:
                        st.error("Splunk export triage failed.")
                        st.code(message)

                except Exception as e:
                    st.error(f"Splunk export processing failed: {e}")

    st.markdown("<hr class='soc-divider'>", unsafe_allow_html=True)
# ── Load data (must happen before filter widgets so options reflect real values) ──
if uploaded is not None:
    df = load_csv(uploaded)

    required_dashboard_cols = {"incident_id", "risk_level", "mitre_technique"}

    if not required_dashboard_cols.issubset(set(df.columns)):
        with tab_soc:
            st.error(
                "This CSV does not look like a processed AI-SOC alerts_summary.csv. "
                "If this is a Splunk alert export, use the 'Splunk Alert Export' uploader in SOC Intake instead."
            )
        st.stop()

    using_demo = False

else:
    default_path = CSV_PATH

    if default_path.exists():
        df = load_csv(default_path)
        using_demo = False
        with tab_soc:
            st.info(f"Loaded from {default_path}", icon="📂")

    else:
        df = pd.DataFrame(DEMO_DATA)

        # Normalize demo VT values, but intentionally showcase analyst workflow statuses.
        df["vt_verdict"] = df["vt_verdict"].apply(normalize_vt_verdict)

        demo_status_showcase = [
            "NEW",
            "ESCALATED",
            "REVIEWING",
            "NEW",
            "CLOSED - TRUE POSITIVE",
            "CLOSED - FALSE POSITIVE",
            "CLOSED - BENIGN",
            "REVIEWING",
            "ESCALATED",
        ]

        df["status"] = demo_status_showcase[:len(df)]

        using_demo = True
        with tab_soc:
            st.info(
                "No real alerts_summary.csv found — showing built-in demo data for preview only. "
                "Upload a CSV or run AI triage on a .txt log to generate real dashboard data.",
                icon="ℹ️",
            )
# ── Build dynamic filter option lists from the loaded data ──
def _sorted_opts(series, preferred_order=None):
    """Return ['All'] + unique non-blank values, with preferred_order first if supplied."""
    vals = sorted(series.dropna().astype(str).str.strip().unique().tolist())
    vals = [v for v in vals if v not in ("", "—", "nan")]
    if preferred_order:
        head = [v for v in preferred_order if v in vals]
        tail = [v for v in vals if v not in preferred_order]
        vals = head + tail
    return ["All"] + vals

risk_order_pref = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

status_opts_dyn = ["All"] + ANALYST_STATUS_OPTIONS

vt_order_pref = ["Malicious", "Suspicious", "Clean", "Unknown"]

if "vt_verdict" in df.columns:
    df["vt_verdict"] = df["vt_verdict"].apply(normalize_vt_verdict)
else:
    df["vt_verdict"] = "Unknown"

vt_opts_dyn = ["All"] + vt_order_pref

risk_opts_dyn = _sorted_opts(df["risk_level"], preferred_order=risk_order_pref) \
                if "risk_level" in df.columns else ["All"] + risk_order_pref
# ── SOC filter widgets ──
with tab_soc:
    st.markdown('<div class="section-hdr">SOC Filters</div>', unsafe_allow_html=True)
    
    def format_risk_label(risk):
        colors = {
            "CRITICAL": "🔴 CRITICAL",
            "HIGH": "🟠 HIGH",
            "MEDIUM": "🟡 MEDIUM",
            "LOW": "🟢 LOW",
            "All": "All"
        }
        return colors.get(risk, risk)

    formatted_risk_opts = [format_risk_label(r) for r in risk_opts_dyn]

    f1, f2, f3, f4, f5 = st.columns([2, 1, 1, 1, 1])
    with f1:
        search_q = st.text_input(
            "Search",
            placeholder="ID / IP / technique / file",
            key="soc_search",
            label_visibility="visible",
        )
    with f2:
        selected_risk_label = st.selectbox(
            "SOC Risk Level",
            formatted_risk_opts,
            key="soc_risk_filter",
        )

    # Map back to original value
    sel_risk = risk_opts_dyn[formatted_risk_opts.index(selected_risk_label)]
    with f3:
        sel_status = st.selectbox("SOC Status", status_opts_dyn, key="soc_status_filter")
    with f4:
        sel_vt = st.selectbox("SOC VT Verdict", vt_opts_dyn, key="soc_vt_filter")
    with f5:
        st.markdown("<br>", unsafe_allow_html=True)
        highcrit_only = st.checkbox("High / Critical only", key="soc_highcrit_only")

    st.markdown("<hr class='soc-divider'>", unsafe_allow_html=True)

# ── Apply filters ──
dff = df.copy()

if highcrit_only:
    dff = dff[dff["risk_level"].str.upper().isin(["CRITICAL", "HIGH"])]
if sel_risk != "All":
    dff = dff[dff["risk_level"].str.strip().str.upper() == sel_risk.strip().upper()]
if sel_status != "All":
    dff = dff[dff["status"].str.strip().str.upper() == sel_status.strip().upper()]
if sel_vt != "All":
    dff = dff[
        dff["vt_verdict"].apply(normalize_vt_verdict).str.upper()
        == normalize_vt_verdict(sel_vt).upper()
    ]
if search_q.strip():
    q = search_q.strip().lower()
    mask = (
        dff.get("incident_id",    pd.Series(dtype=str)).str.lower().str.contains(q, na=False) |
        dff.get("enriched_ip",    pd.Series(dtype=str)).str.lower().str.contains(q, na=False) |
        dff.get("mitre_technique",pd.Series(dtype=str)).str.lower().str.contains(q, na=False) |
        dff.get("source_file",    pd.Series(dtype=str)).str.lower().str.contains(q, na=False)
    )
    dff = dff[mask]

# Sort by risk then timestamp
dff["_risk_ord"] = dff["risk_level"].str.strip().str.upper().map(RISK_ORDER).fillna(99)
dff = dff.sort_values(["_risk_ord", "timestamp"], ascending=[True, True])
dff = dff.drop(columns=["_risk_ord"])

with tab_soc:
    # ─────────────────────────────────────────────
    # KPI STRIP
    # ─────────────────────────────────────────────
    total_alerts   = len(dff)
    highcrit_count = len(dff[dff["risk_level"].str.strip().str.upper().isin(["CRITICAL", "HIGH"])])
    avg_fp         = dff["false_positive_likelihood"].mean() if not dff.empty else 0
    escalate_count = len(dff[
        dff["risk_level"].str.upper().isin(["CRITICAL", "HIGH"]) &
        dff["vt_verdict"].str.strip().str.lower().isin(["malicious", "suspicious", "low reputation"])
    ])
    unique_ips = dff["enriched_ip"].nunique()
    
    k1, k2, k3, k4, k5 = st.columns(5)
    k1.metric("Total Alerts",         total_alerts)
    k2.metric("High / Critical",      highcrit_count)
    k3.metric("Avg FP Likelihood",    f"{avg_fp:.0f}%")
    k4.metric("Needs Escalation",     escalate_count)
    k5.metric("Unique IPs",           unique_ips)
    
    st.markdown("<br>", unsafe_allow_html=True)
    
    st.markdown(
        """
        <div class="detail-panel">
          <div class="panel-title">Export Current View</div>
          <div style="font-size:0.78rem;color:#7d8590;margin-bottom:10px">
            Download the currently filtered dashboard results as a CSV for reporting, ticket attachment, or analyst handoff.
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    
    export_csv = dff.to_csv(index=False).encode("utf-8")
    export_filename = f"ai_soc_triage_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    
    st.download_button(
        label="⬇️ Export Current Dashboard View",
        data=export_csv,
        file_name=export_filename,
        mime="text/csv",
        use_container_width=True,
    )
    
    st.markdown("<hr class='soc-divider'>", unsafe_allow_html=True)
    
    
    # ─────────────────────────────────────────────
    # ALERT QUEUE
    # ─────────────────────────────────────────────
    st.markdown(
        f'<div class="section-hdr">Alert Queue <span>{len(dff)} alerts</span></div>',
        unsafe_allow_html=True
    )
    
    if dff.empty:
        st.warning("No alerts match the current filters.")
    else:
        queue_cols = [
            "incident_id",
            "timestamp",
            "status",
            "risk_level",
            "mitre_technique",
            "confidence",
            "false_positive_likelihood",
            "enriched_ip",
            "vt_verdict",
            "vt_malicious",
            "source_file",
        ]
    
        available_cols = [col for col in queue_cols if col in dff.columns]
    
        queue_df = dff[available_cols].copy()
    
        def color_risk(val):
            if val == "CRITICAL":
                return "color: #ff4d4d; font-weight: bold"
            elif val == "HIGH":
                return "color: #ff9933; font-weight: bold"
            elif val == "MEDIUM":
                return "color: #ffd633"
            elif val == "LOW":
                return "color: #33cc33"
            return ""
        def color_status(val):
            val = str(val).strip().upper()
    
            if val == "ESCALATED":
                return "color: #ff4d4d; font-weight: bold"
            elif val == "REVIEWING":
                return "color: #bc8cff; font-weight: bold"
            elif val == "NEW":
                return "color: #c9d1d9; font-weight: bold"
            elif val == "CLOSED - TRUE POSITIVE":
                return "color: #33cc33; font-weight: bold"
            elif val in ["CLOSED - FALSE POSITIVE", "CLOSED - BENIGN"]:
                return "color: #8b949e; font-weight: bold"
    
            return ""
    
        styled_df = (
        queue_df.style
        .map(color_risk, subset=["risk_level"])
        .map(color_status, subset=["status"])
        )
    
        st.dataframe(
        styled_df,
        use_container_width=True,
        hide_index=True,
        height=360,
        column_config={
            "status": st.column_config.TextColumn(
                "analyst_status",
                width="medium",
            ),
            "mitre_technique": st.column_config.TextColumn(
                "mitre_technique",
                width="large",
            ),
            "source_file": st.column_config.TextColumn(
                "source_file",
                width="medium",
            ),
        },
    )
    
    st.markdown("<hr class='soc-divider'>", unsafe_allow_html=True)
    
    
    # ─────────────────────────────────────────────
    # INCIDENT SELECTOR
    # ─────────────────────────────────────────────
    st.markdown('<div class="section-hdr">Incident Detail</div>', unsafe_allow_html=True)
    
    if dff.empty:
        st.info("No alerts to display. Adjust filters.")
        st.stop()
    
    incident_ids = dff["incident_id"].tolist()
    
    # Pre-select first CRITICAL/HIGH if available
    default_idx = 0
    for i, row in dff.iterrows():
        if str(row.get("risk_level", "")).strip().upper() in ("CRITICAL", "HIGH"):
            default_idx = incident_ids.index(row["incident_id"])
            break
    
    def format_incident_option(incident_id):
        row = dff[dff["incident_id"] == incident_id].iloc[0]
    
        risk = safe_str(row.get("risk_level"))
        status = safe_str(row.get("status"))
        mitre = safe_str(row.get("mitre_technique"))
    
        return f"{incident_id}  ·  {status}  ·  {risk}  ·  {mitre}"
    
    
    selected_id = st.selectbox(
        "Select Incident",
        options=incident_ids,
        index=default_idx,
        format_func=format_incident_option,
        label_visibility="collapsed",
    )
    
    sel_row = dff[dff["incident_id"] == selected_id].iloc[0].to_dict()
    
    
    # ─────────────────────────────────────────────
    # INCIDENT OVERVIEW + THREAT INTEL (2-col)
    # ─────────────────────────────────────────────
    col_left, col_right = st.columns(2)
    
    with col_left:
        fp_val    = safe_float(sel_row.get("false_positive_likelihood", 0))
        fp_color  = "#3fb950" if fp_val >= 60 else "#d29922" if fp_val >= 35 else "#f85149"
        risk_val  = safe_str(sel_row.get("risk_level"))
        conf_val = safe_str(sel_row.get("confidence", "N/A"))
    
        st.markdown(f"""
        <div class="detail-panel accent">
          <div class="panel-title">Incident Overview</div>
          <div class="field-row"><span class="field-label">Incident ID</span><span class="field-value accent">{safe_str(sel_row.get("incident_id"))}</span></div>
          <div class="field-row"><span class="field-label">Timestamp</span><span class="field-value">{safe_str(sel_row.get("timestamp"))}</span></div>
          <div class="field-row"><span class="field-label">Status</span><span class="field-value">{status_badge(safe_str(sel_row.get("status")))}</span></div>
          <div class="field-row"><span class="field-label">Risk Level</span><span class="field-value">{risk_badge(risk_val)}</span></div>
          <div class="field-row"><span class="field-label">Source File</span><span class="field-value muted path-wrap">{safe_str(sel_row.get("source_file"))}</span></div>
          <div class="field-row"><span class="field-label">MITRE</span><span class="field-value" style="font-size:0.7rem">{safe_str(sel_row.get("mitre_technique"))}</span></div>
          <div class="field-row"><span class="field-label">Confidence</span><span class="field-value">{conf_val}</span></div>
          <div class="field-row">
            <span class="field-label">FP Likelihood</span>
            <span class="field-value" style="color:{fp_color}">{fp_val:.0f}%</span>
          </div>
        </div>
        """, unsafe_allow_html=True)
    
    with col_right:
        ip      = safe_str(sel_row.get("enriched_ip"))
        country = safe_str(sel_row.get("country"))
        city    = safe_str(sel_row.get("city"))
        asn     = safe_str(sel_row.get("asn_org"))
        hosting = sel_row.get("hosting", False)
        proxy   = sel_row.get("proxy", False)
        vt_rep  = safe_int(sel_row.get("vt_reputation", 0))
        vt_mal  = safe_int(sel_row.get("vt_malicious", 0))
        vt_sus  = safe_int(sel_row.get("vt_suspicious", 0))
        vt_har  = safe_int(sel_row.get("vt_harmless", 0))
        vt_undet= safe_int(sel_row.get("vt_undetected", 0))
        vt_verd = safe_str(sel_row.get("vt_verdict"))
    
        ip_is_internal = is_internal_ip(ip)
        ip_color   = "#bc8cff" if ip_is_internal else "#388bfd"
        ip_display = f"Internal / {ip}" if ip_is_internal else ip
        rep_color  = "#f85149" if vt_rep < 0 else "#3fb950"
        host_color = "#f0883e" if hosting else "#3fb950"
        proxy_color= "#f0883e" if proxy else "#3fb950"
        mal_color  = "#f85149" if vt_mal > 0 else "#7d8590"
        sus_color  = "#f0883e" if vt_sus > 0 else "#7d8590"
    
        st.markdown(f"""
        <div class="detail-panel">
          <div class="panel-title">Threat Intelligence</div>
          <div class="field-row"><span class="field-label">Enriched IP</span><span class="field-value" style="color:{ip_color}">{ip_display}</span></div>
          <div class="field-row"><span class="field-label">Country</span><span class="field-value">{country}</span></div>
          <div class="field-row"><span class="field-label">City</span><span class="field-value">{city}</span></div>
          <div class="field-row"><span class="field-label">ASN / Org</span><span class="field-value muted">{asn}</span></div>
          <div class="field-row"><span class="field-label">Hosting</span><span class="field-value" style="color:{host_color}">{'Yes' if hosting else 'No'}</span></div>
          <div class="field-row"><span class="field-label">Proxy</span><span class="field-value" style="color:{proxy_color}">{'Yes' if proxy else 'No'}</span></div>
          <div style="border-top:1px solid #21262d;margin:8px 0"></div>
          <div class="field-row"><span class="field-label">VT Verdict</span><span class="field-value">{vt_badge(vt_verd)}</span></div>
          <div class="field-row"><span class="field-label">VT Reputation</span><span class="field-value" style="color:{rep_color}">{vt_rep:+d}</span></div>
          <div class="field-row"><span class="field-label">VT Malicious</span><span class="field-value" style="color:{mal_color}">{vt_mal}</span></div>
          <div class="field-row"><span class="field-label">VT Suspicious</span><span class="field-value" style="color:{sus_color}">{vt_sus}</span></div>
          <div class="field-row"><span class="field-label">VT Harmless</span><span class="field-value green">{vt_har}</span></div>
          <div class="field-row"><span class="field-label">VT Undetected</span><span class="field-value muted">{vt_undet}</span></div>
        </div>
        """, unsafe_allow_html=True)
    
    # ─────────────────────────────────────────────
    # ANALYST STATUS UPDATE
    # ─────────────────────────────────────────────
    st.markdown('<div class="section-hdr">Analyst Status Update</div>', unsafe_allow_html=True)
    
    analyst_status_options = ANALYST_STATUS_OPTIONS
    
    current_status = safe_str(sel_row.get("status", "NEW")).upper()
    
    if current_status not in analyst_status_options:
        current_status = "NEW"
    
    status_col1, status_col2 = st.columns([2, 1])
    
    with status_col1:
        selected_status_update = st.selectbox(
            "Set Analyst Status",
            options=analyst_status_options,
            index=analyst_status_options.index(current_status),
            label_visibility="visible",
        )
    
    with status_col2:
        st.markdown("<br>", unsafe_allow_html=True)
    
        if st.button("💾 Save Status", use_container_width=True):
            if using_demo:
                st.warning("Status updates are disabled while viewing demo data. Run triage or load a real alerts_summary.csv first.")
            else:
                success, message = update_incident_status_in_csv(
                    incident_id=safe_str(sel_row.get("incident_id")),
                    new_status=selected_status_update,
                )
    
                if success:
                    st.success(message)
                    st.cache_data.clear()
                    st.rerun()
                else:
                    st.error(message)
    
    st.caption(
        "Status is analyst-controlled. AI generates risk and recommendations, but the analyst sets the operational review state."
    )
    
    st.markdown("<hr class='soc-divider'>", unsafe_allow_html=True)
    # ─────────────────────────────────────────────
    # TRIAGE DECISION SUPPORT
    # ─────────────────────────────────────────────
    st.markdown('<div class="section-hdr">Triage Decision Support</div>', unsafe_allow_html=True)
    dec_cls, dec_text = triage_decision(sel_row)
    st.markdown(f'<div class="{dec_cls}">{dec_text}</div>', unsafe_allow_html=True)
    if has_identity_pivot_signal(sel_row):
        st.info(
            "Identity Pivot Recommended: This alert contains identity-risk indicators. "
            "Review the IdentityGuard AI tab for deeper account-takeover or access-abuse triage."
        )
    with st.expander("Identity Pivot", expanded=False):
        st.info(
            "If this alert involves account takeover, MFA abuse, OAuth consent, mailbox forwarding, "
            "impossible travel, or privileged login activity, review the IdentityGuard AI tab for "
            "deeper identity-risk triage."
        )
    st.markdown("<br>", unsafe_allow_html=True)
    
    
    # ─────────────────────────────────────────────
    # AI ANALYST INSIGHT
    # ─────────────────────────────────────────────
    insight = safe_str(sel_row.get("analyst_insight", ""), "No analyst insight available.")
    
    st.markdown(f"""
    <div class="detail-panel accent">
      <div class="panel-title">AI Analyst Insight</div>
      <div class="insight-box">{insight}</div>
    </div>
    """, unsafe_allow_html=True)
    
    
    # ─────────────────────────────────────────────
    # RECOMMENDED ACTION
    # ─────────────────────────────────────────────
    rec = safe_str(sel_row.get("recommended_action", ""), "")
    
    st.markdown(f"""
    <div class="detail-panel green">
      <div class="panel-title">Recommended Action</div>
      {action_items_html(rec)}
    </div>
    """, unsafe_allow_html=True)
    
    
    # ─────────────────────────────────────────────
    # ANALYST HANDOFF SUMMARY
    # ─────────────────────────────────────────────
    
    # Pull selected alert values for the handoff summary.
    handoff_incident_id = safe_str(sel_row.get("incident_id"))
    handoff_timestamp = safe_str(sel_row.get("timestamp"))
    handoff_status = safe_str(sel_row.get("status"))
    handoff_risk = safe_str(sel_row.get("risk_level"))
    handoff_mitre = safe_str(sel_row.get("mitre_technique"))
    handoff_confidence = safe_str(sel_row.get("confidence"))
    handoff_fp = safe_str(sel_row.get("false_positive_likelihood"))
    handoff_source = safe_str(sel_row.get("source_file"))
    
    handoff_ip = safe_str(sel_row.get("enriched_ip"))
    handoff_country = safe_str(sel_row.get("country"))
    handoff_city = safe_str(sel_row.get("city"))
    handoff_asn = safe_str(sel_row.get("asn_org"))
    handoff_hosting = "Yes" if sel_row.get("hosting", False) else "No"
    handoff_proxy = "Yes" if sel_row.get("proxy", False) else "No"
    
    handoff_vt_verdict = safe_str(sel_row.get("vt_verdict"))
    handoff_vt_malicious = safe_str(sel_row.get("vt_malicious"))
    handoff_vt_suspicious = safe_str(sel_row.get("vt_suspicious"))
    
    handoff_summary = f"""SOC Analyst Handoff Summary
    
    Incident: {handoff_incident_id} | Risk: {handoff_risk} | MITRE: {handoff_mitre}
    Time: {handoff_timestamp} | Status: {handoff_status} | Source: {handoff_source}
    Confidence: {handoff_confidence} | False Positive Likelihood: {handoff_fp}%
    
    Key Context:
    - Indicator: {handoff_ip}
    - Location/ASN: {handoff_city}, {handoff_country} | {handoff_asn}
    - VT Verdict: {handoff_vt_verdict} | Malicious: {handoff_vt_malicious} | Suspicious: {handoff_vt_suspicious}
    - Hosting: {handoff_hosting} | Proxy: {handoff_proxy}
    
    Assessment:
    {insight}
    
    Recommended Action:
    {rec}
    
    Analyst Follow-Up:
    1. Validate in SIEM/EDR using the indicator, host/user, and timeframe.
    2. Confirm whether the activity is expected or business-approved.
    3. Escalate if telemetry confirms malicious or unauthorized behavior.
    """
    
    with st.expander("📋 Analyst Handoff Summary", expanded=False):
        st.text_area(
            "Copy-ready handoff summary",
            value=handoff_summary,
            height=300,
            label_visibility="collapsed",
        )
    
        st.caption(
            "Copy into Splunk notes, ServiceNow/Jira, Slack escalation, or SOC shift handoff. Validate AI guidance against raw telemetry and business context."
        )
    
    st.markdown("<hr class='soc-divider'>", unsafe_allow_html=True)
    
    
    # ─────────────────────────────────────────────
    # SUGGESTED SPLUNK VALIDATION SEARCHES
    # ─────────────────────────────────────────────
    splunk_searches = build_splunk_searches(sel_row)
    
    with st.expander("🔎 Suggested Splunk Validation Searches", expanded=False):
        st.caption(
            "These SPL queries are validation starting points. Adjust index, sourcetype, host, user, "
            "field names, and time range for your Splunk environment."
        )
    
        if not splunk_searches:
            st.info("No strong indicators were available to generate Splunk searches.")
        else:
            for search_name, spl_query in splunk_searches.items():
                st.markdown(f"**{search_name}**")
                st.code(spl_query, language="spl")
    
        st.caption(
            "The helper prioritizes raw text searches first because Splunk field names vary across environments."
        )
    
    st.markdown("<hr class='soc-divider'>", unsafe_allow_html=True)
    # ─────────────────────────────────────────────
    # ANALYTICS (collapsed by default)
    # ─────────────────────────────────────────────
    with st.expander("📊  Analytics Overview", expanded=False):
        if df.empty:
            st.info("No data loaded.")
        else:
            import altair as alt
    
            def count_axis_values(series) -> list[int]:
                """
                Build exact whole-number axis ticks so Altair does not display
                rounded duplicate values like 0, 1, 1, 2, 2.
                """
                max_count = int(series.max()) if len(series) and pd.notna(series.max()) else 0
                return list(range(0, max_count + 1))
    
            ac1, ac2 = st.columns(2)
    
            # Risk distribution
            with ac1:
                st.markdown("**Risk Distribution**")
    
                risk_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    
                risk_counts = dff["risk_level"].value_counts().reindex(
                    risk_order, fill_value=0
                )
    
                risk_df = risk_counts.reset_index()
                risk_df.columns = ["Risk Level", "Count"]
    
                chart = alt.Chart(risk_df).mark_bar().encode(
                    x=alt.X(
                        "Count:Q",
                        title="",
                        axis=alt.Axis(
                            values=count_axis_values(risk_df["Count"]),
                            format="d",
                        ),
                    ),
                    y=alt.Y(
                        "Risk Level:N",
                        sort=risk_order,
                        title="",
                    ),
                    color=alt.Color(
                        "Risk Level:N",
                        scale=alt.Scale(
                            domain=risk_order,
                            range=["#f85149", "#f0883e", "#d29922", "#3fb950"],
                        ),
                        legend=None,
                    ),
                    tooltip=["Risk Level", "Count"],
                ).properties(height=140).configure_view(fill="#0d1117").configure_axis(
                    labelColor="#7d8590",
                    gridColor="#21262d",
                    domainColor="#30363d",
                    tickColor="#30363d",
                )
    
                st.altair_chart(chart, use_container_width=True)
    
            # VT verdict distribution
            with ac2:
                st.markdown("**VT Verdict Distribution**")
    
                vt_order = ["Malicious", "Suspicious", "Clean", "Unknown"]
    
                vt_counts = dff["vt_verdict"].apply(normalize_vt_verdict).value_counts().reindex(
                    vt_order, fill_value=0
                )
    
                vt_df = vt_counts.reset_index()
                vt_df.columns = ["Verdict", "Count"]
    
                color_map = {
                    "Malicious": "#f85149",
                    "Suspicious": "#f0883e",
                    "Clean": "#3fb950",
                    "Unknown": "#7d8590",
                }
    
                chart2 = alt.Chart(vt_df).mark_bar().encode(
                    x=alt.X(
                        "Count:Q",
                        title="",
                        axis=alt.Axis(
                            values=count_axis_values(vt_df["Count"]),
                            format="d",
                        ),
                    ),
                    y=alt.Y(
                        "Verdict:N",
                        sort=vt_order,
                        title="",
                    ),
                    color=alt.Color(
                        "Verdict:N",
                        scale=alt.Scale(
                            domain=list(color_map.keys()),
                            range=list(color_map.values()),
                        ),
                        legend=None,
                    ),
                    tooltip=["Verdict", "Count"],
                ).properties(height=140).configure_view(fill="#0d1117").configure_axis(
                    labelColor="#7d8590",
                    gridColor="#21262d",
                    domainColor="#30363d",
                    tickColor="#30363d",
                )
    
                st.altair_chart(chart2, use_container_width=True)
    
            # Analyst status distribution — full width because this reflects analyst workflow state
            st.markdown("**Analyst Status Distribution**")
    
            status_order = [
                "NEW",
                "REVIEWING",
                "ESCALATED",
                "CLOSED - TRUE POSITIVE",
                "CLOSED - FALSE POSITIVE",
                "CLOSED - BENIGN",
            ]
    
            status_counts = dff["status"].value_counts().reindex(
                status_order, fill_value=0
            )
    
            status_df = status_counts.reset_index()
            status_df.columns = ["Status", "Count"]
    
            status_chart = alt.Chart(status_df).mark_bar().encode(
                x=alt.X(
                    "Count:Q",
                    title="",
                    axis=alt.Axis(
                        values=count_axis_values(status_df["Count"]),
                        format="d",
                    ),
                ),
                y=alt.Y(
                    "Status:N",
                    sort=status_order,
                    title="",
                ),
                color=alt.Color(
                    "Status:N",
                    scale=alt.Scale(
                        domain=status_order,
                        range=[
                            "#c9d1d9",
                            "#bc8cff",
                            "#f85149",
                            "#3fb950",
                            "#7d8590",
                            "#7d8590",
                        ],
                    ),
                    legend=None,
                ),
                tooltip=["Status", "Count"],
            ).properties(height=230).configure_view(fill="#0d1117").configure_axis(
                labelColor="#7d8590",
                gridColor="#21262d",
                domainColor="#30363d",
                tickColor="#30363d",
                labelLimit=220,
            )
    
            st.altair_chart(status_chart, use_container_width=True)
    
            ac3, ac4 = st.columns(2)
    
            # Top MITRE techniques
            with ac3:
                st.markdown("**Top MITRE Techniques**")
    
                mitre_counts = dff["mitre_technique"].value_counts().head(8).reset_index()
                mitre_counts.columns = ["Technique", "Count"]
    
                chart3 = alt.Chart(mitre_counts).mark_bar(color="#bc8cff").encode(
                    x=alt.X(
                        "Count:Q",
                        title="",
                        axis=alt.Axis(
                            values=count_axis_values(mitre_counts["Count"]),
                            format="d",
                        ),
                    ),
                    y=alt.Y("Technique:N", sort="-x", title=""),
                    tooltip=["Technique", "Count"],
                ).properties(height=200).configure_view(fill="#0d1117").configure_axis(
                    labelColor="#7d8590",
                    gridColor="#21262d",
                    domainColor="#30363d",
                    tickColor="#30363d",
                    labelLimit=180,
                )
    
                st.altair_chart(chart3, use_container_width=True)
    
            # Top enriched IPs
            with ac4:
                st.markdown("**Top Enriched IPs**")
    
                ip_counts = dff["enriched_ip"].value_counts().head(8).reset_index()
                ip_counts.columns = ["IP", "Count"]
    
                chart4 = alt.Chart(ip_counts).mark_bar(color="#388bfd").encode(
                    x=alt.X(
                        "Count:Q",
                        title="",
                        axis=alt.Axis(
                            values=count_axis_values(ip_counts["Count"]),
                            format="d",
                        ),
                    ),
                    y=alt.Y("IP:N", sort="-x", title=""),
                    tooltip=["IP", "Count"],
                ).properties(height=200).configure_view(fill="#0d1117").configure_axis(
                    labelColor="#7d8590",
                    gridColor="#21262d",
                    domainColor="#30363d",
                    tickColor="#30363d",
                )
    
                st.altair_chart(chart4, use_container_width=True)# ─────────────────────────────────────────────
    # RAW ALERT RECORD (collapsed by default)
    # ─────────────────────────────────────────────
    with st.expander("🗂  Raw Alert Record", expanded=False):
        import json
    
        raw = {k: v for k, v in sel_row.items() if not k.startswith("_")}
    
        # Convert non-serializable types
        for k, v in raw.items():
            if isinstance(v, bool):
                raw[k] = bool(v)
            elif pd.isna(v) if isinstance(v, float) else False:
                raw[k] = None
    
        st.code(json.dumps(raw, indent=2, default=str), language="json")
    
    
    # ─────────────────────────────────────────────
    # FOOTER
    # ─────────────────────────────────────────────
    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown("""
    <div style="font-family:'Courier New',monospace;font-size:0.62rem;color:#30363d;text-align:center;letter-spacing:0.08em">
    AI-SOC TRIAGE CONSOLE &bull; L1 ANALYST DECISION-SUPPORT &bull; ANTHROPIC CLAUDE
    </div>
    """, unsafe_allow_html=True)
