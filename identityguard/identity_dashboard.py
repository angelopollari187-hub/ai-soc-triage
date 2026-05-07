"""
IdentityGuard AI — Dashboard Tab Renderer
Called from inside `with tab_ig:` in dashboard.py.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
import streamlit as st

BASE_DIR = Path(__file__).resolve().parent.parent
IDENTITY_CSV_PATH = BASE_DIR / "output" / "identity_alerts.csv"
IDENTITY_AI_SUMMARIES_PATH = BASE_DIR / "output" / "identity_ai_summaries.json"
IDENTITY_REPORTS_PATH = BASE_DIR / "output" / "identity_reports"

IG_STATUS_OPTIONS = [
    "NEW", "IN_REVIEW", "ESCALATED", "CONTAINED", "CLOSED", "FALSE_POSITIVE",
]

_RISK_COLOR = {
    "CRITICAL": "#f85149",
    "HIGH":     "#f0883e",
    "MEDIUM":   "#d29922",
    "LOW":      "#3fb950",
}

IDENTITY_EVENT_FIELDS = [
    "incident_id",
    "user",
    "user_role",
    "event_time",
    "event_type",
    "source_ip",
    "country",
    "city",
    "device_id",
    "device_trust_status",
    "device_os",
    "mfa_result",
    "mfa_method",
    "app_name",
    "action",
    "oauth_app_name",
    "oauth_permission",
    "mailbox_action",
    "risk_signal",
    "known_vpn",
    "impossible_travel_flag",
    "failed_login_count",
    "session_id",
    "notes",
]

REQUIRED_IDENTITY_EVENT_FIELDS = ["incident_id", "user", "event_time", "event_type"]
BOOLEAN_IDENTITY_EVENT_FIELDS = {"known_vpn", "impossible_travel_flag"}
NUMERIC_IDENTITY_EVENT_FIELDS = {"failed_login_count"}
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


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _safe(val, fallback="—"):
    if val is None:
        return fallback
    s = str(val).strip()
    return s if s not in ("", "nan", "None") else fallback


def _safe_int(val, fallback=0):
    try:
        return int(float(val))
    except Exception:
        return fallback


def _risk_badge(level):
    slug = str(level).lower()
    return f'<span class="badge badge-{slug}">{level}</span>'


def _status_badge(status):
    slug = str(status).lower().replace("_", "")
    return f'<span class="badge badge-{slug}">{status}</span>'


def _html_escape(val) -> str:
    return (
        str(val)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def _generate_demo_identity_incidents() -> int:
    """Regenerate demo IdentityGuard incidents without touching SOC outputs."""
    from identityguard.demo_identity_generator import (
        build_demo_incidents, triage_all_demo_incidents,
    )
    from identityguard.identity_csv_exporter import write_results

    incidents = build_demo_incidents()
    results = triage_all_demo_incidents(incidents)
    IDENTITY_CSV_PATH.parent.mkdir(parents=True, exist_ok=True)
    write_results(results, str(IDENTITY_CSV_PATH))
    return len(results)


def _parse_bool(value) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).strip().lower() in {"1", "true", "yes", "y", "on"}


def _blank_if_missing(value) -> str:
    if value is None:
        return ""
    text = str(value).strip()
    return "" if text.lower() in {"", "nan", "none", "null"} else text


def _normalize_identity_event(event: dict) -> dict:
    normalized = {}
    for field in IDENTITY_EVENT_FIELDS:
        value = event.get(field, "")
        if field in BOOLEAN_IDENTITY_EVENT_FIELDS:
            normalized[field] = _parse_bool(value)
        elif field in NUMERIC_IDENTITY_EVENT_FIELDS:
            try:
                normalized[field] = int(float(value)) if _blank_if_missing(value) else 0
            except Exception:
                normalized[field] = 0
        else:
            normalized[field] = _blank_if_missing(value)
    return normalized


def _validate_identity_events(events: list[dict]) -> list[str]:
    missing = set()
    for event in events:
        for field in REQUIRED_IDENTITY_EVENT_FIELDS:
            if not _blank_if_missing(event.get(field)):
                missing.add(field)
    return sorted(missing)


def _group_events_by_incident(events: list[dict]) -> list[dict]:
    grouped: dict[str, list[dict]] = {}
    for event in events:
        incident_id = _blank_if_missing(event.get("incident_id"))
        if not incident_id:
            continue
        grouped.setdefault(incident_id, []).append(event)

    incidents = []
    for incident_id, incident_events in grouped.items():
        user = _blank_if_missing(incident_events[0].get("user")) or "unknown user"
        incidents.append({
            "incident_id": incident_id,
            "scenario": f"Uploaded identity telemetry for {user}",
            "events": incident_events,
        })
    return incidents


def _incidents_from_csv(uploaded_file) -> list[dict]:
    uploaded_file.seek(0)
    df = pd.read_csv(uploaded_file)
    records = df.fillna("").to_dict(orient="records")
    missing = _validate_identity_events(records)
    if missing:
        raise ValueError("Missing required identity field(s): " + ", ".join(missing))
    events = [_normalize_identity_event(record) for record in records]
    return _group_events_by_incident(events)


def _incidents_from_json(uploaded_file) -> list[dict]:
    try:
        payload = json.loads(uploaded_file.getvalue().decode("utf-8"))
    except UnicodeDecodeError:
        payload = json.loads(uploaded_file.getvalue().decode("utf-8-sig"))

    if not isinstance(payload, list):
        raise ValueError("Identity JSON must be a list of incidents or a list of event objects.")

    if payload and isinstance(payload[0], dict) and "events" in payload[0]:
        incidents = []
        all_events = []
        for item in payload:
            if not isinstance(item, dict):
                raise ValueError("Each identity incident must be a JSON object.")
            events = item.get("events", [])
            if not isinstance(events, list):
                raise ValueError("Each identity incident must contain an events list.")
            parent_incident_id = _blank_if_missing(item.get("incident_id"))
            event_records = []
            for event in events:
                if not isinstance(event, dict):
                    continue
                event_copy = dict(event)
                if parent_incident_id and not _blank_if_missing(event_copy.get("incident_id")):
                    event_copy["incident_id"] = parent_incident_id
                event_records.append(event_copy)
            normalized_events = [_normalize_identity_event(event) for event in event_records]
            all_events.extend(normalized_events)
            incident_id = _blank_if_missing(item.get("incident_id")) or (
                normalized_events[0]["incident_id"] if normalized_events else ""
            )
            incidents.append({
                "incident_id": incident_id,
                "scenario": _blank_if_missing(item.get("scenario")) or f"Uploaded identity telemetry for {incident_id}",
                "events": normalized_events,
            })
        missing = _validate_identity_events(all_events)
        if missing:
            raise ValueError("Missing required identity field(s): " + ", ".join(missing))
        return [inc for inc in incidents if inc["incident_id"] and inc["events"]]

    events = [item for item in payload if isinstance(item, dict)]
    missing = _validate_identity_events(events)
    if missing:
        raise ValueError("Missing required identity field(s): " + ", ".join(missing))
    return _group_events_by_incident([_normalize_identity_event(event) for event in events])


def _triage_and_write_identity_incidents(incidents: list[dict]) -> int:
    from identityguard.identity_csv_exporter import write_results
    from identityguard.identity_scoring import score_incident

    if not incidents:
        raise ValueError("No identity incidents were found in the uploaded file.")
    results = [score_incident(inc["incident_id"], inc["events"]) for inc in incidents]
    IDENTITY_CSV_PATH.parent.mkdir(parents=True, exist_ok=True)
    write_results(results, str(IDENTITY_CSV_PATH))
    return len(results)


def _soc_identity_signal_mask(df: pd.DataFrame) -> pd.Series:
    likely_fields = [
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
    existing_fields = [field for field in likely_fields if field in df.columns]
    if not existing_fields:
        existing_fields = list(df.columns)
    text = df[existing_fields].fillna("").astype(str).agg(" ".join, axis=1).str.lower()
    pattern = "|".join(re.escape(keyword.lower()) for keyword in IDENTITY_PIVOT_KEYWORDS)
    return text.str.contains(pattern, regex=True, na=False)


def _render_soc_pivot_review(uploaded_file) -> None:
    if uploaded_file is None:
        return
    try:
        uploaded_file.seek(0)
        df = pd.read_csv(uploaded_file)
    except Exception as exc:
        st.error(f"Could not read SOC alerts_summary.csv: {exc}")
        return

    if df.empty:
        st.info("Uploaded SOC alerts_summary.csv is empty.")
        return

    matches = df[_soc_identity_signal_mask(df)].copy()
    if matches.empty:
        st.info("No identity signals detected in the uploaded SOC alerts_summary.csv.")
        return

    st.success(f"Identity signals detected in {len(matches)} SOC alert(s).")
    st.info(
        "Limited SOC alert context detected. For deeper IdentityGuard scoring, upload full identity telemetry CSV/JSON."
    )
    preview_cols = [
        col for col in [
            "incident_id",
            "risk_level",
            "mitre_technique",
            "source_file",
            "analyst_insight",
            "recommended_action",
        ] if col in matches.columns
    ]
    st.dataframe(matches[preview_cols].head(25), use_container_width=True, hide_index=True)


def _handle_identity_upload(uploaded_file, file_kind: str) -> None:
    if uploaded_file is None:
        return

    file_bytes = uploaded_file.getvalue()
    upload_hash = hashlib.sha256(file_bytes).hexdigest()
    state_key = f"ig_processed_{file_kind}_hash"
    if st.session_state.get(state_key) == upload_hash:
        return

    try:
        if file_kind == "csv":
            incidents = _incidents_from_csv(uploaded_file)
        else:
            incidents = _incidents_from_json(uploaded_file)
        count = _triage_and_write_identity_incidents(incidents)
    except Exception as exc:
        st.error(str(exc))
        return

    st.session_state[state_key] = upload_hash
    st.session_state["ig_uploaded_incidents"] = incidents
    st.session_state["ig_upload_success"] = (
        f"Uploaded identity {file_kind.upper()} validated and triaged. "
        f"{count} incidents written to output/identity_alerts.csv."
    )
    st.rerun()


def _clear_identity_runtime_data() -> list[str]:
    """Remove only IdentityGuard runtime outputs allowed by the dashboard control."""
    removed = []
    runtime_targets = [
        IDENTITY_CSV_PATH,
        IDENTITY_AI_SUMMARIES_PATH,
        IDENTITY_REPORTS_PATH,
    ]

    for target in runtime_targets:
        if target.is_dir():
            shutil.rmtree(target)
            removed.append(str(target.relative_to(BASE_DIR)))
        elif target.is_file():
            target.unlink()
            removed.append(str(target.relative_to(BASE_DIR)))

    return removed


def _sample_identity_csv_template() -> bytes:
    sample_row = {
        "incident_id": "INC-IG-SAMPLE-001",
        "user": "user@example.com",
        "user_role": "Employee",
        "event_time": "2026-05-06T12:00:00Z",
        "event_type": "SignIn",
        "source_ip": "203.0.113.10",
        "country": "United States",
        "city": "New York",
        "device_id": "DEV-SAMPLE-001",
        "device_trust_status": "managed",
        "device_os": "Windows 11",
        "mfa_result": "success",
        "mfa_method": "authenticator_app",
        "app_name": "Example SaaS App",
        "action": "login_success",
        "oauth_app_name": "",
        "oauth_permission": "",
        "mailbox_action": "",
        "risk_signal": "",
        "known_vpn": "false",
        "impossible_travel_flag": "false",
        "failed_login_count": "0",
        "session_id": "sess-sample-001",
        "notes": "Replace this row with identity telemetry.",
    }
    header = ",".join(IDENTITY_EVENT_FIELDS)
    row = ",".join(str(sample_row.get(field, "")) for field in IDENTITY_EVENT_FIELDS)
    return f"{header}\n{row}\n".encode("utf-8")


def _sample_identity_json_template() -> bytes:
    template = [
        {
            "incident_id": "INC-IG-SAMPLE-001",
            "scenario": "Sample Identity Incident",
            "events": [
                {
                    "incident_id": "INC-IG-SAMPLE-001",
                    "user": "user@example.com",
                    "user_role": "Employee",
                    "event_time": "2026-05-06T12:00:00+00:00",
                    "event_type": "SignIn",
                    "source_ip": "203.0.113.10",
                    "country": "United States",
                    "city": "New York",
                    "device_id": "DEV-SAMPLE-001",
                    "device_trust_status": "managed",
                    "device_os": "Windows 11",
                    "mfa_result": "success",
                    "mfa_method": "authenticator_app",
                    "app_name": "Microsoft 365",
                    "action": "login_success",
                    "oauth_app_name": None,
                    "oauth_permission": None,
                    "mailbox_action": None,
                    "risk_signal": None,
                    "known_vpn": False,
                    "impossible_travel_flag": False,
                    "failed_login_count": 0,
                    "session_id": "sess-sample-001",
                    "notes": "Replace this sample event with identity telemetry.",
                },
                {
                    "incident_id": "INC-IG-SAMPLE-001",
                    "user": "user@example.com",
                    "user_role": "Employee",
                    "event_time": "2026-05-06T12:07:00Z",
                    "event_type": "OAuthConsent",
                    "source_ip": "203.0.113.10",
                    "country": "United States",
                    "city": "New York",
                    "device_id": "DEV-SAMPLE-001",
                    "device_trust_status": "managed",
                    "device_os": "Windows 11",
                    "mfa_result": "",
                    "mfa_method": "",
                    "app_name": "Example SaaS App",
                    "action": "oauth_consent_granted",
                    "oauth_app_name": "ExampleApp",
                    "oauth_permission": "Mail.Read",
                    "mailbox_action": "",
                    "risk_signal": "oauth_consent_to_unverified_app",
                    "known_vpn": False,
                    "impossible_travel_flag": False,
                    "failed_login_count": 0,
                    "session_id": "sess-sample-001",
                    "notes": "Optional second event showing OAuth consent telemetry.",
                },
            ],
        }
    ]
    return json.dumps(template, indent=2).encode("utf-8")


def _render_identity_control_panel() -> None:
    st.markdown('<div class="section-hdr">IdentityGuard Intake</div>', unsafe_allow_html=True)
    st.caption(
        "Upload structured identity telemetry exported from an IAM, SIEM, SOAR, or identity-security workflow. "
        "Use the templates below when preparing demo or test data."
    )
    if st.session_state.get("ig_upload_success"):
        st.success(st.session_state["ig_upload_success"])

    c1, c2, c3 = st.columns(3)

    with c1:
        csv_upload = st.file_uploader(
            "Upload Identity CSV",
            type=["csv"],
            key="ig_identity_csv_upload",
            help="Required fields: incident_id, user, event_time, event_type.",
        )
        _handle_identity_upload(csv_upload, "csv")

    with c2:
        json_upload = st.file_uploader(
            "Upload Identity JSON",
            type=["json"],
            key="ig_identity_json_upload",
            help="Supports a list of incidents with events or a flat list of event objects.",
        )
        _handle_identity_upload(json_upload, "json")

    with c3:
        soc_pivot_upload = st.file_uploader(
            "Upload SOC alerts_summary.csv for Identity Pivot Review",
            type=["csv"],
            key="ig_soc_pivot_upload",
            help="Preview identity-related SOC alerts without overwriting IdentityGuard triage output.",
        )
        _render_soc_pivot_review(soc_pivot_upload)

    t1, t2, t3 = st.columns([1, 1, 1])
    with t1:
        st.download_button(
            "Download Sample Identity CSV Template",
            data=_sample_identity_csv_template(),
            file_name="identityguard_sample_template.csv",
            mime="text/csv",
            use_container_width=True,
            key="ig_sample_csv_template",
        )

    with t2:
        st.download_button(
            "Download Sample Identity JSON Template",
            data=_sample_identity_json_template(),
            file_name="identityguard_sample_template.json",
            mime="application/json",
            use_container_width=True,
            key="ig_sample_json_template",
        )

    with t3:
        if st.button(
            "Clear IdentityGuard Runtime Data",
            use_container_width=True,
            key="ig_clear_runtime_data",
        ):
            removed = _clear_identity_runtime_data()
            for key in ("ig_processed_csv_hash", "ig_processed_json_hash", "ig_upload_success", "ig_uploaded_incidents"):
                st.session_state.pop(key, None)
            if removed:
                st.success("Cleared: " + ", ".join(removed))
            else:
                st.info("No IdentityGuard runtime data was present.")

    st.markdown("<hr class='soc-divider'>", unsafe_allow_html=True)
# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------

def _load_or_generate() -> tuple[pd.DataFrame, bool]:
    """Load identity_alerts.csv, or generate 12 demo incidents if absent."""
    if IDENTITY_CSV_PATH.exists():
        try:
            df = pd.read_csv(IDENTITY_CSV_PATH)
            if not df.empty:
                return df, False
        except Exception:
            pass

    # Generate demo data
    from identityguard.demo_identity_generator import (
        build_demo_incidents, triage_all_demo_incidents,
    )
    from identityguard.identity_csv_exporter import write_results, load_results

    incidents = build_demo_incidents()
    results = triage_all_demo_incidents(incidents)
    write_results(results, str(IDENTITY_CSV_PATH))
    rows = load_results(str(IDENTITY_CSV_PATH))
    return pd.DataFrame(rows), True


# ---------------------------------------------------------------------------
# Event timeline HTML
# ---------------------------------------------------------------------------

def _event_timeline_html(incident_id: str) -> str:
    uploaded_incidents = st.session_state.get("ig_uploaded_incidents", [])
    if uploaded_incidents:
        inc = next((i for i in uploaded_incidents if i.get("incident_id") == incident_id), None)
        if inc:
            events = inc.get("events", [])
            if not events:
                return "<div style='color:#7d8590;font-size:0.75rem'>No events.</div>"
            return _event_rows_html(events)

    sample_path = BASE_DIR / "identityguard" / "sample_events" / "demo_incidents.json"
    if not sample_path.exists():
        return "<div style='color:#7d8590;font-size:0.75rem'>Timeline not available.</div>"

    with open(sample_path, "r", encoding="utf-8") as f:
        incidents = json.load(f)

    inc = next((i for i in incidents if i["incident_id"] == incident_id), None)
    if not inc:
        return f"<div style='color:#7d8590;font-size:0.75rem'>No events for {incident_id}.</div>"

    events = inc.get("events", [])
    if not events:
        return "<div style='color:#7d8590;font-size:0.75rem'>No events.</div>"
    return _event_rows_html(events)


def _event_rows_html(events: list[dict]) -> str:
    rows_html = ""
    for i, ev in enumerate(events):
        action        = _safe(ev.get("action", ""))
        mailbox_action = _safe(ev.get("mailbox_action", ""))
        event_type    = _safe(ev.get("event_type", ""))

        if "failed" in action or "denied" in action:
            txt = "#f0883e"
        elif "success" in action:
            txt = "#3fb950"
        elif "forward" in mailbox_action or "rule" in mailbox_action:
            txt = "#f85149"
        elif "oauth" in event_type.lower():
            txt = "#bc8cff"
        elif "password_reset" in action:
            txt = "#f0883e"
        else:
            txt = "#c9d1d9"

        ts      = _safe(ev.get("event_time", ""))[:19].replace("T", " ")
        country = _safe(ev.get("country", ""))
        trust   = _safe(ev.get("device_trust_status", ""))
        mfa     = ev.get("mfa_result")
        mfa_str = f"MFA:{mfa}" if mfa and mfa not in (None, "", "None") else ""
        sig     = ev.get("risk_signal")
        sig_str = f"signal:{sig}" if sig and sig not in (None, "", "None") else ""
        detail  = " · ".join(filter(None, [country, trust, mfa_str, sig_str, action]))

        rows_html += (
            '<tr style="background:#161b22">'
            f'<td style="color:#7d8590;font-size:0.65rem;padding:5px 8px;white-space:nowrap">{i+1}</td>'
            f'<td style="color:#7d8590;font-size:0.65rem;padding:5px 8px;white-space:nowrap">{ts}</td>'
            f'<td style="padding:5px 8px"><span style="color:{txt};background:#0d1117;'
            f'border:1px solid #30363d;border-radius:4px;padding:2px 6px;font-size:0.65rem;'
            f'font-weight:600">{_html_escape(event_type)}</span></td>'
            f'<td style="color:#c9d1d9;font-size:0.68rem;padding:5px 8px">{_html_escape(detail)}</td>'
            f'</tr>'
        )

    return (
        '<div style="background:#161b22;border:1px solid #30363d;border-radius:6px;overflow-x:auto">'
        '<table style="width:100%;border-collapse:collapse;font-family:\'Courier New\',monospace">'
        '<thead><tr style="background:#0d1117">'
        '<th style="color:#7d8590;font-size:0.6rem;text-transform:uppercase;padding:6px 8px;border-bottom:1px solid #30363d;text-align:left">#</th>'
        '<th style="color:#7d8590;font-size:0.6rem;text-transform:uppercase;padding:6px 8px;border-bottom:1px solid #30363d;text-align:left">Time (UTC)</th>'
        '<th style="color:#7d8590;font-size:0.6rem;text-transform:uppercase;padding:6px 8px;border-bottom:1px solid #30363d;text-align:left">Event Type</th>'
        '<th style="color:#7d8590;font-size:0.6rem;text-transform:uppercase;padding:6px 8px;border-bottom:1px solid #30363d;text-align:left">Details</th>'
        '</tr></thead>'
        f'<tbody>{rows_html}</tbody>'
        '</table></div>'
    )


# ---------------------------------------------------------------------------
# Risk score breakdown HTML
# ---------------------------------------------------------------------------

def _scoring_html(scoring_reasons: str) -> str:
    if not scoring_reasons or scoring_reasons == "—":
        return "<div style='color:#7d8590;font-size:0.75rem'>No scoring breakdown available.</div>"

    rows = ""
    for line in str(scoring_reasons).splitlines():
        line = line.strip()
        if not line:
            continue

        score = ""
        rule = ""
        explanation = line
        match = re.match(r"^(\[[^\]]+\])\s*([^:]+)?(?::\s*)?(.*)$", line)
        if match:
            score = match.group(1)
            rule = (match.group(2) or "").strip()
            explanation = (match.group(3) or "").strip() or line

        if score.startswith("[+"):
            score_color = "#f85149"
        elif score.startswith("[-"):
            score_color = "#3fb950"
        else:
            score_color = "#7d8590"

        rows += (
            '<tr style="background:#161b22">'
            f'<td style="color:{score_color};font-size:0.72rem;font-weight:700;padding:7px 10px;'
            f'border-bottom:1px solid #21262d;white-space:nowrap">{_html_escape(score)}</td>'
            f'<td style="color:#bc8cff;font-size:0.7rem;padding:7px 10px;border-bottom:1px solid #21262d;'
            f'white-space:nowrap">{_html_escape(rule) if rule else "—"}</td>'
            f'<td style="color:#c9d1d9;font-size:0.7rem;padding:7px 10px;border-bottom:1px solid #21262d;'
            f'line-height:1.5">{_html_escape(explanation)}</td>'
            '</tr>'
        )
    return (
        '<div style="background:#161b22;border:1px solid #30363d;border-radius:6px;overflow-x:auto">'
        '<table style="width:100%;border-collapse:collapse;font-family:\'Courier New\',monospace">'
        '<thead><tr style="background:#0d1117">'
        '<th style="color:#7d8590;font-size:0.6rem;text-transform:uppercase;padding:6px 10px;border-bottom:1px solid #30363d;text-align:left">Score</th>'
        '<th style="color:#7d8590;font-size:0.6rem;text-transform:uppercase;padding:6px 10px;border-bottom:1px solid #30363d;text-align:left">Rule</th>'
        '<th style="color:#7d8590;font-size:0.6rem;text-transform:uppercase;padding:6px 10px;border-bottom:1px solid #30363d;text-align:left">Explanation</th>'
        '</tr></thead>'
        f'<tbody>{rows}</tbody>'
        '</table></div>'
    )


# ---------------------------------------------------------------------------
# AI summary panel (on-demand, button-gated)
# ---------------------------------------------------------------------------

def _get_cached_handoff_summary(incident_id: str) -> str:
    """Return the AI analyst_summary string for the handoff report, or a placeholder."""
    try:
        from identityguard.identity_ai_prompt import get_cached_summary
        # We don't have the incident dict here, so we check the cache directly
        from identityguard.identity_ai_prompt import _load_cache
        cache = _load_cache()
        entry = cache.get(incident_id, {})
        summary_dict = entry.get("summary", {})
        if summary_dict.get("_fallback_narrative"):
            return summary_dict.get("analyst_summary", "AI fallback narrative cached.")
        return summary_dict.get("analyst_summary", "(AI summary not yet generated — click Generate AI Summary)")
    except Exception:
        return "(AI summary not yet generated)"


def _render_ai_summary_failure(result) -> None:
    st.warning(
        "AI summary generation failed. Deterministic triage recommendations remain available above."
    )
    st.markdown(
        "<details style='margin-top:8px'>"
        "<summary style=\"font-family:'Courier New',monospace;font-size:0.78rem;color:#8b949e;cursor:pointer\">"
        "Debug details</summary>"
        "<pre style=\"white-space:pre-wrap;background:#0d1117;border:1px solid #30363d;"
        "border-radius:6px;padding:10px;color:#c9d1d9;font-size:0.72rem;line-height:1.45\">"
        f"{_html_escape(result)}</pre></details>",
        unsafe_allow_html=True,
    )


def _render_ai_debug_details(details: str) -> None:
    if not details:
        return
    st.markdown(
        "<details style='margin-top:8px'>"
        "<summary style=\"font-family:'Courier New',monospace;font-size:0.78rem;color:#8b949e;cursor:pointer\">"
        "Debug details</summary>"
        "<pre style=\"white-space:pre-wrap;background:#0d1117;border:1px solid #30363d;"
        "border-radius:6px;padding:10px;color:#c9d1d9;font-size:0.72rem;line-height:1.45\">"
        f"{_html_escape(details)}</pre></details>",
        unsafe_allow_html=True,
    )


def _render_ai_summary_panel(incident_id: str, incident: dict) -> None:
    """
    Render the AI analyst summary section.

    Contract:
      - NEVER calls the API automatically.
      - Only calls the API when the analyst clicks "Generate AI Analyst Summary".
      - Shows cached summary if one exists and the incident hash matches.
      - Shows a stale-data warning and Regenerate button if hash has changed.
      - Shows a warning if ANTHROPIC_API_KEY is not set.
    """
    from identityguard.identity_ai_prompt import (
        get_cached_summary,
        is_summary_stale,
        save_summary,
        generate_identity_summary,
        get_cache_metadata,
    )
    import os
    try:
        from dotenv import load_dotenv
        load_dotenv()
    except ImportError:
        pass

    has_api_key  = bool(os.getenv("ANTHROPIC_API_KEY"))
    cached       = get_cached_summary(incident_id, incident)
    stale        = is_summary_stale(incident_id, incident)
    meta         = get_cache_metadata(incident_id)

    with st.expander("AI Analyst Summary", expanded=False):
        st.caption(
            "Optional narrative assist. Use deterministic Priority Confidence, "
            "false-positive likelihood, and supporting evidence above for first-response sequencing."
        )

        # ── State: no API key ──
        if not has_api_key:
            st.warning(
                "ANTHROPIC_API_KEY is not set. Add it to your .env file to enable AI summaries.\n\n"
                "```\nANTHROPIC_API_KEY=sk-ant-...\n```"
            )

        # ── State: cached summary exists ──
        if cached:
            if meta:
                generated_ts = str(meta.get("generated_at", ""))[:19].replace("T", " ")
                st.caption(f"Generated at {generated_ts} UTC  ·  cached locally")

            if stale:
                st.warning(
                    "The incident scoring data has changed since this summary was generated. "
                    "Consider regenerating."
                )

            _render_summary_cards(cached)

            if has_api_key:
                st.markdown("<br>", unsafe_allow_html=True)
                if st.button(
                    "Regenerate Summary",
                    use_container_width=False,
                    key=f"ig_regen_summary_{incident_id}",
                ):
                    with st.spinner("Calling Claude API..."):
                        ok, result = generate_identity_summary(incident)
                    if ok:
                        save_summary(incident_id, result, incident)
                        st.success("Summary regenerated and cached.")
                        st.rerun()
                    else:
                        _render_ai_summary_failure(result)
            return

        # ── State: stale entry exists but hash changed ──
        if stale:
            st.info(
                "A previous summary exists but the incident data has changed since it was generated. "
                "Click Regenerate below to update."
            )

        # ── State: no cache yet ──
        st.markdown(
            '<div style="color:#7d8590;font-family:\'Courier New\',monospace;font-size:0.78rem;'
            'margin-bottom:12px">No AI summary generated yet for this incident.</div>',
            unsafe_allow_html=True,
        )

        if not has_api_key:
            st.info("Set ANTHROPIC_API_KEY in .env to enable the Generate button.")
            return

        if st.button(
            "Generate AI Analyst Summary",
            use_container_width=True,
            key=f"ig_gen_summary_{incident_id}",
            type="primary",
        ):
            with st.spinner("Calling Claude API — this takes 5-15 seconds..."):
                ok, result = generate_identity_summary(incident)

            if ok:
                save_summary(incident_id, result, incident)
                st.success("AI summary generated and cached locally.")
                st.rerun()
            else:
                _render_ai_summary_failure(result)


def _render_summary_cards(summary: dict) -> None:
    """Render a generated summary dict as structured dashboard panels."""

    if summary.get("_fallback_narrative"):
        st.warning("AI returned narrative output instead of structured JSON. Displaying fallback summary.")
        st.markdown(f"""
        <div class="detail-panel">
          <div class="panel-title">Fallback AI Narrative Summary</div>
          <div class="insight-box">{_html_escape(summary.get("analyst_summary", "No fallback text available."))}</div>
        </div>
        """, unsafe_allow_html=True)
        _render_ai_debug_details(str(summary.get("_debug_details", "")))
        return

    def _s(key: str, fallback: str = "—") -> str:
        v = summary.get(key, fallback)
        if not v or str(v).strip() in ("", "None"):
            return fallback
        return str(v).strip()

    def _list_html(key: str) -> str:
        items = summary.get(key, [])
        if not items:
            return "<div style='color:#7d8590;font-size:0.75rem'>None provided.</div>"
        if isinstance(items, str):
            items = [items]
        rows = "".join(
            f'<div class="action-item">'
            f'<span class="action-bullet">&#9658;</span>'
            f'<span style="font-size:0.75rem">{item}</span>'
            f'</div>'
            for item in items
        )
        return f'<div class="action-box">{rows}</div>'

    # ── Analyst summary ──
    st.markdown(f"""
    <div class="detail-panel accent">
      <div class="panel-title">Analyst Summary</div>
      <div class="insight-box">{_s("analyst_summary")}</div>
    </div>
    """, unsafe_allow_html=True)

    # ── Likely scenario + why flagged ──
    c1, c2 = st.columns(2)
    with c1:
        st.markdown(f"""
        <div class="detail-panel">
          <div class="panel-title">Likely Scenario</div>
          <div class="insight-box" style="font-size:0.78rem">{_s("likely_scenario")}</div>
        </div>
        """, unsafe_allow_html=True)
    with c2:
        st.markdown(f"""
        <div class="detail-panel">
          <div class="panel-title">Why Flagged</div>
          <div class="insight-box" style="font-size:0.78rem">{_s("why_flagged")}</div>
        </div>
        """, unsafe_allow_html=True)

    # ── FP considerations + uncertainty ──
    c3, c4 = st.columns(2)
    with c3:
        st.markdown(f"""
        <div class="detail-panel">
          <div class="panel-title">False Positive Considerations</div>
          <div class="insight-box" style="font-size:0.78rem">{_s("false_positive_considerations")}</div>
        </div>
        """, unsafe_allow_html=True)
    with c4:
        conf = _s("confidence_assessment")
        conf_color = "#f85149" if conf.startswith("LOW") else "#d29922" if conf.startswith("MEDIUM") else "#3fb950"
        st.markdown(f"""
        <div class="detail-panel">
          <div class="panel-title">AI Confidence Assessment</div>
          <div style="font-family:'Courier New',monospace;font-size:0.78rem;
                      color:{conf_color};line-height:1.6">{conf}</div>
        </div>
        """, unsafe_allow_html=True)

    # ── Action lists ──
    col_rec, col_con = st.columns(2)
    with col_rec:
        st.markdown(
            '<div class="panel-title" style="margin-top:8px">Recommended Analyst Actions</div>',
            unsafe_allow_html=True,
        )
        st.markdown(_list_html("recommended_analyst_actions"), unsafe_allow_html=True)
    with col_con:
        st.markdown(
            '<div class="panel-title" style="margin-top:8px">Containment Steps</div>',
            unsafe_allow_html=True,
        )
        st.markdown(_list_html("containment_steps"), unsafe_allow_html=True)

    # ── Evidence checklist ──
    st.markdown(
        '<div class="panel-title" style="margin-top:8px">Evidence Checklist</div>',
        unsafe_allow_html=True,
    )
    st.markdown(_list_html("evidence_checklist"), unsafe_allow_html=True)

    # ── Ticket handoff ──
    with st.expander("Ticket-Ready Handoff Text", expanded=False):
        st.text_area(
            "Ticket handoff",
            value=_s("ticket_handoff"),
            height=180,
            label_visibility="collapsed",
            key=f"ai_ticket_{id(summary)}",
        )
        st.caption("Copy into ServiceNow / Jira / Slack escalation.")

    # ── Uncertainty notes ──
    uncertainty = _s("uncertainty_notes")
    if uncertainty and uncertainty != "—":
        st.markdown(
            f'<div class="decision-validate" style="margin-top:8px">'
            f'[?] Uncertainty: {uncertainty}</div>',
            unsafe_allow_html=True,
        )


def _recommended_actions_html(recommended_actions: str) -> str:
    parts = [p.strip() for p in recommended_actions.replace("\n\n", "\n").split("\n") if p.strip()]
    if not parts:
        parts = ["No recommended actions available."]

    rows = ""
    for idx, part in enumerate(parts, start=1):
        match = re.match(r"^(\d+[\.\)]\s*|[-*]\s*)?(.*)$", part)
        prefix = (match.group(1) or f"{idx}. ") if match else f"{idx}. "
        body = (match.group(2) or part).strip() if match else part
        body = re.sub(r"\s*;\s*", ";<br>", _html_escape(body))
        body = re.sub(r"\s+-\s+", "<br>", body)
        rows += (
            '<div style="display:grid;grid-template-columns:34px 1fr;gap:10px;align-items:start;'
            'background:#0d1117;border:1px solid #30363d;border-radius:6px;padding:9px 11px;'
            'margin-bottom:8px">'
            f'<div style="color:#7d8590;font-family:\'Courier New\',monospace;font-size:0.72rem;'
            f'font-weight:700">{_html_escape(prefix.strip())}</div>'
            f'<div style="color:#c9d1d9;font-family:\'Courier New\',monospace;font-size:0.74rem;'
            f'line-height:1.6">{body}</div>'
            '</div>'
        )

    return (
        '<div class="detail-panel" style="border-color:#30363d">'
        '<div class="panel-title">Full Playbook Steps / Company-Specific SOAR Mapping</div>'
        f'{rows}</div>'
    )


def _detection_set(sel: dict) -> set[str]:
    raw = " | ".join([
        _safe(sel.get("detection_type"), ""),
        _safe(sel.get("all_detections"), ""),
        _safe(sel.get("identity_indicators"), ""),
    ]).lower()
    return {d.strip() for d in re.split(r"[|,;/\s]+", raw) if d.strip()}


def _has_detection(detections: set[str], name: str) -> bool:
    return name in detections or name.replace("_", "") in {d.replace("_", "") for d in detections}


def _get_ranked_next_moves(sel: dict) -> list[dict]:
    detections = _detection_set(sel)
    risk_level = _safe(sel.get("risk_level")).upper()
    risk_score = _safe_int(sel.get("risk_score"))
    fp_val = _safe_int(sel.get("false_positive_likelihood"))
    escalation = _safe(sel.get("escalation_decision")).upper()

    immediate = "ESCALATE_IMMEDIATELY" in escalation or risk_level == "CRITICAL" or risk_score >= 90
    escalated = "ESCALATE" in escalation or risk_level in ("CRITICAL", "HIGH")

    moves = []

    def add(key: str, title: str, confidence: int, why_first: str, playbook_action: str) -> None:
        if any(m["key"] == key for m in moves):
            return
        moves.append({
            "key": key,
            "title": title,
            "confidence": max(55, min(98, int(confidence))),
            "why_first": why_first,
            "playbook_action": playbook_action,
        })

    if immediate or escalated:
        add(
            "contain",
            "Escalate and contain identity session",
            95 if immediate else 88,
            "Rule evidence indicates a critical identity-risk chain requiring containment before further access can continue.",
            "Identity Provider / IAM + SOAR / Ticketing: revoke active sessions, require re-authentication, temporarily restrict privileged/admin access if applicable, and open identity containment workflow.",
        )

    validate_conf = 65
    if _has_detection(detections, "mfa_fatigue"):
        validate_conf += 20
    if fp_val >= 60:
        validate_conf += 15
    elif fp_val >= 35:
        validate_conf += 8
    if immediate:
        validate_conf += 5
    add(
        "validate",
        "Validate user intent out-of-band",
        validate_conf,
        (
            "High FP likelihood means validate business context before disruptive action unless additional telemetry confirms risk."
            if fp_val >= 60
            else "MFA, login, reset, or consent activity requires validation through a trusted channel before closure."
        ),
        "Identity Provider / IAM + SOAR / Ticketing: contact user or manager through a trusted channel, verify activity, temporarily disable push MFA if relevant, and move to stronger MFA where appropriate.",
    )

    if _has_detection(detections, "oauth_abuse") or _has_detection(detections, "mailbox_forwarding"):
        detail_parts = []
        if _has_detection(detections, "oauth_abuse"):
            detail_parts.append("revoke suspicious OAuth consent")
        if _has_detection(detections, "mailbox_forwarding"):
            detail_parts.append("remove mailbox forwarding/inbox rules")
        add(
            "persistence",
            "Remove persistence mechanisms",
            88 if len(detail_parts) > 1 else 84,
            "OAuth consent and mailbox rules can allow continued mailbox or SaaS access even after password resets.",
            "Identity Provider / IAM + Email Security / Mailbox Audit + CASB / SaaS Security: revoke suspicious app consent, remove mailbox forwarding/inbox rules, and review app consent logs.",
        )

    if _has_detection(detections, "mailbox_forwarding") or _has_detection(detections, "oauth_abuse") or _has_detection(detections, "admin_risky_login"):
        add(
            "impact",
            "Review mailbox and tenant impact",
            86 if immediate else 82,
            "The incident contains indicators that may affect mailbox integrity, outbound email, admin actions, or tenant-wide configuration.",
            "SIEM + Email Security / Mailbox Audit + Identity Provider / IAM: review mailbox access, forwarding destination, outbound email, admin actions, role changes, and MFA method changes.",
        )

    if _has_detection(detections, "admin_risky_login") and not immediate:
        add(
            "admin",
            "Verify and contain privileged account",
            90,
            "Privileged-account activity increases potential tenant-wide impact and should be validated quickly.",
            "Identity Provider / IAM + SIEM + SOAR / Ticketing: temporarily restrict privileged access if applicable, review admin actions, and escalate if unauthorized.",
        )

    if (_has_detection(detections, "unmanaged_device") or _has_detection(detections, "new_device_login")) and not immediate:
        add(
            "device",
            "Verify device ownership and compliance",
            78 + (6 if risk_level in ("CRITICAL", "HIGH") else 0),
            "New or unmanaged device access increases uncertainty and may bypass normal endpoint controls.",
            "MDM / Device Compliance + Identity Provider / IAM: confirm device ownership, enforce managed-device compliance, and require device enrollment before restoring access.",
        )

    if _has_detection(detections, "mfa_fatigue"):
        add(
            "mfa",
            "Disable or replace push MFA path",
            80,
            "MFA push denials followed by approval may indicate user fatigue, coercion, confusion, or unauthorized approval.",
            "Identity Provider / IAM + SOAR / Ticketing: verify MFA approval, temporarily disable push MFA, and move to stronger MFA where appropriate.",
        )

    add(
        "harden",
        "Verify device ownership and harden access path",
        75 + (8 if risk_level == "CRITICAL" else 0),
        "New or unmanaged device access and identity control gaps should be addressed after immediate containment and validation.",
        "MDM / Device Compliance + Identity Provider / IAM: confirm device ownership, enforce managed-device access, strengthen MFA, and review Conditional Access gaps.",
    )

    if fp_val >= 60:
        moves.sort(key=lambda m: (m["key"] != "validate", -m["confidence"], m["title"]))
    elif immediate:
        moves.sort(key=lambda m: (m["key"] != "contain", -m["confidence"], m["title"]))
    else:
        moves.sort(key=lambda m: (-m["confidence"], m["title"]))
    return moves[:5]


def _render_ranked_next_moves(sel: dict) -> None:
    moves = _get_ranked_next_moves(sel)
    rows = ""
    for move in moves:
        rows += (
            '<div style="background:#0d1117;border:1px solid #30363d;border-radius:6px;'
            'padding:12px 14px;margin-bottom:10px">'
            '<div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:8px">'
            f'<span style="color:#bc8cff;background:rgba(188,140,255,0.12);border:1px solid rgba(188,140,255,0.25);'
            f'border-radius:4px;padding:3px 7px;font-family:\'Courier New\',monospace;font-size:0.72rem;'
            f'font-weight:700">{move["confidence"]}% Priority Confidence</span>'
            f'<span style="color:#e6edf3;font-family:\'Courier New\',monospace;font-size:0.8rem;'
            f'font-weight:700">{_html_escape(move["title"])}</span>'
            '</div>'
            '<div style="display:grid;grid-template-columns:minmax(120px,180px) 1fr;gap:8px 12px;'
            'font-family:\'Courier New\',monospace;font-size:0.72rem;line-height:1.55">'
            '<div style="color:#7d8590;font-weight:700">Why first:</div>'
            f'<div style="color:#c9d1d9">{_html_escape(move["why_first"])}</div>'
            '<div style="color:#7d8590;font-weight:700">Suggested SOAR / Playbook Action:</div>'
            f'<div style="color:#c9d1d9">{_html_escape(move["playbook_action"])}</div>'
            '</div>'
            '</div>'
        )
    st.markdown(
        '<div class="detail-panel" style="border-color:#30363d">'
        '<div class="panel-title">Recommended Next Moves</div>'
        f'{rows}'
        '<div style="color:#7d8590;font-family:\'Courier New\',monospace;font-size:0.66rem;'
        'line-height:1.5;margin-top:4px">Priority confidence is based on deterministic rule evidence and should guide first-response sequencing. '
        'It is not a final probability of compromise.</div>'
        '</div>',
        unsafe_allow_html=True,
    )


def _zero_trust_text_html(zero_trust_gaps: str) -> str:
    rows = ""
    for line in str(zero_trust_gaps).replace(" | ", "\n").splitlines():
        text = line.strip()
        if not text:
            continue
        if ":" in text:
            pillar, gap = text.split(":", 1)
        else:
            pillar, gap = "Control", text
        rows += (
            '<tr style="background:#161b22">'
            f'<td style="color:#bc8cff;font-family:\'Courier New\',monospace;font-size:0.72rem;'
            f'font-weight:600;padding:7px 10px;border-bottom:1px solid #21262d;white-space:nowrap">'
            f'{_html_escape(pillar.strip())}</td>'
            f'<td style="color:#c9d1d9;font-family:\'Courier New\',monospace;font-size:0.72rem;'
            f'line-height:1.5;padding:7px 10px;border-bottom:1px solid #21262d">'
            f'{_html_escape(gap.strip())}</td>'
            '</tr>'
        )
    return (
        '<div style="background:#161b22;border:1px solid #30363d;border-radius:6px;overflow-x:auto">'
        '<table style="width:100%;border-collapse:collapse">'
        '<thead><tr style="background:#0d1117">'
        '<th style="color:#7d8590;font-family:\'Courier New\',monospace;font-size:0.6rem;text-transform:uppercase;'
        'padding:6px 10px;border-bottom:1px solid #30363d;text-align:left">Pillar</th>'
        '<th style="color:#7d8590;font-family:\'Courier New\',monospace;font-size:0.6rem;text-transform:uppercase;'
        'padding:6px 10px;border-bottom:1px solid #30363d;text-align:left">Gap</th>'
        '</tr></thead>'
        f'<tbody>{rows}</tbody></table></div>'
    )


# ---------------------------------------------------------------------------
# Main tab renderer
# ---------------------------------------------------------------------------

def render_identity_guard_tab() -> None:
    """Render the complete IdentityGuard AI tab. Called from dashboard.py."""

    st.markdown(
        '<div style="font-family:\'Courier New\',monospace;font-size:0.9rem;font-weight:600;'
        'color:#bc8cff;letter-spacing:0.1em;text-transform:uppercase;margin-bottom:4px">'
        'IdentityGuard AI</div>'
        '<div style="font-family:\'Courier New\',monospace;font-size:0.7rem;color:#7d8590;'
        'letter-spacing:0.05em;margin-bottom:16px">'
        'Account Takeover Triage &bull; Identity Risk Detection</div>',
        unsafe_allow_html=True,
    )

    # ── Load data ──
    st.caption("Use this tab for identity-risk deep dives after SOC triage.")

    df_ig, is_demo = _load_or_generate()

    if is_demo:
        st.info(
            "Showing 12 built-in demo identity incidents. "
            "Run `python run_identity_triage.py` to regenerate or upload your own identity_alerts.csv."
        )

    if df_ig.empty:
        st.error("No identity alert data found and demo generation failed.")
        return

    _render_identity_control_panel()

    # Normalise numeric columns
    df_ig["risk_score"] = pd.to_numeric(df_ig.get("risk_score", 0), errors="coerce").fillna(0).astype(int)
    df_ig["false_positive_likelihood"] = pd.to_numeric(
        df_ig.get("false_positive_likelihood", 0), errors="coerce"
    ).fillna(0).astype(int)
    for col in ["status", "risk_level", "detection_type", "escalation_decision",
                "all_detections", "identity_indicators", "user", "incident_id",
                "confidence", "mitre_techniques", "scoring_reasons",
                "recommended_actions", "ai_summary", "analyst_notes", "created_at"]:
        if col not in df_ig.columns:
            df_ig[col] = ""
        df_ig[col] = df_ig[col].fillna("").astype(str)

    # ── IdentityGuard filters ──
    st.markdown('<div class="section-hdr">IdentityGuard Filters</div>', unsafe_allow_html=True)

    ig_risk_opts = ["All", "CRITICAL", "HIGH", "MEDIUM", "LOW"]
    ig_status_opts = ["All"] + IG_STATUS_OPTIONS
    det_values = sorted({
        d.strip()
        for cell in df_ig["detection_type"].dropna()
        for d in str(cell).split("|")
        if d.strip()
    })

    ig_f1, ig_f2, ig_f3, ig_f4 = st.columns([2, 1, 1, 1])
    with ig_f1:
        ig_search = st.text_input(
            "Search",
            placeholder="ID / user / detection",
            key="ig_search",
        )
    with ig_f2:
        ig_sel_risk = st.selectbox("IG Risk Level", ig_risk_opts, key="ig_risk_filter")
    with ig_f3:
        ig_sel_status = st.selectbox("IG Status", ig_status_opts, key="ig_status_filter")
    with ig_f4:
        ig_sel_det = st.selectbox("Detection Type", ["All"] + det_values, key="ig_det_filter")

    st.markdown("<hr class='soc-divider'>", unsafe_allow_html=True)

    # ── Apply filters ──
    dff = df_ig.copy()
    if ig_sel_risk != "All":
        dff = dff[dff["risk_level"].str.upper() == ig_sel_risk]
    if ig_sel_status != "All":
        dff = dff[dff["status"].str.upper() == ig_sel_status.upper()]
    if ig_sel_det != "All":
        dff = dff[dff["detection_type"].str.contains(ig_sel_det, case=False, na=False)]
    if ig_search.strip():
        q = ig_search.strip().lower()
        mask = (
            dff["incident_id"].str.lower().str.contains(q, na=False)
            | dff["user"].str.lower().str.contains(q, na=False)
            | dff["detection_type"].str.lower().str.contains(q, na=False)
            | dff["all_detections"].str.lower().str.contains(q, na=False)
        )
        dff = dff[mask]

    dff = dff.sort_values("risk_score", ascending=False)

    # ── KPI strip ──
    total_ig   = len(dff)
    crit_count = len(dff[dff["risk_level"] == "CRITICAL"])
    high_count = len(dff[dff["risk_level"] == "HIGH"])
    esc_count  = len(dff[dff["escalation_decision"].str.contains("ESCALATE", na=False)])
    avg_fp     = dff["false_positive_likelihood"].mean() if not dff.empty else 0

    k1, k2, k3, k4, k5 = st.columns(5)
    k1.metric("Identity Incidents", total_ig)
    k2.metric("CRITICAL",           crit_count)
    k3.metric("HIGH",               high_count)
    k4.metric("Needs Escalation",   esc_count)
    k5.metric("Avg FP Likelihood",  f"{avg_fp:.0f}%")

    st.markdown("<br>", unsafe_allow_html=True)

    # ── Alert queue ──
    st.markdown(
        f'<div class="section-hdr">Identity Incident Queue <span>{len(dff)} incidents</span></div>',
        unsafe_allow_html=True,
    )

    if dff.empty:
        st.warning("No identity incidents match the current filters.")
        return

    queue_cols = [c for c in [
        "incident_id", "user", "detection_type", "risk_score",
        "risk_level", "confidence", "false_positive_likelihood",
        "escalation_decision", "status", "created_at",
    ] if c in dff.columns]

    def _clr_risk(v):
        return {
            "CRITICAL": "color:#f85149;font-weight:bold",
            "HIGH":     "color:#f0883e;font-weight:bold",
            "MEDIUM":   "color:#d29922",
            "LOW":      "color:#3fb950",
        }.get(str(v).upper(), "")

    def _clr_esc(v):
        if "IMMEDIATELY" in str(v): return "color:#f85149;font-weight:bold"
        if "ESCALATE"    in str(v): return "color:#f0883e;font-weight:bold"
        return ""

    styled = dff[queue_cols].style.map(_clr_risk, subset=["risk_level"]).map(
        _clr_esc, subset=["escalation_decision"]
    )
    st.dataframe(styled, use_container_width=True, hide_index=True, height=300)

    st.markdown("<hr class='soc-divider'>", unsafe_allow_html=True)

    # ── Incident selector ──
    st.markdown('<div class="section-hdr">Incident Snapshot</div>', unsafe_allow_html=True)
    st.markdown('<div class="section-hdr">Incident Detail</div>', unsafe_allow_html=True)

    ids = dff["incident_id"].tolist()

    def _fmt(iid):
        r   = dff[dff["incident_id"] == iid].iloc[0]
        usr = str(r.get("user", "")).split("@")[0]
        return f"{iid}  ·  {r.get('risk_level','')}  ·  {usr}  ·  {r.get('detection_type','')}"

    sel_id = st.selectbox(
        "Select Identity Incident",
        options=ids,
        index=0,
        format_func=_fmt,
        label_visibility="collapsed",
        key="ig_incident_selector",
    )

    sel = dff[dff["incident_id"] == sel_id].iloc[0].to_dict()

    risk_val  = _safe(sel.get("risk_level"))
    score_val = _safe_int(sel.get("risk_score"))
    fp_val    = _safe_int(sel.get("false_positive_likelihood"))
    fp_color  = "#3fb950" if fp_val >= 60 else "#d29922" if fp_val >= 35 else "#f85149"
    sc_color  = _RISK_COLOR.get(risk_val, "#c9d1d9")

    # ── 2-col detail ──
    col_a, col_b = st.columns(2)

    with col_a:
        st.markdown(f"""
        <div class="detail-panel" style="border-color:rgba(188,140,255,0.4)">
          <div class="panel-title">Identity Incident Overview</div>
          <div class="field-row">
            <span class="field-label">Incident ID</span>
            <span class="field-value" style="color:#bc8cff">{_safe(sel.get("incident_id"))}</span>
          </div>
          <div class="field-row">
            <span class="field-label">User</span>
            <span class="field-value">{_safe(sel.get("user"))}</span>
          </div>
          <div class="field-row">
            <span class="field-label">Risk Score</span>
            <span class="field-value" style="color:{sc_color};font-size:1.1rem;font-weight:700">{score_val} / 100</span>
          </div>
          <div class="field-row">
            <span class="field-label">Risk Level</span>
            <span class="field-value">{_risk_badge(risk_val)}</span>
          </div>
          <div class="field-row">
            <span class="field-label">Confidence</span>
            <span class="field-value">{_safe(sel.get("confidence"))}</span>
          </div>
          <div class="field-row">
            <span class="field-label">FP Likelihood</span>
            <span class="field-value" style="color:{fp_color}">{fp_val}%</span>
          </div>
          <div class="field-row">
            <span class="field-label">Status</span>
            <span class="field-value">{_status_badge(_safe(sel.get("status")))}</span>
          </div>
          <div class="field-row">
            <span class="field-label">Created</span>
            <span class="field-value muted">{_safe(sel.get("created_at",""))[:19].replace("T"," ")}</span>
          </div>
        </div>
        """, unsafe_allow_html=True)

    with col_b:
        esc      = _safe(sel.get("escalation_decision"))
        esc_col  = "#f85149" if "IMMEDIATELY" in esc else "#f0883e" if "ESCALATE" in esc else "#d29922" if "REVIEW" in esc else "#3fb950"
        dets     = _safe(sel.get("all_detections", _safe(sel.get("identity_indicators"))))
        mitre    = _safe(sel.get("mitre_techniques"))
        mitre_lines = mitre.replace(" | ", "<br>") if mitre != "—" else "—"

        st.markdown(f"""
        <div class="detail-panel">
          <div class="panel-title">Detection Summary</div>
          <div class="field-row">
            <span class="field-label">Primary Detection</span>
            <span class="field-value" style="color:#bc8cff">{_safe(sel.get("detection_type"))}</span>
          </div>
          <div class="field-row">
            <span class="field-label">All Detections</span>
            <span class="field-value" style="font-size:0.68rem">{dets}</span>
          </div>
          <div class="field-row">
            <span class="field-label">Escalation</span>
            <span class="field-value" style="color:{esc_col};font-weight:600">{esc}</span>
          </div>
          <div style="border-top:1px solid #21262d;margin:8px 0"></div>
          <div class="panel-title" style="margin-top:4px">MITRE ATT&amp;CK</div>
          <div style="font-family:'Courier New',monospace;font-size:0.68rem;color:#c9d1d9;line-height:1.8">
            {mitre_lines}
          </div>
        </div>
        """, unsafe_allow_html=True)

    # ── Event timeline ──
    st.markdown("<hr class='soc-divider'>", unsafe_allow_html=True)
    st.markdown('<div class="section-hdr">Analyst Decision</div>', unsafe_allow_html=True)

    # ── Risk score breakdown ──

    # ── Recommended actions ──
    rec = _safe(sel.get("recommended_actions"), "No recommended actions available.")
    _render_ranked_next_moves(sel)

    # ── FP analysis ──
    if fp_val >= 60:
        fp_class = "decision-review"
        fp_msg   = f"[~] HIGH FP likelihood ({fp_val}%) — verify with user before containment."
    elif fp_val >= 35:
        fp_class = "decision-validate"
        fp_msg   = f"[?] MODERATE FP likelihood ({fp_val}%) — validate business context before escalating."
    else:
        fp_class = "decision-escalate"
        fp_msg   = f"[!] LOW FP likelihood ({fp_val}%) — rule evidence strongly supports this detection."

    st.markdown(
        f'<div class="{fp_class}" style="margin-bottom:12px">{fp_msg}</div>',
        unsafe_allow_html=True,
    )

    # ── Zero Trust gaps (placeholder — populated in Phase 3b) ──
    # â”€â”€ Analyst status update â”€â”€
    # â”€â”€ Analyst status update â”€â”€
    st.markdown('<div class="section-hdr">Analyst Status Update</div>', unsafe_allow_html=True)

    curr_status = _safe(sel.get("status", "NEW")).upper()
    if curr_status not in IG_STATUS_OPTIONS:
        curr_status = "NEW"

    sc1, sc2 = st.columns([2, 1])
    with sc1:
        new_status = st.selectbox(
            "Set Status",
            IG_STATUS_OPTIONS,
            index=IG_STATUS_OPTIONS.index(curr_status),
            key=f"ig_status_sel_{sel_id}",
        )
        analyst_note = st.text_input(
            "Analyst Note (optional)",
            placeholder="Add context for the next analyst...",
            key=f"ig_note_{sel_id}",
        )
    with sc2:
        st.markdown("<br><br>", unsafe_allow_html=True)
        if st.button("Save Status", use_container_width=True, key=f"ig_save_{sel_id}"):
            from identityguard.identity_csv_exporter import update_status
            ok = update_status(sel_id, new_status, analyst_note, str(IDENTITY_CSV_PATH))
            if ok:
                st.success(f"Updated {sel_id} -> {new_status}.")
                st.rerun()
            else:
                st.error("Update failed. Ensure identity_alerts.csv exists.")

    st.caption("Status is analyst-controlled. The scoring engine sets risk; analysts set operational state.")

    with st.expander("Full Playbook Steps / Company-Specific SOAR Mapping", expanded=False):
        st.caption(
            "These steps are generic response guidance. In production, they should map to the "
            "organization's approved SOAR playbooks, escalation procedures, and control owners."
        )
        st.markdown(_recommended_actions_html(rec), unsafe_allow_html=True)

    st.markdown("<hr class='soc-divider'>", unsafe_allow_html=True)

    st.markdown('<div class="section-hdr">Supporting Evidence</div>', unsafe_allow_html=True)

    # â”€â”€ Event timeline â”€â”€
    st.markdown('<div class="section-hdr">Identity Event Timeline</div>', unsafe_allow_html=True)
    st.markdown(_event_timeline_html(sel_id), unsafe_allow_html=True)
    st.markdown("<br>", unsafe_allow_html=True)

    # â”€â”€ Risk score breakdown â”€â”€
    st.markdown('<div class="section-hdr">Risk Score Breakdown</div>', unsafe_allow_html=True)
    st.markdown(_scoring_html(_safe(sel.get("scoring_reasons"))), unsafe_allow_html=True)
    st.markdown("<br>", unsafe_allow_html=True)

    with st.expander("Control Gaps / Hardening Notes", expanded=False):
        st.caption(
            "Used for post-incident hardening and manager review. "
            "Immediate response should follow the Analyst Decision section above."
        )
        zt = _safe(sel.get("zero_trust_gaps"))
        if zt and zt != "—":
            st.markdown(_zero_trust_text_html(zt), unsafe_allow_html=True)
        else:
            det_type = _safe(sel.get("detection_type"))
            _render_zero_trust_gaps(det_type)

    # ── AI analyst summary (on-demand) ──
    st.markdown("<hr class='soc-divider'>", unsafe_allow_html=True)
    st.markdown('<div class="section-hdr">Reporting &amp; Export</div>', unsafe_allow_html=True)
    _render_ai_summary_panel(sel_id, sel)

    st.markdown("<hr class='soc-divider'>", unsafe_allow_html=True)

    # ── Analyst handoff report ──
    handoff_text = _build_handoff(sel)

    with st.expander("Analyst Handoff Report", expanded=False):
        st.text_area(
            "Copy-ready handoff",
            value=handoff_text,
            height=350,
            label_visibility="collapsed",
            key=f"ig_handoff_area_{sel_id}",
        )
        st.caption(
            "Copy into ticketing, escalation channel, or shift handoff notes."
        )

    # ── Incident Report Export (Phase 5) ──
    with st.expander("Export Incident Report", expanded=False):
        st.caption(
            "Exports use the currently selected incident and cached AI summary (if available). "
            "No API calls are made during export."
        )
        try:
            from identityguard.identity_report_writer import get_markdown_bytes, get_json_bytes
            ts_now = datetime.now().strftime("%Y%m%d_%H%M%S")
            md_bytes   = get_markdown_bytes(sel)
            json_bytes = get_json_bytes(sel)
            rpt_c1, rpt_c2 = st.columns(2)
            with rpt_c1:
                st.download_button(
                    "Download Markdown Report",
                    data=md_bytes,
                    file_name=f"ig_report_{sel_id}_{ts_now}.md",
                    mime="text/markdown",
                    use_container_width=True,
                    key="ig_md_dl",
                )
            with rpt_c2:
                st.download_button(
                    "Download JSON Report",
                    data=json_bytes,
                    file_name=f"ig_report_{sel_id}_{ts_now}.json",
                    mime="application/json",
                    use_container_width=True,
                    key="ig_json_dl",
                )
        except Exception as _export_err:
            st.error(f"Report generation error: {_export_err}")

    st.markdown("<hr class='soc-divider'>", unsafe_allow_html=True)

    # ── Analyst status update ──
    # ── Export row ──
    st.markdown('<div class="section-hdr">Export</div>', unsafe_allow_html=True)
    ex1, ex2 = st.columns(2)
    with ex1:
        st.download_button(
            "Export Filtered View (CSV)",
            data=dff.to_csv(index=False).encode("utf-8"),
            file_name=f"identityguard_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv",
            use_container_width=True,
            key="ig_csv_dl",
        )
    with ex2:
        st.download_button(
            "Export Handoff Report (TXT)",
            data=handoff_text.encode("utf-8"),
            file_name=f"ig_handoff_{sel_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
            mime="text/plain",
            use_container_width=True,
            key="ig_txt_dl",
        )

    # ── Footer ──
    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown(
        '<div style="font-family:\'Courier New\',monospace;font-size:0.62rem;'
        'color:#30363d;text-align:center;letter-spacing:0.08em">'
        'IDENTITYGUARD AI &bull; ACCOUNT TAKEOVER TRIAGE &bull; DETERMINISTIC RULES'
        '</div>',
        unsafe_allow_html=True,
    )


# ---------------------------------------------------------------------------
# Zero Trust gap descriptions (deterministic, no AI needed)
# ---------------------------------------------------------------------------

_ZT_MAP = {
    "impossible_travel": {
        "Identity":     "Continuous access evaluation was not triggered by location anomaly.",
        "Devices":      "Device posture was not re-checked after geographic impossibility.",
        "Networks":     "No network-based conditional access blocked the foreign IP.",
        "Applications": "No step-up authentication was required despite risk signal.",
        "Data":         "Sensitive resources may have been accessed from untrusted location.",
    },
    "mfa_fatigue": {
        "Identity":     "MFA method (push notification) is vulnerable to approval fatigue.",
        "Devices":      "Device compliance was not enforced as a fallback control.",
        "Applications": "App did not enforce number matching or additional context in push.",
        "Data":         "Account access achieved without verifying user intent.",
    },
    "unmanaged_device": {
        "Devices":      "Unmanaged device was allowed to access corporate resources.",
        "Identity":     "Conditional Access policy did not enforce device compliance.",
        "Data":         "No DLP controls exist on unmanaged device; data at risk of exfiltration.",
    },
    "oauth_abuse": {
        "Applications": "OAuth app consent was granted without admin pre-approval.",
        "Identity":     "No policy restricted third-party app permission scopes.",
        "Data":         "Mail.Read/ReadWrite grants persistent access to email even post-password-reset.",
    },
    "mailbox_forwarding": {
        "Data":         "Inbox rule enables silent email exfiltration to external address.",
        "Applications": "No alert fired when mail forwarding rule was created.",
        "Identity":     "Attacker session persisted long enough to modify mailbox settings.",
    },
    "admin_risky_login": {
        "Identity":     "Privileged account authenticated without Privileged Identity Management (PIM).",
        "Devices":      "Admin access was permitted from unmanaged/unverified device.",
        "Applications": "Admin portal lacked step-up authentication for high-risk login.",
    },
}

_DEFAULT_ZT = {
    "Identity":     "Review Conditional Access policies for this account.",
    "Devices":      "Enforce device compliance as an access condition.",
    "Applications": "Audit application permissions and consent grants.",
}


def _render_zero_trust_gaps(detection_type: str) -> None:
    """Render Zero Trust pillar gaps for the current detection type."""
    gaps = _ZT_MAP.get(detection_type, _DEFAULT_ZT)
    pillar_colors = {
        "Identity":     "#bc8cff",
        "Devices":      "#388bfd",
        "Networks":     "#3fb950",
        "Applications": "#f0883e",
        "Data":         "#f85149",
    }
    rows_html = ""
    for pillar, desc in gaps.items():
        color = pillar_colors.get(pillar, "#7d8590")
        rows_html += (
            '<tr style="background:#161b22">'
            f'<td style="color:{color};font-family:\'Courier New\',monospace;font-size:0.72rem;'
            f'font-weight:600;padding:7px 10px;border-bottom:1px solid #21262d;white-space:nowrap">{pillar}</td>'
            f'<td style="color:#c9d1d9;font-family:\'Courier New\',monospace;font-size:0.72rem;'
            f'line-height:1.5;padding:7px 10px;border-bottom:1px solid #21262d">{desc}</td>'
            '</tr>'
        )
    st.markdown(
        '<div style="background:#161b22;border:1px solid #30363d;border-radius:6px;overflow-x:auto">'
        '<table style="width:100%;border-collapse:collapse">'
        '<thead><tr style="background:#0d1117">'
        '<th style="color:#7d8590;font-family:\'Courier New\',monospace;font-size:0.6rem;text-transform:uppercase;'
        'padding:6px 10px;border-bottom:1px solid #30363d;text-align:left">Pillar</th>'
        '<th style="color:#7d8590;font-family:\'Courier New\',monospace;font-size:0.6rem;text-transform:uppercase;'
        'padding:6px 10px;border-bottom:1px solid #30363d;text-align:left">Gap</th>'
        '</tr></thead>'
        f'<tbody>{rows_html}</tbody></table></div>',
        unsafe_allow_html=True,
    )


# ---------------------------------------------------------------------------
# Handoff report builder
# ---------------------------------------------------------------------------

def _extract_mitre_ids(mitre_text: str) -> list[str]:
    ids = re.findall(r"\bT\d{4}(?:\.\d{3})?\b", _safe(mitre_text, ""))
    return list(dict.fromkeys(ids))


def _build_why_this_matters(sel: dict) -> list[str]:
    detections = _detection_set(sel)
    bullets = []
    if _has_detection(detections, "mfa_fatigue"):
        bullets.append("MFA push denials were followed by a successful approval.")
    if _has_detection(detections, "new_device_login") or _has_detection(detections, "unmanaged_device"):
        bullets.append("Access came from an unmanaged or unrecognized device.")
    if _has_detection(detections, "oauth_abuse"):
        bullets.append("OAuth consent may provide persistent SaaS or mailbox access.")
    if _has_detection(detections, "mailbox_forwarding"):
        bullets.append("Mailbox forwarding may indicate possible email exfiltration or BEC preparation.")
    if _has_detection(detections, "admin_risky_login"):
        bullets.append("Privileged/admin risk increases potential tenant-wide impact.")
    if _has_detection(detections, "impossible_travel"):
        bullets.append("Impossible travel or location anomaly indicates the session may not belong to the expected user.")
    if _has_detection(detections, "password_reset_risky_login"):
        bullets.append("Password reset followed by risky login can indicate account recovery abuse or lockout activity.")
    if not bullets:
        bullets.append("Rule evidence indicates identity activity that requires analyst validation.")
    return bullets[:5]


def _build_validation_checklist(sel: dict) -> list[str]:
    detections = _detection_set(sel)
    base_items = [
        "Confirm with the user or manager whether MFA approval, login, password reset, or app consent was legitimate.",
        "SIEM: validate sign-in timeline, source IP, device ID, and related alerts.",
        "Identity Provider / IAM: review session activity, MFA method changes, role changes, and conditional access events.",
    ]
    evidence_items = []
    if _has_detection(detections, "mailbox_forwarding"):
        evidence_items.append(
            "Email Security / Mailbox Audit: review forwarding rules, mailbox access, forwarding destination, and outbound email."
        )
    if _has_detection(detections, "oauth_abuse") or _has_detection(detections, "mailbox_forwarding"):
        evidence_items.append("CASB / SaaS Security: review suspicious app consent and SaaS access.")
    if _has_detection(detections, "admin_risky_login"):
        evidence_items.append("Identity Provider / IAM + SIEM: review recent admin actions, role changes, and privileged access activity.")
    if _has_detection(detections, "unmanaged_device") or _has_detection(detections, "new_device_login"):
        evidence_items.append("MDM / Device Compliance: verify device ownership and compliance state.")
    if _has_detection(detections, "mfa_fatigue"):
        evidence_items.append("Identity Provider / IAM: review MFA prompt history and MFA method changes.")

    items = base_items + evidence_items[:2]
    if len(items) < 5:
        items.append("Network / Proxy Logs: compare activity timing, source network, and business context.")
    items.append("SOAR / Ticketing: escalate if activity is unauthorized or cannot be validated quickly.")
    return items[:6]


def _build_identity_handoff_summary(sel: dict) -> str:
    detections = _detection_set(sel)
    phrases = []
    if _has_detection(detections, "mfa_fatigue"):
        phrases.append("MFA fatigue")
    if _has_detection(detections, "new_device_login") or _has_detection(detections, "unmanaged_device"):
        phrases.append("successful access from an unmanaged or unrecognized device")
    if _has_detection(detections, "oauth_abuse"):
        phrases.append("high-risk OAuth consent")
    if _has_detection(detections, "mailbox_forwarding"):
        phrases.append("mailbox forwarding or inbox rule creation")
    if _has_detection(detections, "password_reset_risky_login"):
        phrases.append("password reset activity tied to risky login behavior")
    if _has_detection(detections, "admin_risky_login"):
        phrases.append("privileged/admin risk indicators")
    if _has_detection(detections, "impossible_travel"):
        phrases.append("impossible travel or location anomaly")
    if not phrases:
        phrases.append(_safe(sel.get("detection_type"), "identity risk activity"))

    pattern = ", ".join(phrases[:-1]) + f", and {phrases[-1]}" if len(phrases) > 1 else phrases[0]
    escalation = _safe(sel.get("escalation_decision"))
    risk_level = _safe(sel.get("risk_level"))
    if "IMMEDIATELY" in escalation.upper() or risk_level.upper() == "CRITICAL":
        return (
            f"Rule evidence indicates a possible multi-stage account takeover involving {pattern}. "
            "This requires immediate validation and containment because persistence or tenant-impact indicators may be present."
        )
    return (
        f"Rule evidence indicates possible identity-risk activity involving {pattern}. "
        f"The current escalation decision is {escalation}, so the handoff should prioritize validation, containment if unauthorized, and impact review."
    )


def _get_handoff_ai_summary(sel: dict) -> str:
    csv_summary = _safe(sel.get("ai_summary"), "")
    if csv_summary and csv_summary != "—":
        return csv_summary
    cached = _get_cached_handoff_summary(sel.get("incident_id", ""))
    if cached.startswith("("):
        return "AI summary not generated."
    return cached or "AI summary not generated."


def _build_handoff(sel: dict) -> str:
    moves = _get_ranked_next_moves(sel)
    top_move = moves[0] if moves else {
        "title": "Validate identity activity",
        "confidence": 65,
        "playbook_action": "SIEM + Identity Provider / IAM: review identity telemetry and confirm user intent before closing or escalating.",
    }
    why = "\n".join(f"- {item}" for item in _build_why_this_matters(sel))
    checklist = "\n".join(f"{idx}. {item}" for idx, item in enumerate(_build_validation_checklist(sel), start=1))
    mitre_ids = _extract_mitre_ids(_safe(sel.get("mitre_techniques"), ""))
    mitre_text = ", ".join(mitre_ids) if mitre_ids else "None mapped."
    notes = _safe(sel.get("analyst_notes"), "")
    notes = notes if notes and notes != "—" else "(none)"

    return f"""IdentityGuard AI -- Analyst Handoff

Incident: {_safe(sel.get("incident_id"))}
User: {_safe(sel.get("user"))}
Risk: {_safe(sel.get("risk_level"))} | Score: {_safe_int(sel.get("risk_score"))}/100 | FP Likelihood: {_safe_int(sel.get("false_positive_likelihood"))}%
Status: {_safe(sel.get("status"))} | Escalation: {_safe(sel.get("escalation_decision"))}

Summary:
{_build_identity_handoff_summary(sel)}

Why This Matters:
{why}

Recommended First Move:
{top_move["confidence"]}% Priority Confidence -- {top_move["title"]}.
Suggested SOAR / Playbook Action: {top_move["playbook_action"]}

Validation Checklist:
{checklist}

MITRE:
{mitre_text}

AI Analyst Summary:
{_get_handoff_ai_summary(sel)}

Analyst Notes:
{notes}
"""

def _build_handoff_legacy(sel: dict) -> str:
    return f"""IdentityGuard AI -- Analyst Handoff Report
Generated: {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")}

INCIDENT : {_safe(sel.get("incident_id"))}
USER     : {_safe(sel.get("user"))}
RISK     : {_safe(sel.get("risk_level"))} (Score: {_safe_int(sel.get("risk_score"))}/100)
STATUS   : {_safe(sel.get("status"))}
ESCALATION: {_safe(sel.get("escalation_decision"))}

DETECTIONS:
{_safe(sel.get("all_detections", _safe(sel.get("identity_indicators"))))}

MITRE ATT&CK TECHNIQUES:
{_safe(sel.get("mitre_techniques"))}

RISK SCORING BREAKDOWN:
{_safe(sel.get("scoring_reasons"))}

FALSE POSITIVE LIKELIHOOD: {_safe_int(sel.get("false_positive_likelihood"))}%

RECOMMENDED ACTIONS:
{_safe(sel.get("recommended_actions"))}

AI ANALYST SUMMARY:
{_safe(sel.get("ai_summary")) if _safe(sel.get("ai_summary")) not in ("", "—") else _get_cached_handoff_summary(sel.get("incident_id", ""))}

ANALYST NOTES:
{_safe(sel.get("analyst_notes")) if _safe(sel.get("analyst_notes")) not in ("", "—") else "(none)"}
"""
