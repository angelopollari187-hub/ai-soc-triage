"""
IdentityGuard AI — Incident Report Writer (Phase 5)

Generates Markdown and JSON incident reports for a selected IdentityGuard incident.
Reports are saved under output/identity_reports/.

No API calls are made here. AI summary is read from the cache only.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

BASE_DIR = Path(__file__).resolve().parent.parent
REPORTS_DIR = BASE_DIR / "output" / "identity_reports"
AI_SUMMARIES_PATH = BASE_DIR / "output" / "identity_ai_summaries.json"
SAMPLE_EVENTS_PATH = BASE_DIR / "identityguard" / "sample_events" / "demo_incidents.json"


def _safe(val: Any, fallback: str = "—") -> str:
    if val is None:
        return fallback
    s = str(val).strip()
    return s if s not in ("", "nan", "None") else fallback


def _safe_int(val: Any, fallback: int = 0) -> int:
    try:
        return int(float(val))
    except Exception:
        return fallback


def _load_cached_ai_summary(incident_id: str) -> dict | None:
    """Return the cached AI summary dict for incident_id, or None."""
    if not AI_SUMMARIES_PATH.exists():
        return None
    try:
        with open(AI_SUMMARIES_PATH, "r", encoding="utf-8") as f:
            cache = json.load(f)
        entry = cache.get(incident_id)
        if entry and isinstance(entry.get("summary"), dict):
            return {
                "summary": entry["summary"],
                "generated_at": entry.get("generated_at", ""),
            }
    except Exception:
        pass
    return None


def _load_event_timeline(incident_id: str) -> list[dict]:
    """Return raw event list from demo_incidents.json, or []."""
    if not SAMPLE_EVENTS_PATH.exists():
        return []
    try:
        with open(SAMPLE_EVENTS_PATH, "r", encoding="utf-8") as f:
            incidents = json.load(f)
        inc = next((i for i in incidents if i["incident_id"] == incident_id), None)
        return inc.get("events", []) if inc else []
    except Exception:
        return []


def _zt_gaps_for_detection(detection_type: str) -> dict[str, str]:
    """Return Zero Trust gap dict for a given detection type (mirrors identity_dashboard.py)."""
    _ZT_MAP = {
        "impossible_travel": {
            "Identity": "Continuous access evaluation was not triggered by location anomaly.",
            "Devices": "Device posture was not re-checked after geographic impossibility.",
            "Networks": "No network-based conditional access blocked the foreign IP.",
            "Applications": "No step-up authentication was required despite risk signal.",
            "Data": "Sensitive resources may have been accessed from untrusted location.",
        },
        "mfa_fatigue": {
            "Identity": "MFA method (push notification) is vulnerable to approval fatigue.",
            "Devices": "Device compliance was not enforced as a fallback control.",
            "Applications": "App did not enforce number matching or additional context in push.",
            "Data": "Account access achieved without verifying user intent.",
        },
        "unmanaged_device": {
            "Devices": "Unmanaged device was allowed to access corporate resources.",
            "Identity": "Conditional Access policy did not enforce device compliance.",
            "Data": "No DLP controls exist on unmanaged device; data at risk of exfiltration.",
        },
        "oauth_abuse": {
            "Applications": "OAuth app consent was granted without admin pre-approval.",
            "Identity": "No policy restricted third-party app permission scopes.",
            "Data": "Mail.Read/ReadWrite grants persistent access to email even post-password-reset.",
        },
        "mailbox_forwarding": {
            "Data": "Inbox rule enables silent email exfiltration to external address.",
            "Applications": "No alert fired when mail forwarding rule was created.",
            "Identity": "Attacker session persisted long enough to modify mailbox settings.",
        },
        "admin_risky_login": {
            "Identity": "Privileged account authenticated without Privileged Identity Management (PIM).",
            "Devices": "Admin access was permitted from unmanaged/unverified device.",
            "Applications": "Admin portal lacked step-up authentication for high-risk login.",
        },
    }
    _DEFAULT_ZT = {
        "Identity": "Review Conditional Access policies for this account.",
        "Devices": "Enforce device compliance as an access condition.",
        "Applications": "Audit application permissions and consent grants.",
    }
    return _ZT_MAP.get(detection_type, _DEFAULT_ZT)


# ---------------------------------------------------------------------------
# Markdown report
# ---------------------------------------------------------------------------

def build_markdown_report(incident: dict) -> str:
    """Build a full Markdown incident report string from the incident row dict."""
    inc_id       = _safe(incident.get("incident_id"))
    user         = _safe(incident.get("user"))
    det_type     = _safe(incident.get("detection_type"))
    risk_score   = _safe_int(incident.get("risk_score"))
    risk_level   = _safe(incident.get("risk_level"))
    confidence   = _safe(incident.get("confidence"))
    fp_pct       = _safe_int(incident.get("false_positive_likelihood"))
    escalation   = _safe(incident.get("escalation_decision"))
    status       = _safe(incident.get("status"))
    all_dets     = _safe(incident.get("all_detections", incident.get("identity_indicators", "")))
    mitre        = _safe(incident.get("mitre_techniques"))
    scoring      = _safe(incident.get("scoring_reasons"))
    rec_actions  = _safe(incident.get("recommended_actions"))
    created_at   = _safe(incident.get("created_at", ""))[:19].replace("T", " ")
    generated_ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    events       = _load_event_timeline(inc_id)
    ai_data      = _load_cached_ai_summary(inc_id)
    zt_gaps      = _zt_gaps_for_detection(det_type)

    lines: list[str] = []

    # Header
    lines += [
        f"# IdentityGuard AI — Incident Report",
        f"",
        f"**Report Generated:** {generated_ts}  ",
        f"**Incident ID:** `{inc_id}`  ",
        f"**User:** {user}  ",
        f"**Created:** {created_at}  ",
        f"",
        f"---",
        f"",
    ]

    # Overview
    lines += [
        f"## Incident Overview",
        f"",
        f"| Field | Value |",
        f"|-------|-------|",
        f"| Incident ID | `{inc_id}` |",
        f"| User | {user} |",
        f"| Detection Type | {det_type} |",
        f"| All Detections | {all_dets} |",
        f"| Risk Score | **{risk_score} / 100** |",
        f"| Risk Level | **{risk_level}** |",
        f"| Confidence | {confidence} |",
        f"| False-Positive Likelihood | {fp_pct}% |",
        f"| Escalation Decision | {escalation} |",
        f"| Analyst Status | {status} |",
        f"| Created | {created_at} |",
        f"",
    ]

    # Event timeline
    lines += [
        f"## Event Timeline",
        f"",
    ]
    if events:
        lines += [
            f"| # | Time (UTC) | Event Type | Details |",
            f"|---|-----------|------------|---------|",
        ]
        for i, ev in enumerate(events, 1):
            ts      = _safe(ev.get("event_time", ""))[:19].replace("T", " ")
            etype   = _safe(ev.get("event_type", ""))
            action  = _safe(ev.get("action", ""))
            country = _safe(ev.get("country", ""))
            trust   = _safe(ev.get("device_trust_status", ""))
            mfa     = ev.get("mfa_result")
            mfa_s   = f"MFA:{mfa}" if mfa and str(mfa) not in ("None", "") else ""
            sig     = ev.get("risk_signal")
            sig_s   = f"signal:{sig}" if sig and str(sig) not in ("None", "") else ""
            detail  = " · ".join(filter(None, [country, trust, mfa_s, sig_s, action]))
            lines.append(f"| {i} | {ts} | {etype} | {detail} |")
        lines.append("")
    else:
        lines += [f"_No event timeline available for this incident._", f""]

    # Scoring reasons
    lines += [
        f"## Risk Score Breakdown",
        f"",
        f"```",
    ]
    for ln in scoring.splitlines():
        ln = ln.strip()
        if ln:
            lines.append(ln)
    lines += [f"```", f""]

    # False-positive considerations
    if fp_pct >= 60:
        fp_verdict = f"HIGH FP likelihood ({fp_pct}%) — verify with user before containment."
    elif fp_pct >= 35:
        fp_verdict = f"MODERATE FP likelihood ({fp_pct}%) — validate business context before escalating."
    else:
        fp_verdict = f"LOW FP likelihood ({fp_pct}%) — rule evidence strongly supports this detection."

    lines += [
        f"## False-Positive Considerations",
        f"",
        f"{fp_verdict}",
        f"",
    ]

    # MITRE ATT&CK
    lines += [f"## MITRE ATT&CK Mapping", f""]
    if mitre and mitre != "—":
        for tech in mitre.split(" | "):
            lines.append(f"- {tech.strip()}")
    else:
        lines.append("_No MITRE techniques mapped._")
    lines.append("")

    # Zero Trust gaps
    lines += [f"## Zero Trust Control Gaps", f""]
    for pillar, desc in zt_gaps.items():
        lines.append(f"**{pillar}:** {desc}")
    lines.append("")

    # Recommended actions
    lines += [f"## Recommended Actions", f""]
    for part in [p.strip() for p in rec_actions.replace("\n\n", "\n").split("\n") if p.strip()]:
        lines.append(f"- {part}")
    lines.append("")

    # AI summary
    lines += [f"## AI Analyst Summary", f""]
    if ai_data:
        s        = ai_data["summary"]
        gen_at   = str(ai_data.get("generated_at", ""))[:19].replace("T", " ")
        lines += [
            f"_Cached AI summary generated at {gen_at} UTC._",
            f"",
            f"**Analyst Summary:** {s.get('analyst_summary', '—')}",
            f"",
            f"**Likely Scenario:** {s.get('likely_scenario', '—')}",
            f"",
            f"**Why Flagged:** {s.get('why_flagged', '—')}",
            f"",
            f"**AI False-Positive Considerations:** {s.get('false_positive_considerations', '—')}",
            f"",
            f"**AI Confidence Assessment:** {s.get('confidence_assessment', '—')}",
            f"",
        ]
        rec_acts = s.get("recommended_analyst_actions", [])
        if rec_acts:
            lines.append("**Recommended Analyst Actions:**")
            for a in rec_acts:
                lines.append(f"- {a}")
            lines.append("")
        contain = s.get("containment_steps", [])
        if contain:
            lines.append("**Containment Steps:**")
            for c in contain:
                lines.append(f"- {c}")
            lines.append("")
        evidence = s.get("evidence_checklist", [])
        if evidence:
            lines.append("**Evidence Checklist:**")
            for e in evidence:
                lines.append(f"- {e}")
            lines.append("")
        uncertainty = s.get("uncertainty_notes", "")
        if uncertainty:
            lines += [f"**Uncertainty Notes:** {uncertainty}", f""]
    else:
        lines += [
            f"_No cached AI summary was available for this incident._",
            f"_To generate one, open the IdentityGuard AI tab in the dashboard and click "
            f"\"Generate AI Analyst Summary\"._",
            f"",
        ]

    # Ticket-ready handoff
    lines += [f"## Ticket-Ready Analyst Handoff", f""]
    if ai_data and ai_data["summary"].get("ticket_handoff"):
        lines += [
            f"```",
            ai_data["summary"]["ticket_handoff"],
            f"```",
            f"",
        ]
    else:
        # Fallback: build a minimal ticket block from raw fields
        lines += [
            f"```",
            f"INCIDENT : {inc_id}",
            f"USER     : {user}",
            f"RISK     : {risk_level} ({risk_score}/100)",
            f"STATUS   : {status}",
            f"ESCALATION: {escalation}",
            f"",
            f"DETECTIONS:",
            all_dets,
            f"",
            f"MITRE: {mitre}",
            f"",
            f"RECOMMENDED ACTIONS:",
            rec_actions,
            f"```",
            f"",
        ]

    lines += [
        f"---",
        f"",
        f"_Report generated by IdentityGuard AI · {generated_ts}_",
    ]

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# JSON report
# ---------------------------------------------------------------------------

def build_json_report(incident: dict) -> dict:
    """Build a structured JSON report dict from the incident row dict."""
    inc_id      = _safe(incident.get("incident_id"))
    det_type    = _safe(incident.get("detection_type"))
    events      = _load_event_timeline(inc_id)
    ai_data     = _load_cached_ai_summary(inc_id)
    zt_gaps     = _zt_gaps_for_detection(det_type)
    fp_pct      = _safe_int(incident.get("false_positive_likelihood"))
    mitre_raw   = _safe(incident.get("mitre_techniques"))
    mitre_list  = [t.strip() for t in mitre_raw.split(" | ") if t.strip() and mitre_raw != "—"]
    rec_raw     = _safe(incident.get("recommended_actions"))
    rec_list    = [p.strip() for p in rec_raw.replace("\n\n", "\n").split("\n") if p.strip()]
    scoring_raw = _safe(incident.get("scoring_reasons"))
    scoring_list = [ln.strip() for ln in scoring_raw.splitlines() if ln.strip()]

    if fp_pct >= 60:
        fp_verdict = f"HIGH FP likelihood ({fp_pct}%) — verify with user before containment."
    elif fp_pct >= 35:
        fp_verdict = f"MODERATE FP likelihood ({fp_pct}%) — validate business context before escalating."
    else:
        fp_verdict = f"LOW FP likelihood ({fp_pct}%) — rule evidence strongly supports this detection."

    report: dict[str, Any] = {
        "report_metadata": {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "report_type": "IdentityGuard AI Incident Report",
            "incident_id": inc_id,
        },
        "incident_overview": {
            "incident_id": inc_id,
            "user": _safe(incident.get("user")),
            "detection_type": det_type,
            "all_detections": _safe(incident.get("all_detections", incident.get("identity_indicators", ""))),
            "risk_score": _safe_int(incident.get("risk_score")),
            "risk_level": _safe(incident.get("risk_level")),
            "confidence": _safe(incident.get("confidence")),
            "false_positive_likelihood_pct": fp_pct,
            "escalation_decision": _safe(incident.get("escalation_decision")),
            "analyst_status": _safe(incident.get("status")),
            "created_at": _safe(incident.get("created_at", "")),
        },
        "event_timeline": events,
        "risk_score_breakdown": {
            "scoring_reasons": scoring_list,
        },
        "false_positive_considerations": {
            "likelihood_pct": fp_pct,
            "verdict": fp_verdict,
        },
        "mitre_attack_mapping": mitre_list,
        "zero_trust_gaps": zt_gaps,
        "recommended_actions": rec_list,
        "ai_analyst_summary": (
            {
                "available": True,
                "generated_at": ai_data.get("generated_at", ""),
                **ai_data["summary"],
            }
            if ai_data
            else {
                "available": False,
                "note": (
                    "No cached AI summary was available for this incident. "
                    "To generate one, open the IdentityGuard AI tab in the dashboard "
                    "and click 'Generate AI Analyst Summary'."
                ),
            }
        ),
        "ticket_ready_handoff": (
            ai_data["summary"].get("ticket_handoff", "")
            if ai_data
            else (
                f"INCIDENT : {inc_id}\n"
                f"USER     : {_safe(incident.get('user'))}\n"
                f"RISK     : {_safe(incident.get('risk_level'))} ({_safe_int(incident.get('risk_score'))}/100)\n"
                f"STATUS   : {_safe(incident.get('status'))}\n"
                f"ESCALATION: {_safe(incident.get('escalation_decision'))}\n"
            )
        ),
    }
    return report


# ---------------------------------------------------------------------------
# Save to disk
# ---------------------------------------------------------------------------

def _safe_filename(inc_id: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_\-]", "_", inc_id)


def save_markdown_report(incident: dict) -> Path:
    """Generate Markdown report, save to output/identity_reports/, return path."""
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    inc_id    = _safe(incident.get("incident_id"), "UNKNOWN")
    ts        = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename  = f"ig_report_{_safe_filename(inc_id)}_{ts}.md"
    out_path  = REPORTS_DIR / filename
    content   = build_markdown_report(incident)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(content)
    return out_path


def save_json_report(incident: dict) -> Path:
    """Generate JSON report, save to output/identity_reports/, return path."""
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    inc_id   = _safe(incident.get("incident_id"), "UNKNOWN")
    ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"ig_report_{_safe_filename(inc_id)}_{ts}.json"
    out_path = REPORTS_DIR / filename
    content  = build_json_report(incident)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(content, f, indent=2, ensure_ascii=False)
    return out_path


# ---------------------------------------------------------------------------
# Convenience: generate both and return bytes for Streamlit download buttons
# ---------------------------------------------------------------------------

def get_markdown_bytes(incident: dict) -> bytes:
    return build_markdown_report(incident).encode("utf-8")


def get_json_bytes(incident: dict) -> bytes:
    return json.dumps(build_json_report(incident), indent=2, ensure_ascii=False).encode("utf-8")
