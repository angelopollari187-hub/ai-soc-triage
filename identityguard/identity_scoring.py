"""
IdentityGuard AI — Risk Scoring Engine

Aggregates RuleResult objects into a final TriageResult.
Every score change is traceable to a named rule and explicit reason.

Score bands:
  0–24   LOW
  25–49  MEDIUM
  50–74  HIGH
  75+    CRITICAL
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import List, Optional
from datetime import datetime, timezone

from identityguard.identity_rules import RuleResult, run_all_rules


# ---------------------------------------------------------------------------
# Score band helpers
# ---------------------------------------------------------------------------

def score_to_level(score: int) -> str:
    if score >= 75:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 25:
        return "MEDIUM"
    return "LOW"


def score_to_escalation(score: int, level: str) -> str:
    if level == "CRITICAL":
        return "ESCALATE_IMMEDIATELY"
    if level == "HIGH":
        return "ESCALATE"
    if level == "MEDIUM":
        return "ANALYST_REVIEW"
    return "MONITOR"


def _fp_likelihood(score: int, fp_rules_fired: int, total_fp_reductions: int) -> int:
    """
    Heuristic FP likelihood (0–100).
    High score = more likely a true positive.
    High FP-reduction count = more likely a false positive.
    """
    base = max(0, 80 - score)          # lower score → higher FP likelihood
    reduction_bonus = fp_rules_fired * 15
    result = min(95, base + reduction_bonus)
    return max(5, result)


def _aggregate_confidence(results: List[RuleResult]) -> str:
    """Overall confidence from the highest-confidence triggered rule."""
    triggered = [r for r in results if r.triggered and r.score_delta > 0]
    if not triggered:
        return "LOW"
    confidences = [r.confidence for r in triggered]
    if "HIGH" in confidences:
        return "HIGH"
    if "MEDIUM" in confidences:
        return "MEDIUM"
    return "LOW"


# ---------------------------------------------------------------------------
# Triage result type
# ---------------------------------------------------------------------------

@dataclass
class TriageResult:
    incident_id: str
    user: str
    detection_types: List[str]          # canonical names of triggered rules
    risk_score: int
    risk_level: str                     # LOW / MEDIUM / HIGH / CRITICAL
    confidence: str
    false_positive_likelihood: int      # 0–100
    identity_indicators: str            # comma-joined list for CSV
    scoring_reasons: str                # human-readable breakdown, one reason per line
    zero_trust_gaps: str                # populated by zero_trust_mapper.py later
    mitre_techniques: str               # populated by scoring or mapper
    recommended_actions: str
    escalation_decision: str
    status: str                         # analyst workflow state
    created_at: str
    raw_rule_results: List[RuleResult] = field(default_factory=list, repr=False)


# ---------------------------------------------------------------------------
# MITRE technique mapping by detection type
# ---------------------------------------------------------------------------

_MITRE_MAP = {
    "impossible_travel":            "T1078 – Valid Accounts",
    "mfa_fatigue":                  "T1621 – Multi-Factor Authentication Request Generation",
    "new_device_login":             "T1078 – Valid Accounts",
    "unmanaged_device":             "T1078.004 – Cloud Accounts",
    "oauth_abuse":                  "T1550.001 – Application Access Token",
    "mailbox_forwarding":           "T1114.003 – Email Forwarding Rule",
    "failed_then_success":          "T1110 – Brute Force",
    "password_reset_risky_login":   "T1098 – Account Manipulation",
    "admin_risky_login":            "T1078.004 – Cloud Accounts",
    "fp_reduction":                 None,  # not a detection
}


def _build_mitre_string(detection_types: List[str]) -> str:
    seen = set()
    techniques = []
    for dt in detection_types:
        t = _MITRE_MAP.get(dt)
        if t and t not in seen:
            seen.add(t)
            techniques.append(t)
    return " | ".join(techniques) if techniques else "None"


# ---------------------------------------------------------------------------
# Recommended actions by risk level + detection type
# ---------------------------------------------------------------------------

_ACTION_MAP = {
    "impossible_travel": (
        "1. Immediately revoke all active sessions for this user. "
        "2. Force re-authentication with MFA from a trusted device. "
        "3. Review sign-in logs for the past 72 hours. "
        "4. Check for new OAuth consents or inbox rules created in the same session."
    ),
    "mfa_fatigue": (
        "1. Revoke all active sessions. "
        "2. Disable MFA push notifications temporarily; switch to TOTP or FIDO2. "
        "3. Notify the user directly via out-of-band channel (phone/manager). "
        "4. Investigate whether any session was approved under duress."
    ),
    "oauth_abuse": (
        "1. Revoke the OAuth application consent immediately in Azure AD / Okta. "
        "2. Audit all emails and files accessible under the granted permission. "
        "3. Check if the app is registered in the tenant or is a third-party app. "
        "4. Block the app in Cloud App Security / CASB if available."
    ),
    "mailbox_forwarding": (
        "1. Remove the forwarding/inbox rule immediately. "
        "2. Audit outbound emails sent since the rule was created. "
        "3. Revoke all sessions and force password reset. "
        "4. Notify compliance team if sensitive email content may have been exfiltrated."
    ),
    "failed_then_success": (
        "1. Verify with the user whether the successful login was legitimate. "
        "2. Check the source IP against known threat feeds. "
        "3. If unconfirmed, revoke the session and force MFA re-enrollment. "
        "4. Enable account lockout policy if not already configured."
    ),
    "password_reset_risky_login": (
        "1. Verify the password reset was initiated by the legitimate user. "
        "2. If self-service: check if the reset email was sent to a compromised account. "
        "3. Revoke all post-reset sessions and force another password change. "
        "4. Review MFA method registrations for new/attacker-added methods."
    ),
    "admin_risky_login": (
        "1. URGENT: Suspend the admin account until ownership is verified. "
        "2. Review all admin actions taken in the past 24 hours. "
        "3. Check for new user accounts, role assignments, or policy changes. "
        "4. Notify the CISO / security leadership immediately."
    ),
    "unmanaged_device": (
        "1. Block unmanaged devices via Conditional Access policy. "
        "2. Verify with the user whether the device is theirs. "
        "3. Require device enrolment before restoring access. "
        "4. Check what resources were accessed from the unmanaged device."
    ),
    "new_device_login": (
        "1. Confirm device ownership with the user out-of-band. "
        "2. If unconfirmed, revoke the session and require re-authentication. "
        "3. Review what data was accessed from the new device. "
        "4. Register the device in MDM if confirmed legitimate."
    ),
}

_DEFAULT_ACTION = (
    "1. Review the full sign-in log for this user. "
    "2. Confirm activity with the user via out-of-band channel. "
    "3. If unconfirmed, revoke sessions and force MFA re-authentication. "
    "4. Document findings in the incident ticket."
)


def _build_recommended_actions(detection_types: List[str], risk_level: str) -> str:
    seen_actions = []
    seen_keys = set()
    for dt in detection_types:
        if dt in _ACTION_MAP and dt not in seen_keys:
            seen_actions.append(_ACTION_MAP[dt])
            seen_keys.add(dt)
    if not seen_actions:
        return _DEFAULT_ACTION
    if risk_level in ("CRITICAL", "HIGH") and len(seen_actions) > 1:
        return "\n\n".join(seen_actions)
    return seen_actions[0]


# ---------------------------------------------------------------------------
# Core scoring function
# ---------------------------------------------------------------------------

def score_incident(incident_id: str, events: list) -> TriageResult:
    """
    Run all rules against the incident's events and produce a TriageResult.

    Args:
        incident_id: Unique incident identifier.
        events:      List of identity event dicts for this incident.

    Returns:
        TriageResult with fully explainable scoring.
    """
    if not events:
        raise ValueError(f"Incident {incident_id} has no events.")

    user = events[0].get("user", "unknown@unknown.com")
    rule_results = run_all_rules(events)

    # Build score step by step, recording each contribution
    raw_score = 0
    scoring_lines = []
    triggered_detections = []
    fp_rules_fired = 0
    total_fp_reduction = 0

    for r in rule_results:
        if not r.triggered:
            continue
        raw_score += r.score_delta
        if r.score_delta > 0:
            sign = f"+{r.score_delta}"
            triggered_detections.append(r.detection_type)
            scoring_lines.append(f"[{sign}] {r.rule_id}: {r.reason}")
        elif r.score_delta < 0:
            sign = str(r.score_delta)   # already negative
            fp_rules_fired += 1
            total_fp_reduction += abs(r.score_delta)
            scoring_lines.append(f"[{sign}] {r.rule_id} (FP reduction): {r.reason}")

    # Clamp score to [0, 100]
    final_score = max(0, min(100, raw_score))
    risk_level = score_to_level(final_score)
    escalation = score_to_escalation(final_score, risk_level)
    confidence = _aggregate_confidence(rule_results)
    fp_pct = _fp_likelihood(final_score, fp_rules_fired, total_fp_reduction)

    # Deduplicate detection types (a rule may share a detection_type with another)
    unique_detections = list(dict.fromkeys(
        dt for dt in triggered_detections if dt != "fp_reduction"
    ))

    if not scoring_lines:
        scoring_lines = ["[+0] No rules triggered. Activity appears within normal parameters."]

    scoring_reasons_text = "\n".join(scoring_lines)
    if raw_score != final_score:
        scoring_reasons_text += f"\n[clamped] Raw score {raw_score} clamped to {final_score}."

    mitre = _build_mitre_string(unique_detections)
    actions = _build_recommended_actions(unique_detections, risk_level)
    indicators_str = ", ".join(unique_detections) if unique_detections else "none"

    return TriageResult(
        incident_id=incident_id,
        user=user,
        detection_types=unique_detections,
        risk_score=final_score,
        risk_level=risk_level,
        confidence=confidence,
        false_positive_likelihood=fp_pct,
        identity_indicators=indicators_str,
        scoring_reasons=scoring_reasons_text,
        zero_trust_gaps="",          # filled by zero_trust_mapper (Phase 3)
        mitre_techniques=mitre,
        recommended_actions=actions,
        escalation_decision=escalation,
        status="NEW",
        created_at=datetime.now(timezone.utc).isoformat(),
        raw_rule_results=rule_results,
    )
