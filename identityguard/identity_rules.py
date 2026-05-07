"""
IdentityGuard AI — Deterministic Detection Rules

Each rule function accepts a list of event dicts (one incident = one or more events)
and returns a RuleResult. Rules are additive: run all rules and aggregate in scoring.py.

Score deltas are intentionally conservative. False-positive reductions apply last.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import List, Optional


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------

@dataclass
class RuleResult:
    rule_id: str                      # machine-readable rule name
    triggered: bool                   # did the rule fire?
    score_delta: int                  # points added (positive) or removed (negative)
    reason: str                       # plain-English explanation for the dashboard
    confidence: str                   # HIGH / MEDIUM / LOW
    detection_type: str               # canonical detection label
    evidence: List[str] = field(default_factory=list)  # specific log fields that triggered this


# ---------------------------------------------------------------------------
# Helper: safely read a field from any event in the incident
# ---------------------------------------------------------------------------

def _field(events: list, key: str, default=None):
    """Return the first non-null value for `key` across all events."""
    for e in events:
        v = e.get(key)
        if v is not None and v != "":
            return v
    return default


def _any_event(events: list, key: str, value) -> bool:
    """True if at least one event has events[key] == value."""
    return any(e.get(key) == value for e in events)


def _count_events(events: list, key: str, value) -> int:
    return sum(1 for e in events if e.get(key) == value)


def _events_with(events: list, key: str, value) -> list:
    return [e for e in events if e.get(key) == value]


# ---------------------------------------------------------------------------
# RULE 1 — Impossible Travel
# ---------------------------------------------------------------------------

def rule_impossible_travel(events: list) -> RuleResult:
    """
    Fires when the impossible_travel_flag is True on any event in the incident.
    Impossible travel means the physical distance between two consecutive logins
    is too large to cover in the elapsed time (e.g. NYC → Moscow in 90 minutes).
    """
    flagged = [e for e in events if e.get("impossible_travel_flag") is True]
    if not flagged:
        return RuleResult(
            rule_id="impossible_travel",
            triggered=False,
            score_delta=0,
            reason="No impossible travel detected.",
            confidence="HIGH",
            detection_type="impossible_travel",
        )

    countries = list({e.get("country", "Unknown") for e in flagged})
    ips = list({e.get("source_ip", "Unknown") for e in flagged})
    evidence = [
        f"Impossible travel flag set on {len(flagged)} event(s)",
        f"Source countries in incident: {countries}",
        f"Source IPs flagged: {ips}",
    ]

    return RuleResult(
        rule_id="impossible_travel",
        triggered=True,
        score_delta=35,
        reason=(
            f"Impossible travel detected: login(s) originated from {countries} "
            "within a timeframe that is physically impossible given prior session location."
        ),
        confidence="HIGH",
        detection_type="impossible_travel",
        evidence=evidence,
    )


# ---------------------------------------------------------------------------
# RULE 2 — MFA Fatigue / Prompt Bombing
# ---------------------------------------------------------------------------

def rule_mfa_fatigue(events: list) -> RuleResult:
    """
    MFA fatigue: attacker repeatedly sends MFA push prompts hoping the user
    approves out of frustration. Signs: multiple MFA_denied events followed
    by MFA_success, OR mfa_result contains 'fatigue'/'bombing' signal.
    """
    denied = _count_events(events, "mfa_result", "denied")
    success_after = _any_event(events, "mfa_result", "success")
    fatigue_signal = _any_event(events, "risk_signal", "mfa_fatigue")

    # Also check raw notes field for fatigue keywords
    notes_fatigue = any(
        "fatigue" in str(e.get("notes", "")).lower()
        or "bombing" in str(e.get("notes", "")).lower()
        or "prompt" in str(e.get("notes", "")).lower()
        for e in events
    )

    if denied >= 3 and success_after:
        score = 40
        reason = (
            f"MFA fatigue pattern: {denied} MFA push denials followed by approval. "
            "User may have approved under duress or confusion."
        )
        confidence = "HIGH"
        evidence = [f"{denied} MFA denied events", "MFA success event follows denials"]
    elif denied >= 2 and fatigue_signal:
        score = 35
        reason = (
            f"MFA fatigue risk signal with {denied} denials. Risk signal explicitly flagged in log."
        )
        confidence = "HIGH"
        evidence = [f"{denied} MFA denied events", "risk_signal=mfa_fatigue"]
    elif denied >= 2 and notes_fatigue:
        score = 30
        reason = (
            f"{denied} MFA denials with fatigue/bombing keyword in event notes. "
            "Pattern consistent with prompt bombing."
        )
        confidence = "MEDIUM"
        evidence = [f"{denied} MFA denied events", "Fatigue keyword in notes"]
    elif denied >= 2:
        score = 20
        reason = (
            f"{denied} MFA denials detected. Possible accidental denials or early-stage fatigue attempt."
        )
        confidence = "MEDIUM"
        evidence = [f"{denied} MFA denied events (no confirmed success)"]
    else:
        return RuleResult(
            rule_id="mfa_fatigue",
            triggered=False,
            score_delta=0,
            reason="No MFA fatigue pattern detected.",
            confidence="HIGH",
            detection_type="mfa_fatigue",
        )

    return RuleResult(
        rule_id="mfa_fatigue",
        triggered=True,
        score_delta=score,
        reason=reason,
        confidence=confidence,
        detection_type="mfa_fatigue",
        evidence=evidence,
    )


# ---------------------------------------------------------------------------
# RULE 3 — New Device Login
# ---------------------------------------------------------------------------

def rule_new_device_login(events: list) -> RuleResult:
    """
    A login from a device ID that is new, unknown, or never registered
    to the user's account. Signals possible credential compromise.
    """
    new_device_events = [
        e for e in events
        if str(e.get("device_id", "")).upper().startswith("DEV-UNKNOWN")
        or e.get("risk_signal") == "new_device"
        or "new_device" in str(e.get("notes", "")).lower()
        or e.get("device_trust_status") == "unknown"
    ]

    if not new_device_events:
        return RuleResult(
            rule_id="new_device_login",
            triggered=False,
            score_delta=0,
            reason="All logins originated from registered devices.",
            confidence="HIGH",
            detection_type="new_device_login",
        )

    device_ids = list({e.get("device_id", "Unknown") for e in new_device_events})
    evidence = [
        f"New/unknown device(s): {device_ids}",
        f"{len(new_device_events)} event(s) from unrecognised device",
    ]

    return RuleResult(
        rule_id="new_device_login",
        triggered=True,
        score_delta=20,
        reason=(
            f"Login from {len(new_device_events)} unrecognised device(s) "
            f"({device_ids}). Device not previously registered to this user account."
        ),
        confidence="MEDIUM",
        detection_type="new_device_login",
        evidence=evidence,
    )


# ---------------------------------------------------------------------------
# RULE 4 — Unmanaged Device
# ---------------------------------------------------------------------------

def rule_unmanaged_device(events: list) -> RuleResult:
    """
    Login from a device not enrolled in MDM/Intune/Jamf.
    Unmanaged devices lack endpoint controls: no patch compliance,
    no DLP, no conditional access policies enforced by the org.
    """
    unmanaged = [e for e in events if e.get("device_trust_status") == "unmanaged"]
    if not unmanaged:
        return RuleResult(
            rule_id="unmanaged_device",
            triggered=False,
            score_delta=0,
            reason="All devices are managed or status is acceptable.",
            confidence="HIGH",
            detection_type="unmanaged_device",
        )

    roles = list({e.get("user_role", "Unknown") for e in unmanaged})
    apps = list({e.get("app_name", "Unknown") for e in unmanaged})
    evidence = [
        f"Unmanaged device on {len(unmanaged)} event(s)",
        f"User role(s): {roles}",
        f"App(s) accessed: {apps}",
    ]

    # Admin from unmanaged device is a higher signal
    admin_roles = [r for r in roles if "admin" in str(r).lower() or "Admin" in str(r)]
    if admin_roles:
        score = 30
        reason = (
            f"ADMIN user ({admin_roles}) authenticated from unmanaged device. "
            "Privileged access without endpoint controls violates least-privilege and Zero Trust device policy."
        )
        confidence = "HIGH"
    else:
        score = 20
        reason = (
            f"Login from unmanaged device. Device is not enrolled in MDM. "
            f"Accessed app(s): {apps}. No endpoint compliance enforced."
        )
        confidence = "MEDIUM"

    return RuleResult(
        rule_id="unmanaged_device",
        triggered=True,
        score_delta=score,
        reason=reason,
        confidence=confidence,
        detection_type="unmanaged_device",
        evidence=evidence,
    )


# ---------------------------------------------------------------------------
# RULE 5 — Suspicious OAuth Consent
# ---------------------------------------------------------------------------

# Permissions considered high-risk in a cloud tenant
_HIGH_RISK_OAUTH_PERMS = {
    "Mail.Read", "Mail.ReadWrite", "Mail.Send",
    "MailboxSettings.ReadWrite", "Files.ReadWrite.All",
    "Directory.ReadWrite.All", "RoleManagement.ReadWrite.Directory",
    "offline_access", "Calendars.ReadWrite",
    "Contacts.ReadWrite", "User.ReadWrite.All",
}

def rule_oauth_abuse(events: list) -> RuleResult:
    """
    An OAuth application was granted sensitive permissions (mail read, files write, etc.)
    This can enable persistent access even after the user's password is changed.
    """
    oauth_events = [e for e in events if e.get("oauth_permission")]
    if not oauth_events:
        return RuleResult(
            rule_id="oauth_abuse",
            triggered=False,
            score_delta=0,
            reason="No OAuth consent events detected.",
            confidence="HIGH",
            detection_type="oauth_abuse",
        )

    risky_grants = []
    for e in oauth_events:
        perm = e.get("oauth_permission", "")
        app = e.get("oauth_app_name", "Unknown App")
        if perm in _HIGH_RISK_OAUTH_PERMS:
            risky_grants.append(f"{app} granted {perm}")

    if not risky_grants:
        return RuleResult(
            rule_id="oauth_abuse",
            triggered=False,
            score_delta=0,
            reason=f"OAuth consent detected but permissions are low-risk: {[e.get('oauth_permission') for e in oauth_events]}",
            confidence="HIGH",
            detection_type="oauth_abuse",
        )

    evidence = [f"High-risk OAuth grant: {g}" for g in risky_grants]
    return RuleResult(
        rule_id="oauth_abuse",
        triggered=True,
        score_delta=25,
        reason=(
            f"High-risk OAuth permissions granted: {risky_grants}. "
            "These permissions provide persistent access to mailbox/files even after password reset."
        ),
        confidence="HIGH",
        detection_type="oauth_abuse",
        evidence=evidence,
    )


# ---------------------------------------------------------------------------
# RULE 6 — Mailbox Forwarding Rule
# ---------------------------------------------------------------------------

def rule_mailbox_forwarding(events: list) -> RuleResult:
    """
    A mailbox forwarding or inbox rule was created to redirect email to an
    external address. Classic BEC/account-takeover persistence technique.
    """
    fwd_events = [
        e for e in events
        if e.get("mailbox_action") in (
            "forwarding_rule_created", "inbox_rule_created",
            "mailbox_forwarding_enabled", "delegate_access_granted"
        )
        or "forward" in str(e.get("mailbox_action", "")).lower()
        or "inbox_rule" in str(e.get("mailbox_action", "")).lower()
    ]

    if not fwd_events:
        return RuleResult(
            rule_id="mailbox_forwarding",
            triggered=False,
            score_delta=0,
            reason="No mailbox forwarding or inbox rule activity detected.",
            confidence="HIGH",
            detection_type="mailbox_forwarding",
        )

    actions = list({e.get("mailbox_action", "unknown") for e in fwd_events})
    users = list({e.get("user", "Unknown") for e in fwd_events})
    evidence = [
        f"Mailbox rule action(s): {actions}",
        f"Affected user(s): {users}",
        f"{len(fwd_events)} rule-creation event(s)",
    ]

    return RuleResult(
        rule_id="mailbox_forwarding",
        triggered=True,
        score_delta=30,
        reason=(
            f"Mailbox forwarding/inbox rule created ({actions}). "
            "This technique is used in BEC attacks to silently exfiltrate email "
            "and hide attacker communications from the victim."
        ),
        confidence="HIGH",
        detection_type="mailbox_forwarding",
        evidence=evidence,
    )


# ---------------------------------------------------------------------------
# RULE 7 — Failed Logins Followed by Success
# ---------------------------------------------------------------------------

def rule_failed_then_success(events: list) -> RuleResult:
    """
    Multiple failed authentication attempts followed by a successful login
    from the same or similar session. Indicates brute force or credential stuffing success.
    """
    # Check direct failed_login_count field first
    max_failed = max((e.get("failed_login_count", 0) or 0 for e in events), default=0)

    # Also count action == login_failed events
    failed_action_count = _count_events(events, "action", "login_failed")
    success_action = _any_event(events, "action", "login_success")

    total_failures = max(max_failed, failed_action_count)

    if total_failures < 3 or not success_action:
        return RuleResult(
            rule_id="failed_then_success",
            triggered=False,
            score_delta=0,
            reason=f"Failed login pattern not significant (failures={total_failures}, success={success_action}).",
            confidence="HIGH",
            detection_type="failed_then_success",
        )

    if total_failures >= 10:
        score = 35
        confidence = "HIGH"
        reason = (
            f"High-volume brute force pattern: {total_failures} failed logins followed by success. "
            "Consistent with automated credential stuffing."
        )
    elif total_failures >= 5:
        score = 25
        confidence = "HIGH"
        reason = (
            f"{total_failures} failed login attempts followed by successful authentication. "
            "Likely password spray or targeted brute force."
        )
    else:
        score = 15
        confidence = "MEDIUM"
        reason = (
            f"{total_failures} failed login attempts before success. "
            "Could be legitimate user confusion or low-volume credential attack."
        )

    evidence = [
        f"Total failed attempts: {total_failures}",
        "Successful login event present in incident timeline",
    ]

    return RuleResult(
        rule_id="failed_then_success",
        triggered=True,
        score_delta=score,
        reason=reason,
        confidence=confidence,
        detection_type="failed_then_success",
        evidence=evidence,
    )


# ---------------------------------------------------------------------------
# RULE 8 — Password Reset Followed by Suspicious Login
# ---------------------------------------------------------------------------

def rule_password_reset_risky_login(events: list) -> RuleResult:
    """
    A password reset (self-service or admin-initiated) followed by a login
    that carries other risk signals. Attackers who compromise a user via
    phishing often immediately reset the password to lock out the legitimate user.
    """
    reset_events = [
        e for e in events
        if e.get("event_type") in ("PasswordReset", "AdminPasswordReset", "SelfServicePasswordReset")
        or e.get("action") in ("password_reset", "admin_password_reset")
        or "password_reset" in str(e.get("risk_signal", "")).lower()
    ]

    if not reset_events:
        return RuleResult(
            rule_id="password_reset_risky_login",
            triggered=False,
            score_delta=0,
            reason="No password reset activity detected.",
            confidence="HIGH",
            detection_type="password_reset_risky_login",
        )

    # Check if any event after the reset looks risky
    risky_signals = [
        "impossible_travel", "new_device", "suspicious_ip",
        "anonymous_ip", "malware_linked_ip", "unfamiliar_features"
    ]
    post_reset_risky = any(
        e.get("risk_signal") in risky_signals for e in events
    )
    foreign_login = any(
        e.get("impossible_travel_flag") is True for e in events
    )

    if foreign_login or post_reset_risky:
        score = 30
        confidence = "HIGH"
        reason = (
            "Password reset detected followed by login with active risk signals "
            f"({[e.get('risk_signal') for e in events if e.get('risk_signal')]}). "
            "Pattern consistent with account takeover: attacker resets password to maintain control."
        )
    else:
        score = 15
        confidence = "MEDIUM"
        reason = (
            "Password reset occurred in this incident. "
            "No confirmed risky post-reset login, but event warrants analyst review."
        )

    evidence = [
        f"Password reset event type(s): {[e.get('event_type') or e.get('action') for e in reset_events]}",
        f"Post-reset risk signals present: {post_reset_risky or foreign_login}",
    ]

    return RuleResult(
        rule_id="password_reset_risky_login",
        triggered=True,
        score_delta=score,
        reason=reason,
        confidence=confidence,
        detection_type="password_reset_risky_login",
        evidence=evidence,
    )


# ---------------------------------------------------------------------------
# RULE 9 — Admin Login from Risky Source
# ---------------------------------------------------------------------------

def rule_admin_risky_login(events: list) -> RuleResult:
    """
    A user with an administrative role authenticated from a risky or
    unexpected source (unmanaged device, anonymous IP, impossible travel, etc.).
    Admin accounts are high-value targets; any anomaly warrants immediate review.
    """
    admin_events = [
        e for e in events
        if "admin" in str(e.get("user_role", "")).lower()
    ]

    if not admin_events:
        return RuleResult(
            rule_id="admin_risky_login",
            triggered=False,
            score_delta=0,
            reason="No administrative account activity in this incident.",
            confidence="HIGH",
            detection_type="admin_risky_login",
        )

    # Count risk signals on admin events
    risk_factors = []
    for e in admin_events:
        if e.get("device_trust_status") == "unmanaged":
            risk_factors.append("unmanaged device")
        if e.get("impossible_travel_flag") is True:
            risk_factors.append("impossible travel")
        if e.get("risk_signal") in ("anonymous_ip", "suspicious_ip", "malware_linked_ip"):
            risk_factors.append(f"risky IP ({e.get('risk_signal')})")
        if str(e.get("device_id", "")).upper().startswith("DEV-UNKNOWN"):
            risk_factors.append("unknown device")
        if e.get("known_vpn") is False and e.get("country") not in (None, ""):
            # Only flag if there's also another signal
            pass

    if not risk_factors:
        return RuleResult(
            rule_id="admin_risky_login",
            triggered=False,
            score_delta=0,
            reason="Admin login detected but no additional risk factors present.",
            confidence="HIGH",
            detection_type="admin_risky_login",
        )

    roles = list({e.get("user_role", "Unknown") for e in admin_events})
    score = 25 + (10 if len(set(risk_factors)) >= 2 else 0)
    evidence = [
        f"Admin role(s): {roles}",
        f"Risk factors on admin events: {list(set(risk_factors))}",
    ]

    return RuleResult(
        rule_id="admin_risky_login",
        triggered=True,
        score_delta=score,
        reason=(
            f"Privileged account ({roles}) authenticated with risk factors: "
            f"{list(set(risk_factors))}. Admin compromise provides full tenant access."
        ),
        confidence="HIGH",
        detection_type="admin_risky_login",
        evidence=evidence,
    )


# ---------------------------------------------------------------------------
# FALSE-POSITIVE REDUCTION RULES (return negative score_delta)
# ---------------------------------------------------------------------------

def fp_known_vpn(events: list) -> RuleResult:
    """
    If all events in the incident originate from a known corporate VPN,
    the impossible-travel and foreign-IP signals are likely false positives.
    """
    vpn_events = [e for e in events if e.get("known_vpn") is True]
    if not vpn_events or len(vpn_events) < len(events):
        return RuleResult(
            rule_id="fp_known_vpn",
            triggered=False,
            score_delta=0,
            reason="Known VPN not confirmed for all events; no FP reduction applied.",
            confidence="HIGH",
            detection_type="fp_reduction",
        )

    return RuleResult(
        rule_id="fp_known_vpn",
        triggered=True,
        score_delta=-20,
        reason=(
            "All source IPs in this incident are confirmed corporate VPN exit nodes. "
            "Geographic anomaly is expected behaviour for remote workers. "
            "Impossible travel signal likely false positive."
        ),
        confidence="HIGH",
        detection_type="fp_reduction",
        evidence=["known_vpn=True on all events"],
    )


def fp_managed_device(events: list) -> RuleResult:
    """
    All logins from MDM-enrolled, compliant devices reduce residual risk.
    Managed devices have enforced policies, patching, and DLP controls.
    Does NOT apply when OAuth consent or mailbox rules are present — those risks
    are independent of device management status (user can be socially engineered
    into granting OAuth consent from a fully managed device).
    """
    # OAuth abuse and mailbox forwarding are user-action risks, not device-trust risks
    has_oauth = any(e.get("oauth_permission") for e in events)
    has_mailbox = any(e.get("mailbox_action") for e in events)
    if has_oauth or has_mailbox:
        return RuleResult(
            rule_id="fp_managed_device",
            triggered=False,
            score_delta=0,
            reason=(
                "Managed device FP reduction skipped: OAuth consent or mailbox rule activity "
                "present. These risks are independent of device management status."
            ),
            confidence="HIGH",
            detection_type="fp_reduction",
        )

    managed = [e for e in events if e.get("device_trust_status") == "managed"]
    if len(managed) == len(events) and len(events) > 0:
        return RuleResult(
            rule_id="fp_managed_device",
            triggered=True,
            score_delta=-15,
            reason=(
                "All device events show MDM-compliant managed devices. "
                "Endpoint controls are in place; device-based risk reduced."
            ),
            confidence="HIGH",
            detection_type="fp_reduction",
            evidence=["device_trust_status=managed on all events"],
        )

    return RuleResult(
        rule_id="fp_managed_device",
        triggered=False,
        score_delta=0,
        reason="Not all events originated from managed devices; no FP reduction applied.",
        confidence="HIGH",
        detection_type="fp_reduction",
    )


def fp_known_location(events: list) -> RuleResult:
    """
    If the notes or risk_signal indicate a previously seen location or
    legitimate business travel, reduce the impossible-travel score contribution.
    """
    known_travel = any(
        "business_travel" in str(e.get("risk_signal", "")).lower()
        or "known_location" in str(e.get("risk_signal", "")).lower()
        or "expected_travel" in str(e.get("notes", "")).lower()
        or "conference" in str(e.get("notes", "")).lower()
        or "scheduled_travel" in str(e.get("notes", "")).lower()
        for e in events
    )

    if not known_travel:
        return RuleResult(
            rule_id="fp_known_location",
            triggered=False,
            score_delta=0,
            reason="No known-location or expected-travel signal found.",
            confidence="HIGH",
            detection_type="fp_reduction",
        )

    return RuleResult(
        rule_id="fp_known_location",
        triggered=True,
        score_delta=-15,
        reason=(
            "Event notes indicate expected travel or known location. "
            "Geographic anomaly may reflect legitimate business activity. "
            "Analyst should verify against calendar or travel request system."
        ),
        confidence="MEDIUM",
        detection_type="fp_reduction",
        evidence=["Business travel or known location signal in event notes"],
    )


# ---------------------------------------------------------------------------
# Master rule runner — call this from scoring.py
# ---------------------------------------------------------------------------

DETECTION_RULES = [
    rule_impossible_travel,
    rule_mfa_fatigue,
    rule_new_device_login,
    rule_unmanaged_device,
    rule_oauth_abuse,
    rule_mailbox_forwarding,
    rule_failed_then_success,
    rule_password_reset_risky_login,
    rule_admin_risky_login,
]

FP_REDUCTION_RULES = [
    fp_known_vpn,
    fp_managed_device,
    fp_known_location,
]


def run_all_rules(events: list) -> List[RuleResult]:
    """
    Run all detection rules and FP reduction rules against an incident's events.
    Returns the full list of RuleResult objects (triggered and non-triggered).
    """
    results: List[RuleResult] = []
    for rule_fn in DETECTION_RULES:
        results.append(rule_fn(events))
    for fp_fn in FP_REDUCTION_RULES:
        results.append(fp_fn(events))
    return results
