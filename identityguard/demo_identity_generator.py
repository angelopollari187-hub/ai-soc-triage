"""
IdentityGuard AI — Demo Identity Incident Generator

Produces 12 realistic demo incidents that cover the full detection surface:
impossible travel, MFA fatigue, OAuth abuse, mailbox forwarding, brute force,
password reset, admin risk, VPN false positive, business travel false positive,
managed-device normal behaviour, suspicious sensitive-app access, and a
multi-stage account takeover chain.

Each incident is a dict with:
  - incident_id  : unique identifier
  - scenario     : human-readable scenario name
  - events       : list of identity event dicts (one or more per incident)

Usage:
    python -m identityguard.demo_identity_generator
    → writes identityguard/sample_events/demo_incidents.json
    → runs triage on all 12 incidents and prints a summary table
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone

# Allow running as a script from project root
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from identityguard.identity_scoring import score_incident


# ---------------------------------------------------------------------------
# Shared timestamp helpers (all demo events use static times for reproducibility)
# ---------------------------------------------------------------------------

def _ts(year: int, month: int, day: int, hour: int, minute: int = 0) -> str:
    return datetime(year, month, day, hour, minute, tzinfo=timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# 12 Demo incidents
# ---------------------------------------------------------------------------

def build_demo_incidents() -> list:
    incidents = []

    # ------------------------------------------------------------------
    # INC-IG-001  Impossible travel with new device
    # ------------------------------------------------------------------
    incidents.append({
        "incident_id": "INC-IG-001",
        "scenario": "Impossible Travel with New Device",
        "events": [
            {
                "incident_id": "INC-IG-001",
                "user": "alice.johnson@contoso.com",
                "user_role": "Finance Manager",
                "event_time": _ts(2024, 5, 1, 8, 45),
                "event_type": "SignIn",
                "source_ip": "72.21.198.64",
                "country": "United States",
                "city": "New York",
                "device_id": "DEV-WIN-ALICE-001",
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
                "session_id": "sess-alice-001a",
                "notes": "Normal morning login from corporate office, NYC.",
            },
            {
                "incident_id": "INC-IG-001",
                "user": "alice.johnson@contoso.com",
                "user_role": "Finance Manager",
                "event_time": _ts(2024, 5, 1, 10, 12),
                "event_type": "SignIn",
                "source_ip": "185.220.101.47",
                "country": "Russia",
                "city": "Moscow",
                "device_id": "DEV-UNKNOWN-RU-991",
                "device_trust_status": "unmanaged",
                "device_os": "Windows 10",
                "mfa_result": "success",
                "mfa_method": "authenticator_app",
                "app_name": "SharePoint Online",
                "action": "login_success",
                "oauth_app_name": None,
                "oauth_permission": None,
                "mailbox_action": None,
                "risk_signal": "impossible_travel",
                "known_vpn": False,
                "impossible_travel_flag": True,
                "failed_login_count": 0,
                "session_id": "sess-alice-001b",
                "notes": (
                    "Login from Moscow 87 minutes after confirmed NYC session. "
                    "Physical distance ~9000 km. Impossible to travel legitimately."
                ),
            },
        ],
    })

    # ------------------------------------------------------------------
    # INC-IG-002  MFA fatigue followed by approval
    # ------------------------------------------------------------------
    mfa_base = {
        "incident_id": "INC-IG-002",
        "user": "bob.martinez@contoso.com",
        "user_role": "HR Generalist",
        "event_time": _ts(2024, 5, 2, 23, 5),
        "event_type": "MFARequest",
        "source_ip": "91.108.4.142",
        "country": "Germany",
        "city": "Frankfurt",
        "device_id": "DEV-UNKNOWN-DE-002",
        "device_trust_status": "unknown",
        "device_os": "Unknown",
        "mfa_method": "authenticator_push",
        "app_name": "Microsoft 365",
        "action": "mfa_push_sent",
        "oauth_app_name": None,
        "oauth_permission": None,
        "mailbox_action": None,
        "risk_signal": "mfa_fatigue",
        "known_vpn": False,
        "impossible_travel_flag": False,
        "failed_login_count": 0,
        "session_id": "sess-bob-002",
        "notes": "Repeated MFA push notifications sent at 23:05, 23:07, 23:10.",
    }

    def _mfa_event(minute: int, result: str, seq: int) -> dict:
        e = dict(mfa_base)
        e["event_time"] = _ts(2024, 5, 2, 23, minute)
        e["mfa_result"] = result
        e["notes"] = f"MFA push #{seq}: {result} at 23:{minute:02d}."
        if result == "success":
            e["notes"] += " User approved after multiple denials — possible fatigue."
        return e

    incidents.append({
        "incident_id": "INC-IG-002",
        "scenario": "MFA Fatigue Followed by Approval",
        "events": [
            _mfa_event(5, "denied", 1),
            _mfa_event(7, "denied", 2),
            _mfa_event(10, "denied", 3),
            _mfa_event(13, "denied", 4),
            _mfa_event(15, "success", 5),
        ],
    })

    # ------------------------------------------------------------------
    # INC-IG-003  OAuth app granted Mail.Read permission
    # ------------------------------------------------------------------
    incidents.append({
        "incident_id": "INC-IG-003",
        "scenario": "OAuth App Granted Mail.Read Permission",
        "events": [
            {
                "incident_id": "INC-IG-003",
                "user": "carol.smith@contoso.com",
                "user_role": "Marketing Analyst",
                "event_time": _ts(2024, 5, 3, 14, 22),
                "event_type": "OAuthConsent",
                "source_ip": "104.18.32.100",
                "country": "United States",
                "city": "San Francisco",
                "device_id": "DEV-MAC-CAROL-003",
                "device_trust_status": "managed",
                "device_os": "macOS 14",
                "mfa_result": "success",
                "mfa_method": "authenticator_app",
                "app_name": "Azure AD",
                "action": "oauth_consent_granted",
                "oauth_app_name": "EmailAnalyticsPro",
                "oauth_permission": "Mail.Read",
                "mailbox_action": None,
                "risk_signal": "oauth_consent_to_unverified_app",
                "known_vpn": False,
                "impossible_travel_flag": False,
                "failed_login_count": 0,
                "session_id": "sess-carol-003",
                "notes": (
                    "User granted 'EmailAnalyticsPro' (unverified publisher) "
                    "Mail.Read permission. App not on approved vendor list."
                ),
            },
        ],
    })

    # ------------------------------------------------------------------
    # INC-IG-004  Mailbox forwarding rule after suspicious login
    # ------------------------------------------------------------------
    incidents.append({
        "incident_id": "INC-IG-004",
        "scenario": "Mailbox Forwarding Rule After Suspicious Login",
        "events": [
            {
                "incident_id": "INC-IG-004",
                "user": "david.lee@contoso.com",
                "user_role": "Accounts Payable Specialist",
                "event_time": _ts(2024, 5, 4, 3, 17),
                "event_type": "SignIn",
                "source_ip": "45.142.212.100",
                "country": "Ukraine",
                "city": "Kyiv",
                "device_id": "DEV-UNKNOWN-UA-004",
                "device_trust_status": "unmanaged",
                "device_os": "Windows 10",
                "mfa_result": "success",
                "mfa_method": "sms",
                "app_name": "Outlook Web Access",
                "action": "login_success",
                "oauth_app_name": None,
                "oauth_permission": None,
                "mailbox_action": None,
                "risk_signal": "anonymous_ip",
                "known_vpn": False,
                "impossible_travel_flag": False,
                "failed_login_count": 2,
                "session_id": "sess-david-004a",
                "notes": "Login from anonymous-proxy IP at 03:17 UTC. User normally logs in from Chicago.",
            },
            {
                "incident_id": "INC-IG-004",
                "user": "david.lee@contoso.com",
                "user_role": "Accounts Payable Specialist",
                "event_time": _ts(2024, 5, 4, 3, 31),
                "event_type": "MailboxRuleCreated",
                "source_ip": "45.142.212.100",
                "country": "Ukraine",
                "city": "Kyiv",
                "device_id": "DEV-UNKNOWN-UA-004",
                "device_trust_status": "unmanaged",
                "device_os": "Windows 10",
                "mfa_result": None,
                "mfa_method": None,
                "app_name": "Outlook Web Access",
                "action": "inbox_rule_created",
                "oauth_app_name": None,
                "oauth_permission": None,
                "mailbox_action": "forwarding_rule_created",
                "risk_signal": "inbox_rule_post_suspicious_login",
                "known_vpn": False,
                "impossible_travel_flag": False,
                "failed_login_count": 0,
                "session_id": "sess-david-004a",
                "notes": (
                    "Inbox rule created 14 minutes after suspicious login. "
                    "Rule forwards all incoming email to attacker8847@protonmail.com."
                ),
            },
        ],
    })

    # ------------------------------------------------------------------
    # INC-IG-005  Failed logins followed by successful login
    # ------------------------------------------------------------------
    failed_events = []
    for i in range(8):
        failed_events.append({
            "incident_id": "INC-IG-005",
            "user": "eve.chen@contoso.com",
            "user_role": "Software Engineer",
            "event_time": _ts(2024, 5, 5, 2, i * 2),
            "event_type": "SignIn",
            "source_ip": "193.32.162.101",
            "country": "Netherlands",
            "city": "Amsterdam",
            "device_id": "DEV-UNKNOWN-NL-005",
            "device_trust_status": "unmanaged",
            "device_os": "Linux",
            "mfa_result": "not_required",
            "mfa_method": None,
            "app_name": "Azure AD",
            "action": "login_failed",
            "oauth_app_name": None,
            "oauth_permission": None,
            "mailbox_action": None,
            "risk_signal": "password_spray",
            "known_vpn": False,
            "impossible_travel_flag": False,
            "failed_login_count": i + 1,
            "session_id": f"sess-eve-005-attempt{i+1}",
            "notes": f"Failed login attempt {i+1} of 8 from same IP. Pattern consistent with password spray.",
        })

    failed_events.append({
        "incident_id": "INC-IG-005",
        "user": "eve.chen@contoso.com",
        "user_role": "Software Engineer",
        "event_time": _ts(2024, 5, 5, 2, 18),
        "event_type": "SignIn",
        "source_ip": "193.32.162.101",
        "country": "Netherlands",
        "city": "Amsterdam",
        "device_id": "DEV-UNKNOWN-NL-005",
        "device_trust_status": "unmanaged",
        "device_os": "Linux",
        "mfa_result": "not_required",
        "mfa_method": None,
        "app_name": "Azure AD",
        "action": "login_success",
        "oauth_app_name": None,
        "oauth_permission": None,
        "mailbox_action": None,
        "risk_signal": "password_spray",
        "known_vpn": False,
        "impossible_travel_flag": False,
        "failed_login_count": 8,
        "session_id": "sess-eve-005-success",
        "notes": "Successful login on attempt 9 after 8 consecutive failures.",
    })

    incidents.append({
        "incident_id": "INC-IG-005",
        "scenario": "Failed Logins Followed by Successful Login (Brute Force)",
        "events": failed_events,
    })

    # ------------------------------------------------------------------
    # INC-IG-006  Password reset followed by risky login
    # ------------------------------------------------------------------
    incidents.append({
        "incident_id": "INC-IG-006",
        "scenario": "Password Reset Followed by Risky Login",
        "events": [
            {
                "incident_id": "INC-IG-006",
                "user": "frank.nguyen@contoso.com",
                "user_role": "Finance Director",
                "event_time": _ts(2024, 5, 6, 9, 0),
                "event_type": "SelfServicePasswordReset",
                "source_ip": "104.28.42.190",
                "country": "United States",
                "city": "Dallas",
                "device_id": "DEV-WIN-FRANK-006",
                "device_trust_status": "managed",
                "device_os": "Windows 11",
                "mfa_result": "success",
                "mfa_method": "authenticator_app",
                "app_name": "SSPR Portal",
                "action": "password_reset",
                "oauth_app_name": None,
                "oauth_permission": None,
                "mailbox_action": None,
                "risk_signal": "password_reset",
                "known_vpn": False,
                "impossible_travel_flag": False,
                "failed_login_count": 0,
                "session_id": "sess-frank-006a",
                "notes": "Self-service password reset initiated via SSPR portal.",
            },
            {
                "incident_id": "INC-IG-006",
                "user": "frank.nguyen@contoso.com",
                "user_role": "Finance Director",
                "event_time": _ts(2024, 5, 6, 9, 47),
                "event_type": "SignIn",
                "source_ip": "178.62.131.44",
                "country": "Brazil",
                "city": "São Paulo",
                "device_id": "DEV-UNKNOWN-BR-006",
                "device_trust_status": "unmanaged",
                "device_os": "Android",
                "mfa_result": "success",
                "mfa_method": "sms",
                "app_name": "SAP Concur",
                "action": "login_success",
                "oauth_app_name": None,
                "oauth_permission": None,
                "mailbox_action": None,
                "risk_signal": "impossible_travel",
                "known_vpn": False,
                "impossible_travel_flag": True,
                "failed_login_count": 0,
                "session_id": "sess-frank-006b",
                "notes": (
                    "Login from Brazil 47 minutes after Dallas password reset. "
                    "Finance Director account accessing SAP Concur from unknown Android device."
                ),
            },
        ],
    })

    # ------------------------------------------------------------------
    # INC-IG-007  Admin login from unmanaged device
    # ------------------------------------------------------------------
    incidents.append({
        "incident_id": "INC-IG-007",
        "scenario": "Admin Login from Unmanaged Device",
        "events": [
            {
                "incident_id": "INC-IG-007",
                "user": "grace.kim@contoso.com",
                "user_role": "Global Administrator",
                "event_time": _ts(2024, 5, 7, 11, 30),
                "event_type": "SignIn",
                "source_ip": "24.105.60.200",
                "country": "United States",
                "city": "Chicago",
                "device_id": "DEV-UNKNOWN-PERSONAL-007",
                "device_trust_status": "unmanaged",
                "device_os": "macOS 13",
                "mfa_result": "success",
                "mfa_method": "authenticator_app",
                "app_name": "Azure AD Admin Portal",
                "action": "login_success",
                "oauth_app_name": None,
                "oauth_permission": None,
                "mailbox_action": None,
                "risk_signal": "admin_unmanaged_device",
                "known_vpn": False,
                "impossible_travel_flag": False,
                "failed_login_count": 0,
                "session_id": "sess-grace-007",
                "notes": (
                    "Global Admin authenticated from unmanaged personal MacBook. "
                    "Conditional Access policy for admin accounts requires Intune-compliant device. "
                    "Policy may be misconfigured or bypassed."
                ),
            },
        ],
    })

    # ------------------------------------------------------------------
    # INC-IG-008  Normal VPN false positive (LOW risk)
    # ------------------------------------------------------------------
    incidents.append({
        "incident_id": "INC-IG-008",
        "scenario": "Normal VPN False Positive",
        "events": [
            {
                "incident_id": "INC-IG-008",
                "user": "henry.obi@contoso.com",
                "user_role": "Software Engineer",
                "event_time": _ts(2024, 5, 8, 15, 0),
                "event_type": "SignIn",
                "source_ip": "10.200.1.45",
                "country": "United Kingdom",
                "city": "London",
                "device_id": "DEV-WIN-HENRY-008",
                "device_trust_status": "managed",
                "device_os": "Windows 11",
                "mfa_result": "success",
                "mfa_method": "authenticator_app",
                "app_name": "GitHub Enterprise",
                "action": "login_success",
                "oauth_app_name": None,
                "oauth_permission": None,
                "mailbox_action": None,
                "risk_signal": None,
                "known_vpn": True,
                "impossible_travel_flag": False,
                "failed_login_count": 0,
                "session_id": "sess-henry-008",
                "notes": (
                    "Login from London corporate VPN exit node. "
                    "User is a remote employee who normally works from Toronto. "
                    "VPN IP is in approved corporate IP range. Expected behaviour."
                ),
            },
        ],
    })

    # ------------------------------------------------------------------
    # INC-IG-009  Legitimate business travel false positive
    # ------------------------------------------------------------------
    incidents.append({
        "incident_id": "INC-IG-009",
        "scenario": "Legitimate Business Travel False Positive",
        "events": [
            {
                "incident_id": "INC-IG-009",
                "user": "irene.walsh@contoso.com",
                "user_role": "Sales Director",
                "event_time": _ts(2024, 5, 9, 10, 0),
                "event_type": "SignIn",
                "source_ip": "77.111.245.6",
                "country": "Japan",
                "city": "Tokyo",
                "device_id": "DEV-MAC-IRENE-009",
                "device_trust_status": "managed",
                "device_os": "macOS 14",
                "mfa_result": "success",
                "mfa_method": "authenticator_app",
                "app_name": "Salesforce",
                "action": "login_success",
                "oauth_app_name": None,
                "oauth_permission": None,
                "mailbox_action": None,
                "risk_signal": "business_travel",
                "known_vpn": False,
                "impossible_travel_flag": False,
                "failed_login_count": 0,
                "session_id": "sess-irene-009",
                "notes": (
                    "Login from Tokyo. User has approved business travel to Japan "
                    "for Contoso Asia-Pacific conference (May 8–12). "
                    "Travel pre-approved in IT ticketing system. Managed device. Expected."
                ),
            },
        ],
    })

    # ------------------------------------------------------------------
    # INC-IG-010  Managed device login from known location (normal)
    # ------------------------------------------------------------------
    incidents.append({
        "incident_id": "INC-IG-010",
        "scenario": "Managed Device Login from Known Location (Normal Behaviour)",
        "events": [
            {
                "incident_id": "INC-IG-010",
                "user": "james.patel@contoso.com",
                "user_role": "Accountant",
                "event_time": _ts(2024, 5, 10, 9, 0),
                "event_type": "SignIn",
                "source_ip": "72.21.198.64",
                "country": "United States",
                "city": "New York",
                "device_id": "DEV-WIN-JAMES-010",
                "device_trust_status": "managed",
                "device_os": "Windows 11",
                "mfa_result": "success",
                "mfa_method": "authenticator_app",
                "app_name": "Microsoft 365",
                "action": "login_success",
                "oauth_app_name": None,
                "oauth_permission": None,
                "mailbox_action": None,
                "risk_signal": "known_location",
                "known_vpn": False,
                "impossible_travel_flag": False,
                "failed_login_count": 0,
                "session_id": "sess-james-010",
                "notes": (
                    "Standard workday login from corporate NYC office. "
                    "Managed device, known location, MFA success. No risk indicators."
                ),
            },
        ],
    })

    # ------------------------------------------------------------------
    # INC-IG-011  Suspicious login followed by sensitive app access
    # ------------------------------------------------------------------
    incidents.append({
        "incident_id": "INC-IG-011",
        "scenario": "Suspicious Login Followed by Sensitive App Access",
        "events": [
            {
                "incident_id": "INC-IG-011",
                "user": "karen.white@contoso.com",
                "user_role": "HR Manager",
                "event_time": _ts(2024, 5, 11, 4, 5),
                "event_type": "SignIn",
                "source_ip": "103.229.57.24",
                "country": "Singapore",
                "city": "Singapore",
                "device_id": "DEV-UNKNOWN-SG-011",
                "device_trust_status": "unmanaged",
                "device_os": "Windows 10",
                "mfa_result": "success",
                "mfa_method": "sms",
                "app_name": "Azure AD",
                "action": "login_success",
                "oauth_app_name": None,
                "oauth_permission": None,
                "mailbox_action": None,
                "risk_signal": "suspicious_ip",
                "known_vpn": False,
                "impossible_travel_flag": False,
                "failed_login_count": 0,
                "session_id": "sess-karen-011",
                "notes": "Login from Singapore at 04:05 UTC. User normally works from Boston. Unmanaged device.",
            },
            {
                "incident_id": "INC-IG-011",
                "user": "karen.white@contoso.com",
                "user_role": "HR Manager",
                "event_time": _ts(2024, 5, 11, 4, 12),
                "event_type": "AppAccess",
                "source_ip": "103.229.57.24",
                "country": "Singapore",
                "city": "Singapore",
                "device_id": "DEV-UNKNOWN-SG-011",
                "device_trust_status": "unmanaged",
                "device_os": "Windows 10",
                "mfa_result": None,
                "mfa_method": None,
                "app_name": "Workday (HR Systems)",
                "action": "sensitive_app_access",
                "oauth_app_name": None,
                "oauth_permission": None,
                "mailbox_action": None,
                "risk_signal": "sensitive_resource_access_post_suspicious_login",
                "known_vpn": False,
                "impossible_travel_flag": False,
                "failed_login_count": 0,
                "session_id": "sess-karen-011",
                "notes": "Accessed Workday HR system (contains all employee PII and salary data) 7 minutes after suspicious login.",
            },
            {
                "incident_id": "INC-IG-011",
                "user": "karen.white@contoso.com",
                "user_role": "HR Manager",
                "event_time": _ts(2024, 5, 11, 4, 25),
                "event_type": "FileDownload",
                "source_ip": "103.229.57.24",
                "country": "Singapore",
                "city": "Singapore",
                "device_id": "DEV-UNKNOWN-SG-011",
                "device_trust_status": "unmanaged",
                "device_os": "Windows 10",
                "mfa_result": None,
                "mfa_method": None,
                "app_name": "SharePoint Online",
                "action": "bulk_download",
                "oauth_app_name": None,
                "oauth_permission": None,
                "mailbox_action": None,
                "risk_signal": "suspicious_ip",
                "known_vpn": False,
                "impossible_travel_flag": False,
                "failed_login_count": 0,
                "session_id": "sess-karen-011",
                "notes": "Bulk download of 847 HR documents from SharePoint. Triggered DLP alert.",
            },
        ],
    })

    # ------------------------------------------------------------------
    # INC-IG-012  Multi-stage account takeover chain
    # ------------------------------------------------------------------
    incidents.append({
        "incident_id": "INC-IG-012",
        "scenario": "Multi-Stage Account Takeover Chain",
        "events": [
            {
                "incident_id": "INC-IG-012",
                "user": "liam.cooper@contoso.com",
                "user_role": "IT Administrator",
                "event_time": _ts(2024, 5, 12, 1, 0),
                "event_type": "SignIn",
                "source_ip": "159.89.201.11",
                "country": "Romania",
                "city": "Bucharest",
                "device_id": "DEV-UNKNOWN-RO-012",
                "device_trust_status": "unmanaged",
                "device_os": "Windows 10",
                "mfa_result": "denied",
                "mfa_method": "authenticator_push",
                "app_name": "Azure AD",
                "action": "login_failed",
                "oauth_app_name": None,
                "oauth_permission": None,
                "mailbox_action": None,
                "risk_signal": "password_spray",
                "known_vpn": False,
                "impossible_travel_flag": False,
                "failed_login_count": 1,
                "session_id": "sess-liam-012-s1",
                "notes": "Stage 1: Initial credential stuffing attempt from Bucharest. MFA denied.",
            },
            {
                "incident_id": "INC-IG-012",
                "user": "liam.cooper@contoso.com",
                "user_role": "IT Administrator",
                "event_time": _ts(2024, 5, 12, 1, 8),
                "event_type": "MFARequest",
                "source_ip": "159.89.201.11",
                "country": "Romania",
                "city": "Bucharest",
                "device_id": "DEV-UNKNOWN-RO-012",
                "device_trust_status": "unmanaged",
                "device_os": "Windows 10",
                "mfa_result": "denied",
                "mfa_method": "authenticator_push",
                "app_name": "Azure AD",
                "action": "mfa_push_sent",
                "oauth_app_name": None,
                "oauth_permission": None,
                "mailbox_action": None,
                "risk_signal": "mfa_fatigue",
                "known_vpn": False,
                "impossible_travel_flag": False,
                "failed_login_count": 2,
                "session_id": "sess-liam-012-s1",
                "notes": "Stage 2: Second MFA push. Denied.",
            },
            {
                "incident_id": "INC-IG-012",
                "user": "liam.cooper@contoso.com",
                "user_role": "IT Administrator",
                "event_time": _ts(2024, 5, 12, 1, 16),
                "event_type": "MFARequest",
                "source_ip": "159.89.201.11",
                "country": "Romania",
                "city": "Bucharest",
                "device_id": "DEV-UNKNOWN-RO-012",
                "device_trust_status": "unmanaged",
                "device_os": "Windows 10",
                "mfa_result": "denied",
                "mfa_method": "authenticator_push",
                "app_name": "Azure AD",
                "action": "mfa_push_sent",
                "oauth_app_name": None,
                "oauth_permission": None,
                "mailbox_action": None,
                "risk_signal": "mfa_fatigue",
                "known_vpn": False,
                "impossible_travel_flag": False,
                "failed_login_count": 3,
                "session_id": "sess-liam-012-s1",
                "notes": "Stage 2: Third MFA push. Denied.",
            },
            {
                "incident_id": "INC-IG-012",
                "user": "liam.cooper@contoso.com",
                "user_role": "IT Administrator",
                "event_time": _ts(2024, 5, 12, 1, 24),
                "event_type": "MFARequest",
                "source_ip": "159.89.201.11",
                "country": "Romania",
                "city": "Bucharest",
                "device_id": "DEV-UNKNOWN-RO-012",
                "device_trust_status": "unmanaged",
                "device_os": "Windows 10",
                "mfa_result": "success",
                "mfa_method": "authenticator_push",
                "app_name": "Azure AD",
                "action": "login_success",
                "oauth_app_name": None,
                "oauth_permission": None,
                "mailbox_action": None,
                "risk_signal": "mfa_fatigue",
                "known_vpn": False,
                "impossible_travel_flag": False,
                "failed_login_count": 3,
                "session_id": "sess-liam-012-s2",
                "notes": "Stage 2: Fourth MFA push APPROVED. User likely approved out of fatigue.",
            },
            {
                "incident_id": "INC-IG-012",
                "user": "liam.cooper@contoso.com",
                "user_role": "IT Administrator",
                "event_time": _ts(2024, 5, 12, 1, 30),
                "event_type": "OAuthConsent",
                "source_ip": "159.89.201.11",
                "country": "Romania",
                "city": "Bucharest",
                "device_id": "DEV-UNKNOWN-RO-012",
                "device_trust_status": "unmanaged",
                "device_os": "Windows 10",
                "mfa_result": None,
                "mfa_method": None,
                "app_name": "Azure AD",
                "action": "oauth_consent_granted",
                "oauth_app_name": "DataSyncHelper",
                "oauth_permission": "Mail.ReadWrite",
                "mailbox_action": None,
                "risk_signal": "oauth_consent_to_unverified_app",
                "known_vpn": False,
                "impossible_travel_flag": False,
                "failed_login_count": 0,
                "session_id": "sess-liam-012-s2",
                "notes": "Stage 3: OAuth consent granted to 'DataSyncHelper' for Mail.ReadWrite. Unverified publisher.",
            },
            {
                "incident_id": "INC-IG-012",
                "user": "liam.cooper@contoso.com",
                "user_role": "IT Administrator",
                "event_time": _ts(2024, 5, 12, 1, 37),
                "event_type": "MailboxRuleCreated",
                "source_ip": "159.89.201.11",
                "country": "Romania",
                "city": "Bucharest",
                "device_id": "DEV-UNKNOWN-RO-012",
                "device_trust_status": "unmanaged",
                "device_os": "Windows 10",
                "mfa_result": None,
                "mfa_method": None,
                "app_name": "Outlook Web Access",
                "action": "inbox_rule_created",
                "oauth_app_name": None,
                "oauth_permission": None,
                "mailbox_action": "forwarding_rule_created",
                "risk_signal": "inbox_rule_post_suspicious_login",
                "known_vpn": False,
                "impossible_travel_flag": False,
                "failed_login_count": 0,
                "session_id": "sess-liam-012-s2",
                "notes": "Stage 4: Mailbox forwarding rule created. All inbound mail forwarded to exfil99@tutanota.com.",
            },
            {
                "incident_id": "INC-IG-012",
                "user": "liam.cooper@contoso.com",
                "user_role": "IT Administrator",
                "event_time": _ts(2024, 5, 12, 1, 45),
                "event_type": "AdminPasswordChange",
                "source_ip": "159.89.201.11",
                "country": "Romania",
                "city": "Bucharest",
                "device_id": "DEV-UNKNOWN-RO-012",
                "device_trust_status": "unmanaged",
                "device_os": "Windows 10",
                "mfa_result": None,
                "mfa_method": None,
                "app_name": "Azure AD",
                "action": "password_reset",
                "oauth_app_name": None,
                "oauth_permission": None,
                "mailbox_action": None,
                "risk_signal": "password_reset",
                "known_vpn": False,
                "impossible_travel_flag": False,
                "failed_login_count": 0,
                "session_id": "sess-liam-012-s2",
                "notes": (
                    "Stage 5: Password changed by attacker session to lock out legitimate user. "
                    "IT Admin account fully compromised."
                ),
            },
        ],
    })

    return incidents


# ---------------------------------------------------------------------------
# Save to JSON
# ---------------------------------------------------------------------------

def save_demo_incidents(incidents: list, path: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(incidents, f, indent=2, default=str)
    print(f"[+] Saved {len(incidents)} demo incidents -> {path}")


def load_demo_incidents(path: str) -> list:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


# ---------------------------------------------------------------------------
# Run triage on all demo incidents and return TriageResult list
# ---------------------------------------------------------------------------

def triage_all_demo_incidents(incidents: list) -> list:
    results = []
    for inc in incidents:
        result = score_incident(inc["incident_id"], inc["events"])
        results.append(result)
    return results


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def _print_summary_table(results: list) -> None:
    col_w = [14, 40, 10, 10, 8, 8, 30]
    header = ["Incident ID", "Scenario / Detections", "Score", "Level", "Conf", "FP%", "Escalation"]
    sep = "  ".join("-" * w for w in col_w)
    fmt = "  ".join(f"{{:<{w}}}" for w in col_w)

    print("\n" + "=" * 130)
    print(" IdentityGuard AI — Phase 2 Triage Results")
    print("=" * 130)
    print(fmt.format(*header))
    print(sep)

    # We need scenario names — zip results with incidents
    demo = build_demo_incidents()
    scenario_map = {d["incident_id"]: d["scenario"] for d in demo}

    for r in results:
        scenario = scenario_map.get(r.incident_id, "")
        # Abbreviate detections for the table
        detections = ", ".join(r.detection_types[:2]) + ("…" if len(r.detection_types) > 2 else "")
        label = f"{scenario[:30]}"
        score_str = str(r.risk_score)
        fp_str = f"{r.false_positive_likelihood}%"
        print(fmt.format(
            r.incident_id,
            label,
            score_str,
            r.risk_level,
            r.confidence,
            fp_str,
            r.escalation_decision,
        ))

    print(sep)
    print(f"  Total incidents triaged: {len(results)}")
    critical = sum(1 for r in results if r.risk_level == "CRITICAL")
    high = sum(1 for r in results if r.risk_level == "HIGH")
    medium = sum(1 for r in results if r.risk_level == "MEDIUM")
    low = sum(1 for r in results if r.risk_level == "LOW")
    print(f"  CRITICAL: {critical}  HIGH: {high}  MEDIUM: {medium}  LOW: {low}")
    print("=" * 130 + "\n")


if __name__ == "__main__":
    SAMPLE_PATH = os.path.join(
        os.path.dirname(__file__), "sample_events", "demo_incidents.json"
    )

    print("[*] Building demo incidents...")
    incidents = build_demo_incidents()

    print(f"[*] Saving to {SAMPLE_PATH}...")
    save_demo_incidents(incidents, SAMPLE_PATH)

    print("[*] Running identity triage on all 12 incidents...")
    results = triage_all_demo_incidents(incidents)

    _print_summary_table(results)

    print("[*] Scoring breakdown for INC-IG-012 (multi-stage ATO chain):")
    for r in results:
        if r.incident_id == "INC-IG-012":
            print(f"    Score : {r.risk_score}")
            print(f"    Level : {r.risk_level}")
            print(f"    MITRE : {r.mitre_techniques}")
            print("    Reasons:")
            for line in r.scoring_reasons.splitlines():
                print(f"      {line}")
            break

    print("\n[+] Phase 2 engine test complete.")
