import argparse
import json
import os
from datetime import datetime


MITRE_MAP = {
    "impossible_travel": {
        "tactic": "Initial Access",
        "technique": "T1078 - Valid Accounts",
        "confidence_hint": "HIGH",
        "scenario": "Potential account takeover through impossible travel authentication pattern.",
    },
    "abnormal_login_volume": {
        "tactic": "Credential Access",
        "technique": "T1110 - Brute Force",
        "confidence_hint": "MEDIUM-HIGH",
        "scenario": "Potential brute force or password spraying activity.",
    },
    "suspicious_data_transfer": {
        "tactic": "Exfiltration",
        "technique": "T1048 - Exfiltration Over Alternative Protocol",
        "confidence_hint": "HIGH",
        "scenario": "Potential outbound data exfiltration to an unusual external destination.",
    },
    "privileged_account_anomaly": {
        "tactic": "Persistence / Privilege Escalation",
        "technique": "T1098 - Account Manipulation",
        "confidence_hint": "HIGH",
        "scenario": "Potential privileged account misuse or unauthorized administrative change.",
    },
}


def load_alert(alert_path: str) -> dict:
    with open(alert_path, "r", encoding="utf-8") as f:
        return json.load(f)


def detect_alert_type(alert: dict, alert_path: str) -> str:
    if alert.get("alert_type"):
        return alert["alert_type"]

    if alert.get("alert_name"):
        name = alert["alert_name"].lower()

        if "impossible travel" in name:
            return "impossible_travel"
        if "login" in name or "brute" in name:
            return "abnormal_login_volume"
        if "data" in name or "transfer" in name or "exfil" in name:
            return "suspicious_data_transfer"
        if "privileged" in name or "admin" in name:
            return "privileged_account_anomaly"

    filename = os.path.basename(alert_path).lower()

    if "impossible" in filename:
        return "impossible_travel"
    if "login" in filename:
        return "abnormal_login_volume"
    if "transfer" in filename or "exfil" in filename:
        return "suspicious_data_transfer"
    if "privileged" in filename or "admin" in filename:
        return "privileged_account_anomaly"

    return "generic_alert"


def normalize_risk_score(value) -> str:
    if isinstance(value, str):
        value_upper = value.upper()
        if value_upper in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
            return value_upper

        try:
            value = int(value)
        except ValueError:
            return "MEDIUM"

    try:
        score = int(value)
    except (TypeError, ValueError):
        return "MEDIUM"

    if score >= 90:
        return "CRITICAL"
    if score >= 70:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    return "LOW"


def build_raw_events(alert: dict) -> str:
    raw_events = alert.get("raw_events", [])

    if isinstance(raw_events, list) and raw_events:
        return "\n".join(raw_events)

    return "No raw events provided."


def get_mitre_context(alert_type: str) -> dict:
    return MITRE_MAP.get(
        alert_type,
        {
            "tactic": "Unknown",
            "technique": "N/A",
            "confidence_hint": "MEDIUM",
            "scenario": "Generic SIEM alert requiring analyst review.",
        },
    )


def convert_alert_to_log(alert: dict, alert_path: str) -> str:
    alert_type = detect_alert_type(alert, alert_path)
    mitre = get_mitre_context(alert_type)

    risk_value = alert.get("risk_score") or alert.get("risk_level") or alert.get("severity")
    normalized_risk = normalize_risk_score(risk_value)

    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    common_context = f"""
SIEM / UEBA ALERT NORMALIZED FOR AI-SOC TRIAGE

Generated At: {generated_at}
Original File: {alert_path}
Alert Type: {alert_type}
Alert Name: {alert.get("alert_name", alert_type.replace("_", " ").title())}
Source Platform: {alert.get("source", "Splunk UEBA Simulation")}
User: {alert.get("user", "N/A")}
Source IP: {alert.get("src_ip", alert.get("source_ip", "N/A"))}
Destination IP: {alert.get("dest_ip", alert.get("destination_ip", "N/A"))}
Risk Score / Severity: {risk_value}
Normalized Risk Hint: {normalized_risk}

Expected MITRE Context:
Tactic: {mitre["tactic"]}
Technique: {mitre["technique"]}
Confidence Hint: {mitre["confidence_hint"]}

Scenario Context:
{mitre["scenario"]}

Description:
{alert.get("description", "N/A")}
"""

    if alert_type == "impossible_travel":
        scenario_details = f"""
Scenario-Specific Fields:
User: {alert.get("user", "N/A")}
Source IP: {alert.get("src_ip", "N/A")}
Destination IP: {alert.get("dest_ip", "N/A")}
Risk Score: {alert.get("risk_score", "N/A")}
Behavior: Successful authentications from geographically distant locations within an unrealistic time window.
Primary Concern: Possible account takeover using valid credentials.
False Positive Considerations: VPN, proxy, travel, cloud login routing, shared account, or identity provider location mismatch.
"""

    elif alert_type == "abnormal_login_volume":
        scenario_details = f"""
Scenario-Specific Fields:
User: {alert.get("user", "N/A")}
Source IP: {alert.get("source_ip", alert.get("src_ip", "N/A"))}
Failed Attempts: {alert.get("failed_attempts", "N/A")}
Success After Failures: {alert.get("success_after_failures", "N/A")}
Target System: {alert.get("target_system", "N/A")}
Behavior: High volume of failed login attempts followed by a possible successful authentication.
Primary Concern: Password spraying, brute force, or credential stuffing.
False Positive Considerations: User lockout recovery, mistyped password loop, misconfigured service account, or automated application retry.
"""

    elif alert_type == "suspicious_data_transfer":
        scenario_details = f"""
Scenario-Specific Fields:
User: {alert.get("user", "N/A")}
Source IP: {alert.get("source_ip", alert.get("src_ip", "N/A"))}
Destination IP: {alert.get("destination_ip", alert.get("dest_ip", "N/A"))}
Destination Domain: {alert.get("destination_domain", "N/A")}
Destination Country: {alert.get("destination_country", "N/A")}
Bytes Transferred MB: {alert.get("bytes_transferred_mb", "N/A")}
Protocol: {alert.get("protocol", "N/A")}
Behavior: Large outbound data transfer to a previously unseen or unusual destination.
Primary Concern: Data exfiltration over HTTPS or cloud storage.
False Positive Considerations: Backup job, CI/CD artifact upload, cloud sync client, legitimate developer tooling, or authorized vendor transfer.
"""

    elif alert_type == "privileged_account_anomaly":
        scenario_details = f"""
Scenario-Specific Fields:
User: {alert.get("user", "N/A")}
Source IP: {alert.get("source_ip", alert.get("src_ip", "N/A"))}
Activity: {alert.get("activity", "N/A")}
New Account: {alert.get("new_account", "N/A")}
Privilege Level: {alert.get("privilege_level", "N/A")}
Location: {alert.get("location", "N/A")}
Behavior: Privileged user performed unusual administrative activity outside the normal behavior window.
Primary Concern: Unauthorized privilege escalation, persistence, or account manipulation.
False Positive Considerations: Approved maintenance window, helpdesk admin task, onboarding/offboarding workflow, or scheduled group policy change.
"""

    else:
        scenario_details = """
Scenario-Specific Fields:
Generic alert type. Analyst should review all provided fields and raw events.
"""

    raw_events = f"""
Raw Events:
{build_raw_events(alert)}
"""

    return f"{common_context}\n{scenario_details}\n{raw_events}".strip()


def save_converted_log(alert_path: str, log_text: str) -> str:
    os.makedirs("generated_logs", exist_ok=True)

    base_name = os.path.basename(alert_path).replace(".json", "")
    output_path = os.path.join("generated_logs", f"{base_name}.txt")

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(log_text)

    return output_path


def process_single_alert(alert_path: str) -> str:
    alert = load_alert(alert_path)
    alert_type = detect_alert_type(alert, alert_path)
    log_text = convert_alert_to_log(alert, alert_path)
    output_path = save_converted_log(alert_path, log_text)

    print(f"[+] Alert type detected: {alert_type}")
    print(f"[+] Converted alert to triage log: {output_path}")
    print(f"    py triage.py --log {output_path} --save --json")

    return output_path


def process_batch(alert_dir: str) -> list[str]:
    if not os.path.isdir(alert_dir):
        raise ValueError(f"Batch path is not a directory: {alert_dir}")

    converted_logs = []

    for filename in os.listdir(alert_dir):
        if filename.endswith(".json"):
            alert_path = os.path.join(alert_dir, filename)
            print(f"\n[+] Processing alert file: {alert_path}")
            output_path = process_single_alert(alert_path)
            converted_logs.append(output_path)

    print("\n=== Batch Conversion Summary ===")
    print(f"Total alerts converted: {len(converted_logs)}")

    if converted_logs:
        print("\nNext option:")
        print("Run all generated logs through triage:")
        print("    py triage.py --batch generated_logs/ --save --json")

    return converted_logs


def main():
    parser = argparse.ArgumentParser(
        description="Convert SIEM/UEBA alert JSON into AI-SOC triage log input"
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--alert", help="Path to a single SIEM/UEBA alert JSON file")
    group.add_argument("--batch", help="Directory of SIEM/UEBA alert JSON files")

    args = parser.parse_args()

    if args.alert:
        process_single_alert(args.alert)

    if args.batch:
        process_batch(args.batch)


if __name__ == "__main__":
    main()