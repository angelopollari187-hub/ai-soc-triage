import os
import requests

from logger_config import get_logger

logger = get_logger("notifier")


def get_severity_emoji(risk_level: str) -> str:
    risk = (risk_level or "").upper()

    if risk == "CRITICAL":
        return "🚨"
    if risk == "HIGH":
        return "⚠️"
    if risk == "MEDIUM":
        return "🟡"
    if risk == "LOW":
        return "🟢"

    return "ℹ️"


def send_slack_alert(alert: dict) -> bool:
    webhook_url = os.getenv("SLACK_WEBHOOK_URL")

    if not webhook_url:
        message = "[!] SLACK_WEBHOOK_URL not found. Skipping Slack alert."
        print(message)
        logger.warning(message)
        return False

    risk_level = alert.get("risk_level", "UNKNOWN")
    mitre = alert.get("mitre_technique", "N/A")
    source_file = alert.get("source_file", "N/A")
    confidence = alert.get("confidence", "N/A")
    false_positive = alert.get("false_positive_likelihood", "N/A")
    recommended_action = alert.get("recommended_action", "N/A")
    enrichment = alert.get("enrichment", {})

    emoji = get_severity_emoji(risk_level)

    payload = {
        "text": f"{emoji} AI-SOC Triage Alert - {risk_level}",
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{emoji} AI-SOC Triage Alert",
                    "emoji": True,
                },
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Risk Level:*\n{risk_level}"},
                    {"type": "mrkdwn", "text": f"*Confidence:*\n{confidence}"},
                    {"type": "mrkdwn", "text": f"*MITRE Technique:*\n{mitre}"},
                    {"type": "mrkdwn", "text": f"*False Positive Likelihood:*\n{false_positive}%"},
                ],
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Source File:*\n`{source_file}`",
                },
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Enriched IP:*\n{enrichment.get('ip', 'N/A')}"},
                    {"type": "mrkdwn", "text": f"*Location:*\n{enrichment.get('city', 'N/A')}, {enrichment.get('country', 'N/A')}"},
                    {"type": "mrkdwn", "text": f"*ASN / Org:*\n{enrichment.get('asn', 'N/A')}"},
                    {
                        "type": "mrkdwn",
                        "text": (
                            f"*Hosting / Proxy:*\n"
                            f"Hosting: {enrichment.get('hosting', 'N/A')} | "
                            f"Proxy: {enrichment.get('proxy', 'N/A')}"
                        ),
                    },
                ],
            },
            {"type": "divider"},
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Recommended Action:*\n{recommended_action}",
                },
            },
        ],
    }

    try:
        response = requests.post(webhook_url, json=payload, timeout=10)
        response.raise_for_status()

        success_msg = "[+] Slack alert sent successfully."
        print(success_msg)
        logger.info(success_msg)
        return True

    except requests.RequestException as e:
        error_msg = f"[-] Failed to send Slack alert: {e}"
        print(error_msg)
        logger.error(error_msg)
        return False