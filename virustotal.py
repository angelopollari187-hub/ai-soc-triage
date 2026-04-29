import os
import requests

from logger_config import get_logger

logger = get_logger("virustotal")


def get_vt_verdict(malicious, suspicious, reputation) -> str:
    try:
        malicious = int(malicious)
        suspicious = int(suspicious)
        reputation = int(reputation)
    except (ValueError, TypeError):
        return "Unknown"

    if malicious > 0:
        return "Malicious"
    if suspicious > 0:
        return "Suspicious"
    if reputation < 0:
        return "Low Reputation"
    return "Clean / Unknown"


def lookup_ip_virustotal(ip_address: str | None) -> dict:
    api_key = os.getenv("VIRUSTOTAL_API_KEY")

    if not ip_address or ip_address == "N/A":
        return {
            "vt_status": "No IP provided",
            "vt_verdict": "N/A",
            "vt_malicious": "N/A",
            "vt_suspicious": "N/A",
            "vt_harmless": "N/A",
            "vt_undetected": "N/A",
            "vt_reputation": "N/A",
        }

    if not api_key:
        logger.warning("VIRUSTOTAL_API_KEY not found. Skipping VirusTotal lookup.")
        return {
            "vt_status": "API key missing",
            "vt_verdict": "N/A",
            "vt_malicious": "N/A",
            "vt_suspicious": "N/A",
            "vt_harmless": "N/A",
            "vt_undetected": "N/A",
            "vt_reputation": "N/A",
        }

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
    headers = {"x-apikey": api_key}

    try:
        response = requests.get(url, headers=headers, timeout=10)

        if response.status_code == 429:
            logger.warning("VirusTotal rate limit reached.")
            return {
                "vt_status": "Rate limited",
                "vt_verdict": "N/A",
                "vt_malicious": "N/A",
                "vt_suspicious": "N/A",
                "vt_harmless": "N/A",
                "vt_undetected": "N/A",
                "vt_reputation": "N/A",
            }

        response.raise_for_status()
        data = response.json()

        attributes = data.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        reputation = attributes.get("reputation", 0)

        return {
            "vt_status": "Success",
            "vt_verdict": get_vt_verdict(malicious, suspicious, reputation),
            "vt_malicious": malicious,
            "vt_suspicious": suspicious,
            "vt_harmless": harmless,
            "vt_undetected": undetected,
            "vt_reputation": reputation,
        }

    except requests.RequestException as e:
        logger.error(f"VirusTotal lookup failed for {ip_address}: {e}")
        return {
            "vt_status": "Request failed",
            "vt_verdict": "N/A",
            "vt_malicious": "N/A",
            "vt_suspicious": "N/A",
            "vt_harmless": "N/A",
            "vt_undetected": "N/A",
            "vt_reputation": "N/A",
        }