import ipaddress
import re
from typing import Optional

import requests

from logger_config import get_logger

logger = get_logger("enrichment")


IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def extract_public_ip(text: str) -> Optional[str]:
    """
    Extracts the first public IPv4 address from log text.
    Skips private, loopback, reserved, multicast, and invalid IPs.
    """
    candidates = IP_PATTERN.findall(text)

    for candidate in candidates:
        try:
            ip_obj = ipaddress.ip_address(candidate)

            if (
                ip_obj.is_private
                or ip_obj.is_loopback
                or ip_obj.is_reserved
                or ip_obj.is_multicast
            ):
                continue

            return candidate

        except ValueError:
            continue

    return None


def enrich_ip(ip_address: Optional[str]) -> dict:
    """
    Enriches a public IP using ip-api.com.
    Returns safe fallback values if no public IP is found or lookup fails.
    """
    if not ip_address:
        return {
            "ip": "N/A",
            "country": "N/A",
            "city": "N/A",
            "region": "N/A",
            "org": "N/A",
            "asn": "N/A",
            "isp": "N/A",
            "hosting": "N/A",
            "proxy": "N/A",
            "enrichment_status": "No public IP found",
        }

    url = (
        f"http://ip-api.com/json/{ip_address}"
        "?fields=status,message,query,country,regionName,city,isp,org,as,proxy,hosting"
    )

    try:
        response = requests.get(url, timeout=8)
        response.raise_for_status()
        data = response.json()

        if data.get("status") != "success":
            return {
                "ip": ip_address,
                "country": "N/A",
                "city": "N/A",
                "region": "N/A",
                "org": "N/A",
                "asn": "N/A",
                "isp": "N/A",
                "hosting": "N/A",
                "proxy": "N/A",
                "enrichment_status": f"Lookup failed: {data.get('message', 'unknown')}",
            }

        return {
            "ip": data.get("query", ip_address),
            "country": data.get("country", "N/A"),
            "city": data.get("city", "N/A"),
            "region": data.get("regionName", "N/A"),
            "org": data.get("org", "N/A"),
            "asn": data.get("as", "N/A"),
            "isp": data.get("isp", "N/A"),
            "hosting": data.get("hosting", "N/A"),
            "proxy": data.get("proxy", "N/A"),
            "enrichment_status": "Success",
        }

    except requests.RequestException as e:
        logger.error(f"IP enrichment failed for {ip_address}: {e}")

        return {
            "ip": ip_address,
            "country": "N/A",
            "city": "N/A",
            "region": "N/A",
            "org": "N/A",
            "asn": "N/A",
            "isp": "N/A",
            "hosting": "N/A",
            "proxy": "N/A",
            "enrichment_status": "Request failed",
        }