import csv
import os

from logger_config import get_logger

logger = get_logger("csv_exporter")


CSV_HEADERS = [
    "incident_id",
    "timestamp",
    "status",
    "source_file",
    "risk_level",
    "mitre_technique",
    "confidence",
    "false_positive_likelihood",
    "enriched_ip",
    "country",
    "city",
    "asn_org",
    "hosting",
    "proxy",
    "vt_status",
    "vt_malicious",
    "vt_suspicious",
    "vt_harmless",
    "vt_undetected",
    "vt_reputation",
    "recommended_action",
    "vt_verdict",
    "analyst_insight",
]


def append_alert_to_csv(alert: dict, csv_path: str = "output/alerts_summary.csv") -> bool:
    """
    Appends a structured SOC alert row to a CSV summary file.
    Creates the output directory and CSV headers if needed.
    """
    try:
        os.makedirs(os.path.dirname(csv_path), exist_ok=True)

        enrichment = alert.get("enrichment", {})
        virustotal = alert.get("virustotal", {})

        row = {
            "incident_id": alert.get("incident_id", "N/A"),
            "timestamp": alert.get("timestamp", "N/A"),
            "status": alert.get("status", "N/A"),
            "source_file": alert.get("source_file", "N/A"),
            "risk_level": alert.get("risk_level", "N/A"),
            "mitre_technique": alert.get("mitre_technique", "N/A"),
            "confidence": alert.get("confidence", "N/A"),
            "false_positive_likelihood": alert.get("false_positive_likelihood", "N/A"),
            "enriched_ip": enrichment.get("ip", "N/A"),
            "country": enrichment.get("country", "N/A"),
            "city": enrichment.get("city", "N/A"),
            "asn_org": enrichment.get("asn", "N/A"),
            "hosting": enrichment.get("hosting", "N/A"),
            "proxy": enrichment.get("proxy", "N/A"),
            "vt_status": virustotal.get("vt_status", "N/A"),
            "vt_malicious": virustotal.get("vt_malicious", "N/A"),
            "vt_suspicious": virustotal.get("vt_suspicious", "N/A"),
            "vt_harmless": virustotal.get("vt_harmless", "N/A"),
            "vt_undetected": virustotal.get("vt_undetected", "N/A"),
            "vt_reputation": virustotal.get("vt_reputation", "N/A"),
            "recommended_action": alert.get("recommended_action", "N/A"),
            "vt_verdict": virustotal.get("vt_verdict", "N/A"),
            "analyst_insight": alert.get("analyst_insight", "N/A"),
        }

        file_exists = os.path.isfile(csv_path)

        with open(csv_path, "a", newline="", encoding="utf-8") as csv_file:
            writer = csv.DictWriter(csv_file, fieldnames=CSV_HEADERS)

            if not file_exists:
                writer.writeheader()

            writer.writerow(row)

        logger.info(f"CSV alert appended to {csv_path}")
        return True

    except Exception as e:
        logger.error(f"Failed to append alert to CSV: {e}")
        return False