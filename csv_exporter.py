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
    "recommended_action",
]


def append_alert_to_csv(alert: dict, csv_path: str = "output/alerts_summary.csv") -> bool:
    """
    Appends a structured SOC alert row to a CSV summary file.
    Creates the output directory and CSV headers if needed.
    """
    try:
        os.makedirs(os.path.dirname(csv_path), exist_ok=True)

        enrichment = alert.get("enrichment", {})

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
            "recommended_action": alert.get("recommended_action", "N/A"),
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