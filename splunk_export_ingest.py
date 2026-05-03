"""
splunk_export_ingest.py

Converts a Splunk-style alert export CSV into triage-ready .txt log bundles.

Workflow:
    Splunk export CSV
    → generated_logs/splunk_alert_001.txt
    → triage.py --batch generated_logs --save --json
    → dashboard.py

Example:
    python splunk_export_ingest.py --csv splunk_exports/sample_splunk_alert_export.csv --out generated_logs
"""

import argparse
import csv
from pathlib import Path
from datetime import datetime


DEFAULT_FIELDS = [
    "_time",
    "index",
    "sourcetype",
    "host",
    "source",
    "event_id",
    "signature",
    "severity",
    "user",
    "src_ip",
    "dest_ip",
    "process_name",
    "command_line",
    "url",
    "file_hash",
    "action",
    "raw",
]


def clean(value: str, fallback: str = "N/A") -> str:
    """Return a clean string for report generation."""
    if value is None:
        return fallback

    value = str(value).strip()
    return value if value else fallback


def build_log_bundle(row: dict, row_num: int) -> str:
    """
    Convert one Splunk CSV row into a readable triage log bundle.
    This keeps the raw alert context together so triage.py can review it as one incident.
    """
    event_id = clean(row.get("event_id"), f"SPL-{row_num:03d}")
    signature = clean(row.get("signature"), "Splunk Alert")
    severity = clean(row.get("severity"), "Unknown")
    timestamp = clean(row.get("_time"), datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    index = clean(row.get("index"))
    sourcetype = clean(row.get("sourcetype"))
    source = clean(row.get("source"))
    host = clean(row.get("host"))

    user = clean(row.get("user"))
    src_ip = clean(row.get("src_ip"))
    dest_ip = clean(row.get("dest_ip"))
    process_name = clean(row.get("process_name"))
    command_line = clean(row.get("command_line"))
    url = clean(row.get("url"))
    file_hash = clean(row.get("file_hash"))
    action = clean(row.get("action"))
    raw = clean(row.get("raw"))

    return f"""Splunk Alert Export - AI-SOC Triage Input

Alert Metadata:
Event ID: {event_id}
Timestamp: {timestamp}
Signature: {signature}
Severity: {severity}
Action: {action}

Splunk Context:
Index: {index}
Sourcetype: {sourcetype}
Source: {source}
Host: {host}

Entities / Indicators:
User: {user}
Source IP: {src_ip}
Destination IP: {dest_ip}
Process Name: {process_name}
Command Line: {command_line}
URL: {url}
File Hash: {file_hash}

Raw Event:
{raw}

Analyst Instruction:
Review this Splunk alert export as one security incident. Classify the risk level, map the activity to MITRE ATT&CK where possible, estimate confidence and false-positive likelihood, identify important indicators, and recommend next SOC validation steps.
"""


def clear_existing_splunk_logs(output_dir: Path) -> int:
    """
    Remove old splunk_alert_*.txt files from generated_logs/.
    Does not delete other generated logs.
    """
    deleted = 0

    for file_path in output_dir.glob("splunk_alert_*.txt"):
        if file_path.is_file():
            file_path.unlink()
            deleted += 1

    return deleted


def convert_splunk_csv(csv_path: Path, output_dir: Path, clear_old: bool = False) -> int:
    """
    Convert Splunk CSV rows into generated .txt files.
    Returns number of log bundles created.
    """
    if not csv_path.exists():
        raise FileNotFoundError(f"CSV not found: {csv_path}")

    output_dir.mkdir(parents=True, exist_ok=True)

    if clear_old:
        deleted = clear_existing_splunk_logs(output_dir)
        print(f"[i] Cleared {deleted} old Splunk-generated log file(s).")

    created = 0

    with open(csv_path, "r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)

        if not reader.fieldnames:
            raise ValueError("CSV has no header row.")

        for row_num, row in enumerate(reader, start=1):
            event_id = clean(row.get("event_id"), f"SPL-{row_num:03d}")
            safe_event_id = event_id.lower().replace(" ", "_").replace("/", "_").replace("\\", "_")

            output_file = output_dir / f"splunk_alert_{row_num:03d}_{safe_event_id}.txt"
            log_bundle = build_log_bundle(row, row_num)

            with open(output_file, "w", encoding="utf-8") as out:
                out.write(log_bundle)

            created += 1
            print(f"[+] Created {output_file}")

    return created


def main():
    parser = argparse.ArgumentParser(description="Convert Splunk alert export CSV into triage-ready logs.")

    parser.add_argument(
        "--csv",
        required=True,
        help="Path to Splunk alert export CSV.",
    )

    parser.add_argument(
        "--out",
        default="generated_logs",
        help="Output folder for generated .txt log bundles. Default: generated_logs",
    )

    parser.add_argument(
        "--clear-old",
        action="store_true",
        help="Delete old generated_logs/splunk_alert_*.txt files before creating new ones.",
    )

    args = parser.parse_args()

    csv_path = Path(args.csv)
    output_dir = Path(args.out)

    try:
        count = convert_splunk_csv(
            csv_path=csv_path,
            output_dir=output_dir,
            clear_old=args.clear_old,
        )

        print("=" * 70)
        print(f"[✓] Converted {count} Splunk alert(s) into triage-ready log bundle(s).")
        print(f"[i] Next: python triage.py --batch {output_dir} --save --json")
        print("=" * 70)

    except Exception as e:
        print(f"[!] Splunk export ingestion failed: {e}")
        raise


if __name__ == "__main__":
    main()