"""
IdentityGuard AI — Identity Alert CSV Exporter

Writes TriageResult objects to output/identity_alerts.csv.
Keeps this file completely separate from output/alerts_summary.csv
so the general SOC triage pipeline is never affected.
"""

from __future__ import annotations

import csv
import os
from datetime import datetime, timezone
from typing import List

from identityguard.identity_scoring import TriageResult


OUTPUT_PATH = os.path.join("output", "identity_alerts.csv")

FIELDNAMES = [
    "incident_id",
    "user",
    "detection_type",       # primary detection (first in list)
    "all_detections",       # all triggered detections, pipe-separated
    "risk_score",
    "risk_level",
    "confidence",
    "false_positive_likelihood",
    "identity_indicators",
    "scoring_reasons",
    "mitre_techniques",
    "zero_trust_gaps",
    "recommended_actions",
    "escalation_decision",
    "status",
    "analyst_notes",        # blank on creation, analyst can fill in dashboard
    "ai_summary",           # blank on creation, filled after AI call
    "created_at",
    "updated_at",
]


def _ensure_output_dir() -> None:
    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)


def _result_to_row(result: TriageResult) -> dict:
    primary_detection = result.detection_types[0] if result.detection_types else "none"
    all_detections = " | ".join(result.detection_types) if result.detection_types else "none"
    now = datetime.now(timezone.utc).isoformat()
    return {
        "incident_id":              result.incident_id,
        "user":                     result.user,
        "detection_type":           primary_detection,
        "all_detections":           all_detections,
        "risk_score":               result.risk_score,
        "risk_level":               result.risk_level,
        "confidence":               result.confidence,
        "false_positive_likelihood": result.false_positive_likelihood,
        "identity_indicators":      result.identity_indicators,
        "scoring_reasons":          result.scoring_reasons,
        "mitre_techniques":         result.mitre_techniques,
        "zero_trust_gaps":          result.zero_trust_gaps,
        "recommended_actions":      result.recommended_actions,
        "escalation_decision":      result.escalation_decision,
        "status":                   result.status,
        "analyst_notes":            "",
        "ai_summary":               "",
        "created_at":               result.created_at,
        "updated_at":               now,
    }


def write_results(results: List[TriageResult], path: str = OUTPUT_PATH) -> str:
    """
    Write a list of TriageResult objects to a CSV file.
    Overwrites the file completely (suitable for demo data reload).

    Returns the absolute path to the written file.
    """
    _ensure_output_dir()
    abs_path = os.path.abspath(path)

    with open(abs_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        writer.writeheader()
        for result in results:
            writer.writerow(_result_to_row(result))

    return abs_path


def append_result(result: TriageResult, path: str = OUTPUT_PATH) -> str:
    """
    Append a single TriageResult to the CSV.
    Creates the file with headers if it does not exist.

    Returns the absolute path.
    """
    _ensure_output_dir()
    abs_path = os.path.abspath(path)
    file_exists = os.path.isfile(abs_path)

    with open(abs_path, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        if not file_exists:
            writer.writeheader()
        writer.writerow(_result_to_row(result))

    return abs_path


def update_status(incident_id: str, new_status: str,
                  analyst_notes: str = "", path: str = OUTPUT_PATH) -> bool:
    """
    Update the status (and optionally analyst_notes) for a specific incident_id.
    Reads the CSV, modifies the matching row(s), and writes back.

    Returns True if at least one row was updated.
    """
    abs_path = os.path.abspath(path)
    if not os.path.isfile(abs_path):
        return False

    rows = []
    updated = False
    now = datetime.now(timezone.utc).isoformat()

    with open(abs_path, "r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row.get("incident_id") == incident_id:
                row["status"] = new_status
                row["updated_at"] = now
                if analyst_notes:
                    row["analyst_notes"] = analyst_notes
                updated = True
            rows.append(row)

    if updated:
        with open(abs_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
            writer.writeheader()
            writer.writerows(rows)

    return updated


def update_ai_summary(incident_id: str, ai_summary: str,
                      path: str = OUTPUT_PATH) -> bool:
    """
    Write the AI-generated summary text back to the matching incident row.
    Called after the analyst clicks 'Generate AI Summary' in the dashboard.

    Returns True if the row was found and updated.
    """
    abs_path = os.path.abspath(path)
    if not os.path.isfile(abs_path):
        return False

    rows = []
    updated = False
    now = datetime.now(timezone.utc).isoformat()

    with open(abs_path, "r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row.get("incident_id") == incident_id:
                row["ai_summary"] = ai_summary
                row["updated_at"] = now
                updated = True
            rows.append(row)

    if updated:
        with open(abs_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
            writer.writeheader()
            writer.writerows(rows)

    return updated


def load_results(path: str = OUTPUT_PATH) -> list:
    """
    Load all rows from identity_alerts.csv as a list of dicts.
    Returns an empty list if the file does not exist.
    """
    abs_path = os.path.abspath(path)
    if not os.path.isfile(abs_path):
        return []
    with open(abs_path, "r", newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))
