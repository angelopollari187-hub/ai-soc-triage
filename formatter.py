def format_report(data: dict, log_filename: str) -> str:
    divider = "=" * 56
    thin = "-" * 56

    fp = data.get("false_positive_likelihood", "N/A")
    fp_str = f"{fp}%" if isinstance(fp, int) else str(fp)

    report = f"""
{divider}
AI-SOC TRIAGE REPORT
File: {log_filename}
{divider}

INCIDENT SUMMARY:
{data.get("incident_summary", "N/A")}

{thin}
MITRE ATT&CK MAPPING:
Tactic: {data.get("attack_tactic", "N/A")}
Technique: {data.get("attack_technique", "N/A")}

{thin}
RISK LEVEL: {data.get("risk_level", "N/A")}
AI CONFIDENCE: {data.get("confidence", "N/A")}
FALSE POSITIVE LIKELIHOOD: {fp_str}

{thin}
RECOMMENDED ACTION:
{data.get("recommended_action", "N/A")}

{divider}
"""
    return report.strip()