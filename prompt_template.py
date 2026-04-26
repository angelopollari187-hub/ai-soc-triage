SYSTEM_PROMPT = '''
You are an expert SOC analyst with 10 years of experience in threat
detection and incident response at a large financial institution.
You analyze raw security log data and return structured triage reports.
You always respond with a single valid JSON object — no markdown,
no code blocks, no extra text. Only the JSON object.
'''

def build_user_prompt(log_data: str) -> str:
    return f'''
Analyze the following security log data and return a JSON object
with EXACTLY these fields:
{{
"incident_summary": "plain English, 2-3 sentences",
"attack_tactic": "MITRE ATT&CK tactic name",
"attack_technique": "T-number - technique name",
"risk_level": "LOW or MEDIUM or HIGH or CRITICAL",
"recommended_action": "specific steps, 2-4 sentences",
"confidence": "HIGH or MEDIUM or LOW",
"false_positive_likelihood": integer between 0 and 100
}}

LOG DATA TO ANALYZE:
---
{log_data}
---
'''