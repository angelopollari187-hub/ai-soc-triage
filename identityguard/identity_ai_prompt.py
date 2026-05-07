"""
IdentityGuard AI — Claude Analyst Summary Module

Handles:
  - Building the identity-specific system + user prompts
  - Calling the Claude API (on-demand only, never auto-called)
  - Caching generated summaries to output/identity_ai_summaries.json
  - Loading and invalidating stale cached summaries via incident hash

Cache file: output/identity_ai_summaries.json
Cache key:  incident_id
Stale check: SHA-256 of (detection_type + risk_score + scoring_reasons + mitre_techniques)

API model: claude-sonnet-4-6  (matches existing triage.py convention)
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

BASE_DIR   = Path(__file__).resolve().parent.parent
CACHE_FILE = BASE_DIR / "output" / "identity_ai_summaries.json"

# ---------------------------------------------------------------------------
# Prompt templates
# ---------------------------------------------------------------------------

IDENTITY_SYSTEM_PROMPT = """You are a senior identity security analyst at a SOC.
You write structured, evidence-based triage reports for account takeover and
identity compromise incidents.

STRICT RULES YOU MUST FOLLOW:
1. Use ONLY the structured incident data provided. Never invent, hallucinate,
   or assume additional facts beyond what is in the data.
2. Label ALL uncertainty explicitly using phrases such as:
   "the evidence suggests", "this may indicate", "it is possible that",
   "cannot be confirmed without", "warrants further investigation".
3. Do NOT make final legal or criminal attribution claims. You are a technical
   analyst providing decision support, not a legal authority.
4. Do NOT state an incident is "definitely malicious" unless the rule scoring
   data explicitly supports that conclusion beyond reasonable doubt.
5. Acknowledge when evidence is ambiguous or when legitimate explanations exist.
6. Return ONLY a valid JSON object. No markdown fences, no code blocks,
   no explanatory text outside the JSON structure."""


def build_identity_user_prompt(incident: dict) -> str:
    """
    Build the user-facing prompt from a structured triage result dict.
    Only structured fields are included — no raw log data reaches the API.

    Args:
        incident: A row dict from identity_alerts.csv (or equivalent).
    """
    def _get(key: str, fallback: str = "Not available") -> str:
        v = incident.get(key, fallback)
        if not v or str(v).strip() in ("", "nan", "None", "—"):
            return fallback
        return str(v).strip()

    structured_data = {
        "incident_id":              _get("incident_id"),
        "user":                     _get("user"),
        "primary_detection_type":   _get("detection_type"),
        "all_detections":           _get("all_detections", _get("identity_indicators")),
        "risk_score":               _get("risk_score"),
        "risk_level":               _get("risk_level"),
        "confidence":               _get("confidence"),
        "false_positive_likelihood": _get("false_positive_likelihood"),
        "escalation_decision":      _get("escalation_decision"),
        "mitre_techniques":         _get("mitre_techniques"),
        "scoring_reasons":          _get("scoring_reasons"),
        "recommended_actions":      _get("recommended_actions"),
        "analyst_notes":            _get("analyst_notes", "None provided"),
    }

    structured_json = json.dumps(structured_data, indent=2)

    return f"""Analyze this identity security incident and write a structured analyst report.
Use ONLY the provided structured data. Do not invent or assume any additional facts.

INCIDENT DATA:
{structured_json}

Return a JSON object with EXACTLY these fields and no others:
{{
  "analyst_summary": "2-3 sentences in plain English: what happened, which detections fired, and why this warrants analyst attention",
  "likely_scenario": "The most probable explanation for this activity based solely on the provided evidence. Use hedged language if uncertain.",
  "why_flagged": "Specific rules and signals that triggered this alert, directly referencing the scoring_reasons and detection types in the data.",
  "false_positive_considerations": "Legitimate business scenarios that could explain this activity. Be specific about what would need to be true.",
  "recommended_analyst_actions": ["action 1", "action 2", "action 3", "action 4"],
  "containment_steps": ["containment step 1", "containment step 2", "containment step 3"],
  "evidence_checklist": ["evidence item to verify 1", "evidence item to verify 2", "evidence item to verify 3", "evidence item to verify 4"],
  "ticket_handoff": "A ready-to-paste paragraph suitable for a ServiceNow or Jira ticket. Include incident ID, user, detection types, risk level, and recommended next steps.",
  "uncertainty_notes": "What cannot be determined from the available structured data alone and requires human verification.",
  "confidence_assessment": "HIGH, MEDIUM, or LOW — followed by one sentence explaining why based on the scoring data."
}}"""


# ---------------------------------------------------------------------------
# Cache helpers
# ---------------------------------------------------------------------------

def _compute_incident_hash(incident: dict) -> str:
    """
    SHA-256 of the key fields that define the incident's triage state.
    If any of these change, the cached summary is considered stale.
    """
    raw = "|".join([
        str(incident.get("detection_type", "")),
        str(incident.get("risk_score", "")),
        str(incident.get("scoring_reasons", "")),
        str(incident.get("mitre_techniques", "")),
    ])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def _load_cache() -> dict:
    """Load the entire cache file. Returns empty dict if file missing or corrupt."""
    if not CACHE_FILE.exists():
        return {}
    try:
        with open(CACHE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}


def _save_cache(cache: dict) -> None:
    CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(CACHE_FILE, "w", encoding="utf-8") as f:
        json.dump(cache, f, indent=2, default=str)


def get_cached_summary(incident_id: str, incident: dict) -> Optional[dict]:
    """
    Return the cached summary for incident_id if it exists AND the incident
    data hash matches (i.e. the triage result has not changed since caching).

    Returns None if no cache entry exists or if the cache is stale.
    """
    cache = _load_cache()
    entry = cache.get(incident_id)
    if not entry:
        return None

    current_hash = _compute_incident_hash(incident)
    if entry.get("incident_hash") != current_hash:
        return None         # stale — triage data has changed

    return entry.get("summary")


def is_summary_stale(incident_id: str, incident: dict) -> bool:
    """
    True if a cache entry exists but the incident hash no longer matches.
    Used to show a 'Data changed — regenerate?' warning.
    """
    cache = _load_cache()
    entry = cache.get(incident_id)
    if not entry:
        return False
    return entry.get("incident_hash") != _compute_incident_hash(incident)


def save_summary(incident_id: str, summary: dict, incident: dict) -> None:
    """Persist an AI-generated summary to the cache file."""
    cache = _load_cache()
    cache[incident_id] = {
        "summary":       summary,
        "incident_hash": _compute_incident_hash(incident),
        "generated_at":  datetime.now(timezone.utc).isoformat(),
    }
    _save_cache(cache)


def get_cache_metadata(incident_id: str) -> Optional[dict]:
    """Return generated_at and incident_hash for display in the dashboard."""
    cache = _load_cache()
    entry = cache.get(incident_id)
    if not entry:
        return None
    return {
        "generated_at":  entry.get("generated_at", "Unknown"),
        "incident_hash": entry.get("incident_hash", ""),
    }


# ---------------------------------------------------------------------------
# Claude API call
# ---------------------------------------------------------------------------

def generate_identity_summary(incident: dict) -> tuple[bool, str | dict]:
    """
    Call the Claude API and return a structured identity analyst summary.

    This function MUST only be called when the analyst explicitly requests it
    (button click). Never call automatically on page load.

    Args:
        incident: A row dict from identity_alerts.csv.

    Returns:
        (True, summary_dict)   on success
        (False, error_message) on any failure
    """
    # ── API key check ──────────────────────────────────────────────────────
    # load_dotenv() is intentionally NOT called here — the caller (dashboard
    # or CLI) is responsible for loading the environment before invoking this
    # function.  This keeps the function side-effect-free and testable.
    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        return False, (
            "ANTHROPIC_API_KEY is not set. "
            "Add it to your .env file: ANTHROPIC_API_KEY=sk-ant-..."
        )

    # ── Import and initialise client ───────────────────────────────────────
    try:
        import anthropic
    except ImportError:
        return False, "anthropic package not installed. Run: pip install anthropic"

    try:
        from tenacity import retry, stop_after_attempt, wait_exponential

        client = anthropic.Anthropic(api_key=api_key)
        user_prompt = build_identity_user_prompt(incident)

        @retry(stop=stop_after_attempt(3), wait=wait_exponential(min=2, max=10))
        def _call():
            return client.messages.create(
                model="claude-sonnet-4-6",
                max_tokens=1500,
                system=IDENTITY_SYSTEM_PROMPT,
                messages=[{"role": "user", "content": user_prompt}],
            )

        response = _call()

    except Exception as e:
        return False, f"API call failed: {e}"

    # ── Parse response ─────────────────────────────────────────────────────
    raw = response.content[0].text.strip()

    # Strip accidental markdown fences the model may produce
    if raw.startswith("```"):
        raw = raw.split("```")[1]
        if raw.startswith("json"):
            raw = raw[4:]
        raw = raw.strip()

    try:
        summary = json.loads(raw)
    except json.JSONDecodeError as e:
        fallback_text = raw.strip()
        if fallback_text:
            return True, {
                "_fallback_narrative": True,
                "_debug_details": f"JSON parse failed: {e}\n\nRaw output:\n{raw}",
                "analyst_summary": fallback_text,
                "likely_scenario": "AI returned narrative output instead of structured JSON.",
                "why_flagged": "Review deterministic scoring, Priority Confidence, and supporting evidence above.",
                "false_positive_considerations": "Use the deterministic false-positive likelihood and analyst validation workflow.",
                "recommended_analyst_actions": [],
                "containment_steps": [],
                "evidence_checklist": [],
                "ticket_handoff": fallback_text,
                "uncertainty_notes": "Structured JSON parsing failed; use this narrative as optional assistance only.",
                "confidence_assessment": "LOW - fallback narrative was produced from non-JSON model output.",
            }
        return False, f"AI returned non-JSON output: {e}"

    # ── Validate expected keys are present ────────────────────────────────
    required = {
        "analyst_summary", "likely_scenario", "why_flagged",
        "false_positive_considerations", "recommended_analyst_actions",
        "containment_steps", "evidence_checklist", "ticket_handoff",
        "uncertainty_notes", "confidence_assessment",
    }
    missing = required - set(summary.keys())
    if missing:
        return False, f"AI response missing required fields: {missing}"

    return True, summary
