"""Gemini-backed preventive threat intelligence engine for vulscan."""

from __future__ import annotations

import copy
import json
import logging
from datetime import datetime, timezone
from typing import Any

from google import genai
from google.genai import types
from google.api_core import exceptions as google_exceptions

LOGGER = logging.getLogger("vulscan.threat_intel.ai_engine")
MODEL_NAME = "gemini-2.5-flash-lite"

SYSTEM_PROMPT = """
You are a security threat analyst embedded in a CLI vulnerability scanner
called vulscan.
Given a target's technology stack and recent CVE/threat data, identify:
1. Active exploit patterns relevant to this specific stack
2. Code or config CONDITIONS that enable those exploits (symptoms, not just CVE IDs)
3. Concrete one-line remediation steps

Rules:
- Respond in valid JSON only
- No preamble, no markdown, no explanation outside JSON
- Be specific to the detected stack — generic advice is useless
- Focus on conditions an attacker would look for right now
"""

_RESPONSE_INSTRUCTION = """Return a JSON object with this exact structure:
{
  'threat_patterns': [
    {
      'pattern_id': 'TP-001',
      'title': str,
      'description': str,
      'affected_stack': [str],
      'exploit_conditions': [str],
      'severity': 'low|medium|high|critical',
      'source_refs': [str],
      'remediation': str
    }
  ],
  'stack_risk_summary': str,
  'top_priority': str,
  'generated_at': str
}
Return between 3 and 8 threat patterns. No text outside the JSON."""


def _utc_now_iso() -> str:
    """Return the current UTC time in ISO 8601 format."""
    return datetime.now(timezone.utc).isoformat()


def _empty_profile(summary: str = "Unable to parse AI response.") -> dict[str, Any]:
    """Return a safe empty threat profile."""
    return {
        "threat_patterns": [],
        "stack_risk_summary": summary,
        "top_priority": "Unknown",
        "generated_at": _utc_now_iso(),
    }


def _get_client(api_key: str) -> genai.Client:
    """Initialise the google-genai client."""
    return genai.Client(api_key=api_key)


def _truncate_text(value: Any, limit: int = 80) -> str:
    """Convert a value to compact text and truncate it to the requested limit."""
    text = str(value or "").replace("\n", " ").strip()
    return text[:limit]


def _as_list(value: Any) -> list[Any]:
    """Return value as a list without splitting strings into characters."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return [value]


def _format_stack(stack: dict[str, Any]) -> str:
    """Format detected stack fields for the Gemini prompt."""
    languages = _as_list(stack.get("languages"))
    frameworks = _as_list(stack.get("frameworks"))
    package_files = _as_list(
        stack.get("package_files")
        or stack.get("packageFiles")
        or stack.get("packages")
    )

    return "\n".join(
        [
            f"- languages: {languages}",
            f"- frameworks: {frameworks}",
            f"- package files: {package_files}",
        ]
    )


def _format_intel_entries(
    title: str,
    entries: list[Any],
    id_keys: tuple[str, ...],
    text_keys: tuple[str, ...],
) -> str:
    """Format CVE/threat intel entries for the Gemini prompt."""
    lines = [f"{title}:"]
    if not entries:
        lines.append("- none")
        return "\n".join(lines)

    for entry in entries[:5]:
        if isinstance(entry, dict):
            ref_id = next(
                (entry.get(key) for key in id_keys if entry.get(key)),
                "unknown",
            )
            description = next(
                (entry.get(key) for key in text_keys if entry.get(key)),
                "",
            )
        else:
            ref_id = "unknown"
            description = entry
        lines.append(f"- {ref_id}: {_truncate_text(description, 80)}")
    return "\n".join(lines)


def _build_user_prompt(target_info: dict, free_intel: dict) -> str:
    """
    Build a compact prompt from stack info and free intel.

    Designed to stay under 1500 tokens to respect free tier limits.
    """
    stack = free_intel.get("stack", {})
    if not isinstance(stack, dict):
        stack = {}

    target_type = (
        target_info.get("target_type")
        or target_info.get("type")
        or target_info.get("kind")
        or "unknown"
    )

    cisa_entries = _as_list(
        free_intel.get("cisa_kev")
        or free_intel.get("cisa")
        or free_intel.get("kev")
    )
    nvd_entries = _as_list(free_intel.get("nvd"))
    osv_entries = _as_list(free_intel.get("osv"))

    sections = [
        f"Target type: {target_type}",
        "Detected stack:",
        _format_stack(stack),
        _format_intel_entries(
            "Top CISA KEV entries",
            cisa_entries,
            ("cve_id", "cveID", "cve", "id"),
            ("description", "shortDescription", "summary", "details"),
        ),
        _format_intel_entries(
            "Top NVD entries",
            nvd_entries,
            ("cve_id", "cveID", "cve", "id"),
            ("description", "summary", "details"),
        ),
        _format_intel_entries(
            "Top OSV entries",
            osv_entries,
            ("osv_id", "osvId", "id", "cve_id", "cve"),
            ("summary", "description", "details"),
        ),
        _RESPONSE_INSTRUCTION,
    ]
    return "\n\n".join(sections)


def _estimate_tokens(text: str) -> int:
    """Rough estimate: 1 token per 4 characters."""
    return len(text) // 4


def _trim_intel_entries(free_intel: dict, limit: int = 3) -> dict:
    """Return a copy of free intel with major intel feeds capped to limit."""
    trimmed = copy.deepcopy(free_intel)
    for key in ("cisa_kev", "cisa", "kev", "nvd", "osv"):
        if isinstance(trimmed.get(key), list):
            trimmed[key] = trimmed[key][:limit]
    return trimmed


def _call_gemini(client: genai.Client, user_prompt: str) -> str:
    """Calls Gemini 2.0 Flash via the new google-genai SDK."""
    full_prompt = SYSTEM_PROMPT + "\n\n" + user_prompt

    try:
        response = client.models.generate_content(
            model="gemini-2.5-flash-lite",
            contents=full_prompt,
            config=types.GenerateContentConfig(
                response_mime_type="application/json",
                max_output_tokens=1500,
                temperature=0.2,
            ),
        )
        raw_text = response.text
        LOGGER.debug("Raw Gemini response: %s", _truncate_text(raw_text, 200))
        return raw_text
    except google_exceptions.ResourceExhausted:
        LOGGER.warning(
            "Gemini free tier rate limit hit. Try again in 60 seconds."
        )
        raise
    except google_exceptions.InvalidArgument as exc:
        LOGGER.warning("Gemini request rejected: %s", exc)
        raise
    except Exception as exc:
        LOGGER.warning("Gemini call failed: %s", _truncate_text(exc, 200))
        raise


def _strip_markdown_fence(raw: str) -> str:
    """Strip markdown code fences from a Gemini response if present."""
    text = raw.strip()
    if not text.startswith("```"):
        return text

    lines = text.splitlines()
    if lines and lines[0].strip().startswith("```"):
        lines = lines[1:]
    if lines and lines[-1].strip() == "```":
        lines = lines[:-1]
    return "\n".join(lines).strip()


def _parse_response(raw: str) -> dict:
    """
    Parse JSON response from Gemini.

    Strips markdown fences if present. Returns a safe empty profile on any
    failure.
    """
    try:
        cleaned = _strip_markdown_fence(raw)
        result = json.loads(cleaned)
        if not isinstance(result.get("threat_patterns"), list):
            raise ValueError("Missing threat_patterns list")
        return result
    except Exception:
        LOGGER.warning(
            "Unable to parse Gemini response: %s",
            _truncate_text(raw, 200),
        )
        return _empty_profile()


def fetch_threat_profile(
    target_info: dict,
    api_key: str,
    free_intel: dict,
) -> dict:
    """
    Use Gemini 2.0 Flash to analyse the target stack and recent threat intel.

    Returns a structured threat profile with exploit conditions and remediation
    guidance. Called only in preventive or both scan modes. Uses Google Gemini
    free tier: 1500 requests/day, no cost.

    The api_key parameter is resolved by cli.py from either the --api-key flag
    or the GEMINI_API_KEY environment variable. This module only receives it.
    """
    LOGGER.info(
        "Building AI threat profile using Gemini 2.0 Flash (free tier)..."
    )

    client = _get_client(api_key)
    user_prompt = _build_user_prompt(target_info, free_intel)
    estimate = _estimate_tokens(user_prompt)
    LOGGER.debug(
        "Prompt estimate: %s words, %s tokens.",
        len(user_prompt.split()),
        estimate,
    )

    if estimate > 2000:
        LOGGER.warning("Prompt trimmed to stay within free tier limits.")
        user_prompt = _build_user_prompt(
            target_info,
            _trim_intel_entries(free_intel, 3),
        )
        estimate = _estimate_tokens(user_prompt)
        LOGGER.debug(
            "Trimmed prompt estimate: %s words, %s tokens.",
            len(user_prompt.split()),
            estimate,
        )

    try:
        raw = _call_gemini(client, user_prompt)
    except Exception:
        LOGGER.warning(
            "AI threat profile unavailable. Continuing with free intel only."
        )
        result = _empty_profile("AI threat profile unavailable.")
        result["model_used"] = MODEL_NAME
        result["cost"] = "free tier"
        return result

    result = _parse_response(raw)
    result["model_used"] = MODEL_NAME
    result["cost"] = "free tier"

    LOGGER.info(
        "Threat profile built. %s patterns identified.",
        len(result["threat_patterns"]),
    )
    return result
