"""
Keyword / phrase detection.

Scans email content for phrases commonly associated with phishing, grouped
into categories (credential harvesting, urgency, financial lures, etc.) so
the risk scorer and the LLM explanation can reason about *why* something
was flagged, not just *that* it was.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List

_DATA_PATH = Path(__file__).resolve().parent.parent / "data" / "keywords.json"


def load_keyword_db(path: Path = _DATA_PATH) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def detect_keywords(text: str, keyword_db: dict) -> Dict[str, dict]:
    """
    Returns a dict keyed by category name, e.g.:
        {
          "credential_harvesting": {
              "label": "Credential Harvesting",
              "weight": 12,
              "matched": ["verify your account", "confirm your password"],
          },
          ...
        }
    Only categories with at least one match are included.
    """
    text_lower = (text or "").lower()
    matches: Dict[str, dict] = {}

    for category, data in keyword_db.items():
        found: List[str] = [phrase for phrase in data["phrases"] if phrase.lower() in text_lower]
        if found:
            matches[category] = {
                "label": data.get("label", category),
                "weight": data.get("weight", 5),
                "matched": found,
            }

    return matches
