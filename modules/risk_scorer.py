"""
Risk scoring.

Combines the outputs of url_analyzer and keyword_detector with two more
signal sources owned by this module -- sender header anomalies and
attachment risk -- into a single 0-100 score and a risk tier. Point
allocations are a transparent, documented heuristic (not a trained model),
which keeps every score explainable: the same breakdown that produces the
number is also what gets shown to the user and handed to the LLM.

Max contribution per category:
    URLs          -> 35 points (based on the single riskiest URL found)
    Content        -> 30 points (keyword categories matched)
    Sender headers -> 20 points (From/Reply-To/Return-Path anomalies)
    Attachments    -> 15 points (dangerous or disguised file types)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List

from .email_parser import ParsedEmail, attachment_is_risky

URL_MAX = 35
CONTENT_MAX = 30
HEADER_MAX = 20
ATTACHMENT_MAX = 15

TIERS = [
    (70, "Critical", "High-confidence phishing"),
    (45, "High", "Likely phishing"),
    (20, "Medium", "Suspicious, worth a closer look"),
    (0, "Low", "No strong phishing indicators found"),
]


@dataclass
class RiskResult:
    score: int
    tier: str
    tier_description: str
    breakdown: Dict[str, int] = field(default_factory=dict)
    header_flags: List[str] = field(default_factory=list)
    attachment_flags: List[str] = field(default_factory=list)


def _tier_for_score(score: int):
    for threshold, tier, description in TIERS:
        if score >= threshold:
            return tier, description
    return "Low", "No strong phishing indicators found"


def _header_anomalies(parsed: ParsedEmail, known_brands: Dict[str, List[str]]) -> List[str]:
    flags: List[str] = []
    display_lower = (parsed.from_display or "").lower()

    if parsed.from_domain:
        for brand, official_domains in known_brands.items():
            if brand in display_lower:
                is_official = parsed.from_domain in official_domains or any(
                    parsed.from_domain == d or parsed.from_domain.endswith("." + d) for d in official_domains
                )
                if not is_official:
                    flags.append(
                        f'Sender name references "{brand.title()}" but the sending address '
                        f'("{parsed.from_domain}") is not one of that brand\'s official domains'
                    )
                break

    if parsed.reply_to_domain and parsed.from_domain and parsed.reply_to_domain != parsed.from_domain:
        flags.append(
            f'Reply-To address ("{parsed.reply_to_domain}") differs from the From address '
            f'("{parsed.from_domain}") -- replies would go somewhere other than the apparent sender'
        )

    if (
        parsed.return_path_domain
        and parsed.from_domain
        and parsed.return_path_domain != parsed.from_domain
    ):
        flags.append(
            f'Return-Path domain ("{parsed.return_path_domain}") differs from the From address domain '
            f'("{parsed.from_domain}")'
        )

    return flags


def _attachment_risk(parsed: ParsedEmail) -> List[str]:
    flags: List[str] = []
    for attachment in parsed.attachments:
        flags.extend(attachment_is_risky(attachment))
    return flags


def score_email(
    parsed: ParsedEmail,
    url_results: List[dict],
    keyword_results: Dict[str, dict],
    known_brands: Dict[str, List[str]],
) -> RiskResult:
    # --- URLs: scale the single riskiest URL's 0-100 score into our budget ---
    top_url_score = max((r["score"] for r in url_results), default=0)
    url_points = round((top_url_score / 100) * URL_MAX)

    # --- Content: sum matched category weights, capped at the budget ---
    content_raw = sum(data["weight"] for data in keyword_results.values())
    content_points = min(CONTENT_MAX, content_raw)

    # --- Headers ---
    header_flags = _header_anomalies(parsed, known_brands)
    header_points = 0
    if header_flags:
        # First (sender-name-vs-domain) flag is the strongest signal.
        weights = [15, 10, 8]
        header_points = min(HEADER_MAX, sum(weights[: len(header_flags)]))

    # --- Attachments ---
    attachment_flags = _attachment_risk(parsed)
    attachment_points = min(ATTACHMENT_MAX, 15 * min(1, len(attachment_flags)) + 5 * max(0, len(attachment_flags) - 1))

    total = url_points + content_points + header_points + attachment_points
    total = max(0, min(100, total))

    tier, description = _tier_for_score(total)

    return RiskResult(
        score=total,
        tier=tier,
        tier_description=description,
        breakdown={
            "url": url_points,
            "content": content_points,
            "header": header_points,
            "attachment": attachment_points,
        },
        header_flags=header_flags,
        attachment_flags=attachment_flags,
    )
