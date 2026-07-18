"""
URL analysis.

Pure lexical/structural analysis of URLs -- no live requests are ever made
to the URLs found in a scanned email. That's a deliberate choice: this is a
local, offline triage tool, and visiting attacker-controlled links would be
both unsafe and unnecessary for the kind of indicators checked here.
"""

from __future__ import annotations

import re
from typing import Dict, List
from urllib.parse import urlparse

from .email_parser import HtmlLink

KNOWN_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "tiny.cc", "s.id",
}

# Free / low-cost TLDs disproportionately abused for throwaway phishing
# infrastructure. Presence here is a weak-to-moderate signal, not proof.
SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "work", "click", "link",
    "zip", "review", "country", "kim", "loan", "men", "party", "science",
    "gdn", "mom", "rest",
}

# Two-part public suffixes we handle explicitly so "example.co.uk" isn't
# mistaken for the domain "co.uk". Not exhaustive, but covers the common
# cases well enough for a local heuristic tool.
_MULTI_PART_TLDS = {
    "co.uk", "org.uk", "gov.uk", "ac.uk", "co.jp", "co.in", "com.au",
    "com.br", "com.cn", "com.mx", "co.nz", "co.za",
}

_IPV4_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if len(a) < len(b):
        a, b = b, a
    if len(b) == 0:
        return len(a)
    previous_row = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        current_row = [i + 1]
        for j, cb in enumerate(b):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (ca != cb)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


def _registered_domain(hostname: str) -> str:
    """Best-effort extraction of the 'registrable' domain, e.g.
    'login.security.paypa1-verify.xyz' -> 'paypa1-verify.xyz'."""
    hostname = hostname.lower().rstrip(".")
    parts = hostname.split(".")
    if len(parts) <= 2:
        return hostname
    last_two = ".".join(parts[-2:])
    if last_two in _MULTI_PART_TLDS and len(parts) >= 3:
        return ".".join(parts[-3:])
    return last_two


def _sld(registered_domain: str) -> str:
    """Second-level label of a registrable domain, e.g. 'paypa1-verify.xyz' -> 'paypa1-verify'."""
    return registered_domain.split(".")[0] if registered_domain else ""


def analyze_url(url: str, known_brands: Dict[str, List[str]]) -> dict:
    """Score a single URL 0-100 and return the flags that explain the score."""
    flags: List[str] = []
    score = 0

    try:
        parsed = urlparse(url)
    except ValueError:
        return {"url": url, "domain": "", "score": 0, "flags": ["Could not be parsed as a valid URL"]}

    hostname = (parsed.hostname or "").lower()
    registered_domain = _registered_domain(hostname)
    sld = _sld(registered_domain)

    # Full known-domain allowlist across all brands, used to avoid false
    # positives (e.g. never flag mail.google.com as impersonating Google).
    all_official_domains = {d for domains in known_brands.values() for d in domains}
    is_official_domain = hostname in all_official_domains or any(
        hostname == d or hostname.endswith("." + d) for d in all_official_domains
    )

    if not is_official_domain:
        if "@" in url.split("://", 1)[-1]:
            score += 35
            flags.append('Contains an "@" symbol, a classic trick to hide the real destination after a fake-looking prefix')

        if _IPV4_RE.match(hostname):
            score += 40
            flags.append("Links directly to a raw IP address instead of a domain name")

        if hostname in KNOWN_SHORTENERS:
            score += 20
            flags.append(f'Uses the "{hostname}" link-shortening service, which hides the real destination')

        tld = hostname.split(".")[-1] if "." in hostname else ""
        if tld in SUSPICIOUS_TLDS:
            score += 15
            flags.append(f'Uses the ".{tld}" top-level domain, frequently abused for disposable phishing sites')

        if hostname.startswith("xn--") or ".xn--" in hostname:
            score += 25
            flags.append("Uses internationalized (punycode) domain encoding, sometimes used to spoof lookalike characters")

        subdomain_count = max(0, hostname.count(".") - registered_domain.count("."))
        if subdomain_count >= 3:
            score += 15
            flags.append(f"Has an unusually large number of subdomains ({subdomain_count}), often used to bury the real domain")

        if len(url) > 100:
            score += 10
            flags.append("Unusually long URL, which can be used to obscure the true destination")

        # Brand impersonation / typosquat checks. We check the whole SLD *and*
        # its hyphen/underscore-separated segments, since attackers commonly
        # register domains like "paypa1-account-verify.xyz" where no single
        # whole label matches "paypal" but one segment is a near-miss of it.
        segments = [seg for seg in re.split(r"[-_]", sld) if seg]
        candidates = [sld] + [s for s in segments if s != sld]

        matched = False
        if sld:
            for candidate in candidates:
                if candidate in known_brands:
                    score += 45
                    flags.append(
                        f'Domain uses the brand name "{candidate}" directly, but this is not one '
                        f"of that brand's official domains"
                    )
                    matched = True
                    break

        # Prefer this precise "contains the literal brand name" explanation
        # over the fuzzy edit-distance one below when both would apply.
        if not matched and sld:
            for candidate in candidates:
                for brand in known_brands:
                    if brand in candidate and candidate != brand:
                        score += 30
                        flags.append(
                            f'Domain contains the brand name "{brand}" combined with other text, '
                            f"a common impersonation pattern"
                        )
                        matched = True
                        break
                if matched:
                    break

        if not matched and sld:
            best_candidate = best_brand_match = None
            best_distance = None
            for candidate in candidates:
                if len(candidate) <= 3:
                    continue  # too short for edit-distance comparison to mean anything
                for brand in known_brands:
                    distance = _levenshtein(candidate, brand)
                    if 0 < distance <= 2 and (best_distance is None or distance < best_distance):
                        best_distance = distance
                        best_candidate = candidate
                        best_brand_match = brand
            if best_brand_match:
                score += 50
                flags.append(
                    f'Domain segment "{best_candidate}" is suspiciously similar to the brand '
                    f'"{best_brand_match}" (likely typosquatting, edit distance {best_distance})'
                )
                matched = True

    return {
        "url": url,
        "domain": registered_domain or hostname,
        "score": min(score, 100),
        "flags": flags,
    }


def _link_mismatch_flags(html_links: List[HtmlLink], known_brands: Dict[str, List[str]]) -> Dict[str, List[str]]:
    """
    For HTML emails, detect links whose visible text names one destination
    while the actual href points somewhere else entirely (e.g. text reads
    "www.paypal.com" but the link goes to a different domain).
    Returns a mapping of href -> extra flags to merge into that URL's result.
    """
    extra_flags: Dict[str, List[str]] = {}
    domain_in_text_re = re.compile(r"([a-z0-9-]+\.(?:[a-z0-9-]+\.)*[a-z]{2,})", re.IGNORECASE)

    for link in html_links:
        text_match = domain_in_text_re.search(link.text or "")
        if not text_match:
            continue
        try:
            href_host = (urlparse(link.href).hostname or "").lower()
        except ValueError:
            continue
        text_domain = text_match.group(1).lower().rstrip(".")
        if href_host and text_domain and text_domain not in href_host and href_host not in text_domain:
            extra_flags.setdefault(link.href, []).append(
                f'Displayed link text says "{text_domain}" but actually points to "{href_host}"'
            )
    return extra_flags


def analyze_urls(
    urls: List[str],
    html_links: List[HtmlLink],
    known_brands: Dict[str, List[str]],
) -> List[dict]:
    """Analyze every URL found in an email and return results sorted by risk, highest first."""
    mismatch_flags = _link_mismatch_flags(html_links, known_brands)

    results = []
    for url in urls:
        result = analyze_url(url, known_brands)
        if url in mismatch_flags:
            result["flags"].extend(mismatch_flags[url])
            result["score"] = min(100, result["score"] + 30 * len(mismatch_flags[url]))
        results.append(result)

    results.sort(key=lambda r: r["score"], reverse=True)
    return results
