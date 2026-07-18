"""
Local LLM integration (Ollama).

This module's only job is translation: take the structured, already-computed
findings from risk_scorer/url_analyzer/keyword_detector and ask a local
Ollama model to write them up in plain English for an incident report. The
LLM is never asked to invent a risk score or new findings -- it explains the
findings it's given. Nothing here ever leaves the machine except the request
to the local Ollama server (default http://localhost:11434).
"""

from __future__ import annotations

from typing import Dict, Generator, List

import httpx
import ollama

from .email_parser import ParsedEmail
from .risk_scorer import RiskResult

DEFAULT_HOST = "http://localhost:11434"

SYSTEM_PROMPT = """You are a cybersecurity analyst assistant helping write incident documentation.
You will be given the structured, automated findings from a phishing-detection scan of one email.
These findings were computed by deterministic rules, not by you -- do not contradict the given
risk score or invent new findings that are not present below.

Write a concise incident-report section in Markdown with exactly these headings:

## Verdict
One or two sentences stating what the automated scan concluded and how confident it is.

## Why This Was Flagged
Explain the specific red flags in plain language a non-technical reader can follow. Avoid jargon
(e.g. say "the link pretends to go to PayPal but actually points to a different website" rather
than naming technical terms). If there are no notable red flags, say so plainly.

## Recommended Actions
2-4 short bullet points on what the recipient or IT/security team should do next.

Keep the entire response under 300 words. Base every statement strictly on the findings provided."""


class OllamaUnavailable(Exception):
    """Raised when the local Ollama server can't be reached or the model isn't available."""


def _client(host: str) -> ollama.Client:
    return ollama.Client(host=host or DEFAULT_HOST)


def list_models(host: str = DEFAULT_HOST) -> List[str]:
    """Return locally available model names, or an empty list if Ollama isn't reachable."""
    try:
        response = _client(host).list()
        return [m.model for m in response.models if m.model]
    except Exception:
        return []


def is_available(host: str = DEFAULT_HOST) -> bool:
    try:
        _client(host).list()
        return True
    except Exception:
        return False


def format_findings(
    parsed: ParsedEmail,
    risk: RiskResult,
    url_results: List[dict],
    keyword_results: Dict[str, dict],
) -> str:
    """Render all findings as a compact, readable text block for the LLM prompt."""
    lines = []

    lines.append(f"Sender display name: {parsed.from_display or '(none)'}")
    lines.append(f"Sender address: {parsed.from_address or '(none)'}")
    lines.append(f"Subject: {parsed.subject or '(none)'}")
    lines.append(f"Risk Score: {risk.score}/100 ({risk.tier} -- {risk.tier_description})")
    lines.append(
        f"Score breakdown: URLs={risk.breakdown.get('url', 0)}/35, "
        f"Content={risk.breakdown.get('content', 0)}/30, "
        f"Sender headers={risk.breakdown.get('header', 0)}/20, "
        f"Attachments={risk.breakdown.get('attachment', 0)}/15"
    )

    lines.append("")
    lines.append("URL findings:")
    if url_results:
        for r in url_results[:8]:
            if r["flags"]:
                lines.append(f'- {r["url"]} (score {r["score"]}/100) -- ' + "; ".join(r["flags"]))
            else:
                lines.append(f'- {r["url"]} (score {r["score"]}/100) -- no red flags')
    else:
        lines.append("- No URLs found in this email.")

    lines.append("")
    lines.append("Suspicious language categories matched:")
    if keyword_results:
        for data in keyword_results.values():
            lines.append(f"- {data['label']}: " + ", ".join(f'"{p}"' for p in data["matched"]))
    else:
        lines.append("- None.")

    lines.append("")
    lines.append("Sender header anomalies:")
    if risk.header_flags:
        for f in risk.header_flags:
            lines.append(f"- {f}")
    else:
        lines.append("- None.")

    lines.append("")
    lines.append("Attachment findings:")
    if risk.attachment_flags:
        for f in risk.attachment_flags:
            lines.append(f"- {f}")
    elif parsed.attachments:
        lines.append(f"- {len(parsed.attachments)} attachment(s) present, none matched risky file-type patterns.")
    else:
        lines.append("- No attachments.")

    return "\n".join(lines)


def _messages(findings_text: str) -> List[dict]:
    return [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": f"=== AUTOMATED SCAN FINDINGS ===\n{findings_text}\n=== END FINDINGS ==="},
    ]


def stream_report(host: str, model: str, findings_text: str) -> Generator[str, None, None]:
    """Yield the report text incrementally as the model generates it."""
    try:
        client = _client(host)
        stream = client.chat(model=model, messages=_messages(findings_text), stream=True)
        for chunk in stream:
            content = chunk.message.content if chunk.message else ""
            if content:
                yield content
    except (ConnectionError, httpx.TransportError) as e:
        raise OllamaUnavailable(
            f"Could not reach Ollama at {host}. Make sure Ollama is running (`ollama serve`)."
        ) from e
    except ollama.ResponseError as e:
        if e.status_code == 404:
            raise OllamaUnavailable(
                f'Model "{model}" is not pulled yet. Run `ollama pull {model}` and try again.'
            ) from e
        raise OllamaUnavailable(f"Ollama returned an error: {e.error}") from e
    except Exception as e:
        raise OllamaUnavailable(f"Unexpected error talking to Ollama: {e}") from e


def generate_report(host: str, model: str, findings_text: str) -> str:
    """Non-streaming convenience wrapper, e.g. for tests or non-UI callers."""
    return "".join(stream_report(host, model, findings_text))
