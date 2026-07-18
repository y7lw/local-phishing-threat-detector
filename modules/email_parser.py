"""
Email parsing.

Responsible for turning raw input (an uploaded .eml file's bytes, or plain
pasted text) into a structured ParsedEmail. This module only extracts facts
-- it does not decide whether anything is risky. That judgment happens in
risk_scorer.py, using the facts collected here.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from typing import List

from bs4 import BeautifulSoup

# Matches http(s) URLs, plus common "defanged" forms security analysts use
# when sharing indicators (hxxp, [.]  instead of http, .) so pasted IOCs
# still get picked up.
_URL_RE = re.compile(
    r"""(?ix)
    \b
    (?:h[tx][tx]ps?|www)
    (?::\/\/|\[\:\/\/\]|\(:\/\/\))?
    [^\s<>"'\)\]]+
    """
)

_DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".js", ".vbs", ".vbe", ".bat", ".cmd", ".com",
    ".jar", ".msi", ".ps1", ".wsf", ".hta", ".pif", ".lnk",
}
_MACRO_EXTENSIONS = {".docm", ".xlsm", ".pptm", ".dotm", ".xltm"}


@dataclass
class HtmlLink:
    text: str
    href: str


@dataclass
class Attachment:
    filename: str
    content_type: str
    size: int


@dataclass
class ParsedEmail:
    subject: str = ""
    from_display: str = ""
    from_address: str = ""
    from_domain: str = ""
    reply_to_address: str = ""
    reply_to_domain: str = ""
    return_path_address: str = ""
    return_path_domain: str = ""
    to: str = ""
    date: str = ""
    body_text: str = ""
    body_html: str = ""
    urls: List[str] = field(default_factory=list)
    html_links: List[HtmlLink] = field(default_factory=list)
    attachments: List[Attachment] = field(default_factory=list)
    has_headers: bool = False

    @property
    def combined_text(self) -> str:
        """Subject + visible body text, used for keyword scanning."""
        visible_html_text = ""
        if self.body_html:
            visible_html_text = BeautifulSoup(self.body_html, "html.parser").get_text(" ")
        return " ".join([self.subject, self.body_text, visible_html_text])


def _domain_of(address: str) -> str:
    if "@" not in address:
        return ""
    return address.rsplit("@", 1)[-1].strip().lower()


def _defang_normalize(text: str) -> str:
    """Undo common IOC-defanging so URLs are still detected and analyzed."""
    text = re.sub(r"hxxps?", lambda m: m.group(0).replace("x", "t"), text, flags=re.IGNORECASE)
    text = text.replace("[.]", ".").replace("(.)", ".").replace("[:]", ":")
    return text


def _extract_urls_from_text(text: str) -> List[str]:
    if not text:
        return []
    normalized = _defang_normalize(text)
    urls = []
    for m in _URL_RE.finditer(normalized):
        url = m.group(0).rstrip(").,;:!?\"'")
        if not url.lower().startswith(("http://", "https://")):
            url = "http://" + url  # bare "www." links
        urls.append(url)
    return urls


def _extract_html_links(html: str) -> List[HtmlLink]:
    links = []
    if not html:
        return links
    soup = BeautifulSoup(html, "html.parser")
    for a in soup.find_all("a", href=True):
        href = a["href"].strip()
        text = a.get_text(" ", strip=True)
        if href.lower().startswith(("http://", "https://")):
            links.append(HtmlLink(text=text, href=href))
    return links


def _flag_attachment_risk(filename: str) -> bool:
    lower = filename.lower()
    return any(lower.endswith(ext) for ext in _DANGEROUS_EXTENSIONS | _MACRO_EXTENSIONS)


def parse_eml_bytes(raw_bytes: bytes) -> ParsedEmail:
    """Parse an uploaded .eml file's raw bytes into a ParsedEmail."""
    msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)

    parsed = ParsedEmail(has_headers=True)
    parsed.subject = str(msg.get("Subject", "") or "")
    parsed.to = str(msg.get("To", "") or "")
    parsed.date = str(msg.get("Date", "") or "")

    from_display, from_address = parseaddr(str(msg.get("From", "") or ""))
    parsed.from_display = from_display
    parsed.from_address = from_address.lower()
    parsed.from_domain = _domain_of(parsed.from_address)

    _, reply_to = parseaddr(str(msg.get("Reply-To", "") or ""))
    parsed.reply_to_address = reply_to.lower()
    parsed.reply_to_domain = _domain_of(parsed.reply_to_address)

    _, return_path = parseaddr(str(msg.get("Return-Path", "") or ""))
    parsed.return_path_address = return_path.lower()
    parsed.return_path_domain = _domain_of(parsed.return_path_address)

    body_text_parts = []
    body_html_parts = []

    if msg.is_multipart():
        for part in msg.walk():
            content_disposition = str(part.get("Content-Disposition", "") or "")
            if "attachment" in content_disposition or part.get_filename():
                filename = part.get_filename() or "unnamed_attachment"
                payload = part.get_payload(decode=True) or b""
                parsed.attachments.append(
                    Attachment(
                        filename=filename,
                        content_type=part.get_content_type(),
                        size=len(payload),
                    )
                )
                continue
            if part.get_content_type() == "text/plain":
                try:
                    body_text_parts.append(part.get_content())
                except Exception:
                    pass
            elif part.get_content_type() == "text/html":
                try:
                    body_html_parts.append(part.get_content())
                except Exception:
                    pass
    else:
        try:
            if msg.get_content_type() == "text/html":
                body_html_parts.append(msg.get_content())
            else:
                body_text_parts.append(msg.get_content())
        except Exception:
            payload = msg.get_payload(decode=True) or b""
            body_text_parts.append(payload.decode("utf-8", errors="replace"))

    parsed.body_text = "\n".join(body_text_parts)
    parsed.body_html = "\n".join(body_html_parts)

    parsed.html_links = _extract_html_links(parsed.body_html)
    text_urls = _extract_urls_from_text(parsed.body_text)
    html_urls = [link.href for link in parsed.html_links]
    html_body_text_urls = _extract_urls_from_text(
        BeautifulSoup(parsed.body_html, "html.parser").get_text(" ")
    ) if parsed.body_html else []

    seen = set()
    for url in text_urls + html_urls + html_body_text_urls:
        if url not in seen:
            seen.add(url)
            parsed.urls.append(url)

    return parsed


def parse_raw_text(text: str) -> ParsedEmail:
    """
    Parse pasted text. Tries to interpret it as full email source (with
    headers); if no recognizable headers are present, treats the whole
    input as a message body instead so the tool still works on a bare
    email body pasted without headers.
    """
    looks_like_source = bool(re.search(r"(?im)^(From|Subject|To|Date):\s", text))

    if looks_like_source:
        parsed = parse_eml_bytes(text.encode("utf-8", errors="replace"))
        if parsed.subject or parsed.from_address or parsed.body_text or parsed.body_html:
            return parsed

    # Fall back: treat entire input as the message body.
    parsed = ParsedEmail(has_headers=False)
    parsed.body_text = text
    parsed.urls = _extract_urls_from_text(text)
    return parsed


def attachment_is_risky(attachment: Attachment) -> List[str]:
    """Return a list of plain-language flags for a single attachment."""
    flags = []
    lower = attachment.filename.lower()
    name_parts = lower.split(".")

    if any(lower.endswith(ext) for ext in _DANGEROUS_EXTENSIONS):
        flags.append(f'"{attachment.filename}" is an executable/script file type often used to deliver malware')
    if any(lower.endswith(ext) for ext in _MACRO_EXTENSIONS):
        flags.append(f'"{attachment.filename}" is a macro-enabled Office document, a common malware delivery method')
    if len(name_parts) > 2:
        # e.g. invoice.pdf.exe
        second_to_last = "." + name_parts[-2]
        if second_to_last in {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".png"}:
            flags.append(f'"{attachment.filename}" uses a double extension to disguise its real file type')
    return flags
