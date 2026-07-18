"""
Phishing Threat Detector -- Streamlit front end.

This file owns ALL Streamlit-specific code. Every decision about what
counts as "risky" happens in modules/ (framework-agnostic), so this file's
only job is: collect input, call the pipeline, render the result.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

import streamlit as st

from modules import email_parser, keyword_detector, llm_reporter, risk_scorer, url_analyzer

BASE_DIR = Path(__file__).resolve().parent
SAMPLE_DIR = BASE_DIR / "sample_emails"
DEFAULT_HOST = llm_reporter.DEFAULT_HOST

# ----------------------------------------------------------------------------
# Page setup
# ----------------------------------------------------------------------------

st.set_page_config(
    page_title="Phishing Threat Detector",
    page_icon="🎣",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600;700&family=IBM+Plex+Sans:wght@400;500;600&display=swap');

    html, body, [class*="st-emotion"], p, li, span, label, div {
        font-family: 'IBM Plex Sans', -apple-system, sans-serif;
    }
    h1, h2, h3, h4, code, pre, .stCode, .verdict-score, .verdict-tier {
        font-family: 'IBM Plex Mono', 'SF Mono', Consolas, monospace !important;
    }

    :root {
        --risk-low: #33B689;
        --risk-medium: #E3A83B;
        --risk-high: #E2793B;
        --risk-critical: #E2465A;
        --border-subtle: rgba(140, 151, 168, 0.25);
    }

    .verdict-card {
        display: flex;
        align-items: center;
        gap: 28px;
        background: rgba(140, 151, 168, 0.06);
        border: 1px solid var(--border-subtle);
        border-left: 6px solid var(--risk-low);
        border-radius: 10px;
        padding: 22px 28px;
        margin: 4px 0 22px 0;
    }
    .verdict-card.tier-medium { border-left-color: var(--risk-medium); }
    .verdict-card.tier-high { border-left-color: var(--risk-high); }
    .verdict-card.tier-critical { border-left-color: var(--risk-critical); }

    .verdict-score {
        font-size: 3rem;
        font-weight: 700;
        line-height: 1;
        white-space: nowrap;
    }
    .verdict-score .verdict-max {
        font-size: 1.1rem;
        font-weight: 500;
        opacity: 0.55;
    }
    .verdict-tier {
        display: inline-block;
        font-size: 0.75rem;
        font-weight: 600;
        letter-spacing: 0.08em;
        text-transform: uppercase;
        padding: 3px 11px;
        border-radius: 999px;
        margin-bottom: 6px;
        color: #10131A;
        background: var(--risk-low);
    }
    .verdict-card.tier-medium .verdict-tier { background: var(--risk-medium); }
    .verdict-card.tier-high .verdict-tier { background: var(--risk-high); }
    .verdict-card.tier-critical .verdict-tier { background: var(--risk-critical); }

    .verdict-desc { opacity: 0.75; font-size: 0.95rem; }
    </style>
    """,
    unsafe_allow_html=True,
)

TIER_CLASS = {"Low": "tier-low", "Medium": "tier-medium", "High": "tier-high", "Critical": "tier-critical"}


# ----------------------------------------------------------------------------
# Cached loaders (small local files / short-lived Ollama availability check)
# ----------------------------------------------------------------------------

@st.cache_data
def _load_known_brands() -> dict:
    with open(BASE_DIR / "data" / "known_brands.json", "r", encoding="utf-8") as f:
        return json.load(f)


@st.cache_data
def _load_keyword_db() -> dict:
    return keyword_detector.load_keyword_db()


@st.cache_data(ttl=10)
def _list_models_cached(host: str):
    return llm_reporter.list_models(host)


def mono(value) -> str:
    """Render a value as a Markdown code span, safe against embedded backticks."""
    text = str(value) if value not in (None, "") else "(none)"
    return "`" + text.replace("`", "'") + "`"


def render_verdict_card(risk: risk_scorer.RiskResult) -> None:
    css_class = TIER_CLASS.get(risk.tier, "tier-low")
    st.markdown(
        f"""
        <div class="verdict-card {css_class}">
            <div class="verdict-score">{risk.score}<span class="verdict-max">/100</span></div>
            <div>
                <div class="verdict-tier">{risk.tier}</div>
                <div class="verdict-desc">{risk.tier_description}</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def build_report_markdown(parsed, risk, url_results, keyword_results, ai_report_text, source_label) -> str:
    lines = [
        "# Phishing Triage Report",
        "",
        f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  ",
        f"**Source:** {source_label}",
        "",
        f"## Verdict: {risk.score}/100 -- {risk.tier}",
        f"_{risk.tier_description}_",
        "",
        "### Score Breakdown",
        f"- URLs: {risk.breakdown['url']}/35",
        f"- Content: {risk.breakdown['content']}/30",
        f"- Sender headers: {risk.breakdown['header']}/20",
        f"- Attachments: {risk.breakdown['attachment']}/15",
        "",
        "## Email Details",
        f"- **From:** {parsed.from_display or '(none)'} <{parsed.from_address or 'unknown'}>",
        f"- **Reply-To:** {parsed.reply_to_address or '(none)'}",
        f"- **Subject:** {parsed.subject or '(none)'}",
        f"- **Date:** {parsed.date or '(none)'}",
        "",
        "## URL Findings",
    ]

    if url_results:
        for r in url_results:
            lines.append(f"- `{r['url']}` -- score {r['score']}/100")
            for flag in r["flags"]:
                lines.append(f"    - {flag}")
    else:
        lines.append("- No URLs found.")

    lines += ["", "## Suspicious Language"]
    if keyword_results:
        for data in keyword_results.values():
            phrases = ", ".join(f'"{p}"' for p in data["matched"])
            lines.append(f"- **{data['label']}**: {phrases}")
    else:
        lines.append("- None detected.")

    lines += ["", "## Sender Header Anomalies"]
    if risk.header_flags:
        lines += [f"- {f}" for f in risk.header_flags]
    else:
        lines.append("- None detected.")

    lines += ["", "## Attachments"]
    if parsed.attachments:
        for a in parsed.attachments:
            lines.append(f"- `{a.filename}` ({a.content_type}, {a.size:,} bytes)")
        for f in risk.attachment_flags:
            lines.append(f"    - Flag: {f}")
    else:
        lines.append("- None.")

    if ai_report_text:
        lines += ["", "## AI-Generated Explanation", ai_report_text]

    lines += [
        "",
        "---",
        "_Generated locally by the Phishing Threat Detector. This is a heuristic triage aid, "
        "not a certified detection engine -- confirm findings before acting on them._",
    ]
    return "\n".join(lines)


# ----------------------------------------------------------------------------
# Session state
# ----------------------------------------------------------------------------

st.session_state.setdefault("history", [])
st.session_state.setdefault("last_result", None)
st.session_state.setdefault("ai_report_text", None)


# ----------------------------------------------------------------------------
# Sidebar
# ----------------------------------------------------------------------------

with st.sidebar:
    st.markdown("### ⚙️ Local LLM Settings")
    ollama_host = st.text_input("Ollama host", value=DEFAULT_HOST)
    available_models = _list_models_cached(ollama_host)

    if available_models:
        model = st.selectbox("Model", available_models)
        st.success(f"Connected -- {len(available_models)} model(s) available")
    else:
        model = None
        st.warning("Can't reach Ollama at this host.")
        st.caption("From a terminal:")
        st.code("ollama serve\nollama pull llama3.2", language="bash")

    st.divider()
    st.markdown("### ℹ️ About")
    st.caption(
        "URL, keyword, and header analysis run entirely offline using local rules -- "
        "nothing about the email is sent anywhere. The optional AI write-up below is sent "
        "only to your own local Ollama instance."
    )
    st.caption("Heuristic triage tool for education/portfolio use -- not a certified detection engine.")


# ----------------------------------------------------------------------------
# Header
# ----------------------------------------------------------------------------

st.markdown("## 🎣 Phishing Threat Detector")
st.caption(
    "Upload a suspicious email for automated triage: URL and sender analysis, "
    "suspicious-language detection, a risk score, and an optional plain-English write-up."
)

tab_analyze, tab_history = st.tabs(["🔍 Analyze Email", "📋 Scan History"])

# ----------------------------------------------------------------------------
# Analyze tab
# ----------------------------------------------------------------------------

with tab_analyze:
    raw_bytes = None
    raw_text = None
    source_label = None

    input_mode = st.radio("Provide the email as:", [".eml file", "Pasted text"], horizontal=True)

    if input_mode == ".eml file":
        uploaded = st.file_uploader("Upload a .eml file", type=["eml"])
        if uploaded is not None:
            raw_bytes = uploaded.getvalue()
            source_label = uploaded.name
    else:
        raw_text = st.text_area(
            "Paste the email source (with headers) or just the body text",
            height=200,
            placeholder="From: \"Support\" <support@example.com>\nSubject: ...\n\nDear customer, ...",
        )
        if raw_text and raw_text.strip():
            source_label = "Pasted text"

    st.caption("No email handy? Try a bundled example:")
    sc1, sc2 = st.columns(2)
    sample_clicked = False
    if sc1.button("🎣 Load phishing example", width="stretch"):
        raw_bytes = (SAMPLE_DIR / "phishing_example.eml").read_bytes()
        raw_text = None
        source_label = "phishing_example.eml (bundled sample)"
        sample_clicked = True
    if sc2.button("✅ Load legitimate example", width="stretch"):
        raw_bytes = (SAMPLE_DIR / "legitimate_example.eml").read_bytes()
        raw_text = None
        source_label = "legitimate_example.eml (bundled sample)"
        sample_clicked = True

    have_input = bool(raw_bytes) or bool(raw_text and raw_text.strip())
    analyze_clicked = st.button("🔎 Analyze Email", type="primary", disabled=not have_input) or sample_clicked

    if analyze_clicked:
        try:
            parsed = (
                email_parser.parse_eml_bytes(raw_bytes)
                if raw_bytes is not None
                else email_parser.parse_raw_text(raw_text)
            )
        except Exception as e:
            st.error(f"Couldn't parse that email: {e}")
            st.stop()

        known_brands = _load_known_brands()
        keyword_db = _load_keyword_db()

        url_results = url_analyzer.analyze_urls(parsed.urls, parsed.html_links, known_brands)
        keyword_results = keyword_detector.detect_keywords(parsed.combined_text, keyword_db)
        risk = risk_scorer.score_email(parsed, url_results, keyword_results, known_brands)

        st.session_state.last_result = {
            "parsed": parsed,
            "url_results": url_results,
            "keyword_results": keyword_results,
            "risk": risk,
            "source_label": source_label,
        }
        st.session_state.ai_report_text = None  # new email -> any previous AI write-up no longer applies

        st.session_state.history.insert(
            0,
            {
                "Time": datetime.now().strftime("%H:%M:%S"),
                "Source": source_label,
                "Subject": parsed.subject or "(none)",
                "Sender": parsed.from_address or "(none)",
                "Score": risk.score,
                "Tier": risk.tier,
            },
        )

    # --- Render the most recent result (persists across unrelated reruns, e.g. sidebar edits) ---
    result = st.session_state.last_result
    if result:
        parsed = result["parsed"]
        url_results = result["url_results"]
        keyword_results = result["keyword_results"]
        risk = result["risk"]
        source_label = result["source_label"]

        st.divider()
        render_verdict_card(risk)

        m1, m2, m3, m4 = st.columns(4)
        m1.metric("URLs flagged", f"{sum(1 for r in url_results if r['score'] > 0)}/{len(url_results)}")
        m2.metric("Content flags", sum(len(d["matched"]) for d in keyword_results.values()))
        m3.metric("Header anomalies", len(risk.header_flags))
        m4.metric("Attachments", len(parsed.attachments))

        tab_urls, tab_kw, tab_headers, tab_attach = st.tabs(
            ["🔗 URLs", "🔑 Keywords", "📧 Headers", "📎 Attachments"]
        )

        with tab_urls:
            if not url_results:
                st.info("No URLs were found in this email.")
            for r in url_results:
                with st.container(border=True):
                    c1, c2 = st.columns([6, 1])
                    c1.markdown(mono(r["url"]))
                    c2.markdown(f"**{r['score']}**/100")
                    if r["flags"]:
                        for f in r["flags"]:
                            st.markdown(f"- {f}")
                    else:
                        st.caption("No red flags detected for this URL.")

        with tab_kw:
            if not keyword_results:
                st.info("No suspicious language patterns matched.")
            for data in keyword_results.values():
                with st.container(border=True):
                    st.markdown(f"**{data['label']}**")
                    st.write(", ".join(mono(p) for p in data["matched"]))

        with tab_headers:
            st.markdown(f"**From:** {parsed.from_display or '(none)'} -- {mono(parsed.from_address)}")
            st.markdown(f"**Reply-To:** {mono(parsed.reply_to_address)}")
            st.markdown(f"**Return-Path:** {mono(parsed.return_path_address)}")
            st.markdown(f"**Subject:** {mono(parsed.subject)}")
            st.markdown(f"**Date:** {parsed.date or '(none)'}")
            st.divider()
            if risk.header_flags:
                for f in risk.header_flags:
                    st.warning(f)
            else:
                st.success("No sender header anomalies detected.")

        with tab_attach:
            if not parsed.attachments:
                st.info("No attachments found.")
            else:
                for a in parsed.attachments:
                    with st.container(border=True):
                        st.markdown(f"{mono(a.filename)} -- {a.content_type}, {a.size:,} bytes")
                if risk.attachment_flags:
                    st.divider()
                    for f in risk.attachment_flags:
                        st.warning(f)

        st.divider()
        st.markdown("#### 📝 AI-Generated Explanation")

        if st.session_state.ai_report_text:
            st.markdown(st.session_state.ai_report_text)
            if st.button("🔄 Regenerate"):
                st.session_state.ai_report_text = None
                st.rerun()
        elif not model:
            st.info("Connect a local Ollama model (see sidebar) to generate a plain-English write-up.")
        else:
            if st.button(f"✨ Generate explanation with {model}"):
                findings_text = llm_reporter.format_findings(parsed, risk, url_results, keyword_results)
                try:
                    with st.spinner("Contacting local Ollama model..."):
                        generated = st.write_stream(
                            llm_reporter.stream_report(ollama_host, model, findings_text)
                        )
                    st.session_state.ai_report_text = generated
                    st.rerun()
                except llm_reporter.OllamaUnavailable as e:
                    st.error(str(e))

        st.divider()
        report_md = build_report_markdown(
            parsed, risk, url_results, keyword_results, st.session_state.ai_report_text, source_label
        )
        st.download_button(
            "⬇️ Download Full Report (Markdown)",
            data=report_md,
            file_name=f"phishing_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md",
            mime="text/markdown",
            width="stretch",
        )

# ----------------------------------------------------------------------------
# History tab
# ----------------------------------------------------------------------------

with tab_history:
    if st.session_state.history:
        st.dataframe(st.session_state.history, width="stretch", hide_index=True)
        if st.button("🗑️ Clear history"):
            st.session_state.history = []
            st.rerun()
    else:
        st.info("No scans yet this session. Analyze an email to see it logged here.")

st.divider()
st.caption(
    "Phishing Threat Detector -- local, rule-based analysis with an optional local-LLM write-up. "
    "Built for triage and documentation support, not as a sole basis for security decisions."
)
