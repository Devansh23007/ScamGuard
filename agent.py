"""ScamGuard agent: heuristics + link checks + Groq LLM, fused into one report."""
from __future__ import annotations

import heuristics
import url_checker
import llm_analyzer
from models import Report, Signal

VERDICTS = [
    (75, "scam", "🚨 High-risk scam"),
    (50, "likely_scam", "⚠️ Likely a scam"),
    (25, "suspicious", "🤔 Suspicious, verify first"),
    (0, "low_risk", "✅ Low risk"),
]

BASE_ACTIONS = {
    "scam": [
        "Do NOT click links, reply, call back, or share OTP/PIN/card details.",
        "If you already paid or shared details, call 1930 right away and tell your bank.",
        "Report it at cybercrime.gov.in and block the sender.",
    ],
    "likely_scam": [
        "Don't act on it. Verify through the official app or website you type in yourself.",
        "Call the number printed on your card or the company's official site, not the one in the message.",
        "Report and block the sender.",
    ],
    "suspicious": [
        "Pause. Verify the sender through an independent channel before responding.",
        "Never pay a fee or share OTP/PIN to 'get' a job, refund, or prize.",
    ],
    "low_risk": [
        "No strong red flags found, but stay careful with links and payment requests.",
    ],
}


def verdict_for(score: int) -> tuple[str, str]:
    for threshold, key, label in VERDICTS:
        if score >= threshold:
            return key, label
    return "low_risk", VERDICTS[-1][2]


def bulk_dampen(report: Report, is_bulk: bool, ceiling: int = 60) -> Report:
    """Authenticated newsletter-style mail with only weak evidence shouldn't be flagged.
    Never applies when a critical signal fired or the score is already high."""
    if is_bulk and 25 <= report.score < ceiling and not any(s.critical for s in report.signals):
        report.score = 24
        report.verdict, report.verdict_label = verdict_for(24)
        report.summary = "Looks like a regular bulk/newsletter email with only weak warning signs."
    return report


def analyze(text: str = "", images: list[tuple[bytes, str]] | None = None,
            use_llm: bool = True, extra_signals: list[Signal] | None = None) -> Report:
    text = (text or "").strip()
    images = images or []

    # 1) Groq LLM (also reads screenshots)
    llm, llm_error = None, None
    if use_llm and llm_analyzer.llm_available():
        try:
            llm = llm_analyzer.analyze_with_llm(text, images)
        except Exception as e:  # never crash the user flow on an API hiccup
            llm_error = f"{type(e).__name__}: {e}"
    elif images and not text:
        llm_error = "Screenshot analysis needs an GROQ_API_KEY."

    extracted = (llm or {}).get("extracted_text", "") or ""
    full_text = "\n".join(t for t in (text, extracted) if t)

    # 2) Rules + links
    signals: list[Signal] = heuristics.analyze_text(full_text) + url_checker.analyze_urls(full_text)
    signals += list(extra_signals or [])
    urls = url_checker.extract_urls(full_text)
    flagged = url_checker.safe_browsing_flagged(urls)
    for u in flagged:
        signals.append(Signal("safe_browsing", "Google Safe Browsing flagged this link",
                              "This URL is on Google's malware/phishing list.", 0.9, True, "link", u[:90]))
    h_score = heuristics.combine_score(signals)

    # 3) Fuse
    if llm:
        l_score = llm["scam_probability"]
        score = round(0.4 * h_score + 0.6 * l_score)
        if any(s.critical for s in signals):
            score = max(score, 75)
    else:
        l_score = None
        score = h_score

    key, label = verdict_for(score)
    scam_type = (llm or {}).get("scam_type") or heuristics.guess_scam_type(signals)

    if llm and llm.get("summary"):
        summary = llm["summary"]
    elif signals:
        summary = f"Found {len(signals)} warning sign(s). Top concern: {max(signals, key=lambda s: s.weight).title}."
    else:
        summary = "No known scam patterns were detected."

    actions = list(BASE_ACTIONS[key])
    for a in (llm or {}).get("recommended_actions", []):
        if a not in actions:
            actions.append(a)

    return Report(
        score=score, verdict=key, verdict_label=label, scam_type=scam_type, summary=summary,
        signals=sorted(signals, key=lambda s: s.weight, reverse=True),
        heuristic_score=h_score, llm_score=l_score, llm_used=bool(llm), llm_error=llm_error,
        safe_signs=(llm or {}).get("legit_indicators", []), actions=actions,
        extracted_text=extracted, flagged_urls=flagged,
    )