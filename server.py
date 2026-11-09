"""Local ScamGuard API for the Chrome extension.   python server.py   (listens on 127.0.0.1 only)"""
from __future__ import annotations
import hashlib
import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

import agent
import email_signals
import llm_analyzer
import storage
from email_parser import EmailData

AI_ON_OPEN = os.getenv("EXT_AI_ON_OPEN", "1") == "1"      # use Groq when you OPEN a suspicious email
EXTENSION_ID = os.getenv("EXTENSION_ID", "")              # optional: lock to your extension's ID
LLM_MIN_RULE_SCORE = 10

storage.init()
app = FastAPI(title="ScamGuard local API")
app.add_middleware(CORSMiddleware, allow_origin_regex=r"chrome-extension://.*",
                   allow_methods=["GET", "POST"], allow_headers=["*"])


@app.middleware("http")
async def extension_only(request, call_next):
    """Browsers always send Origin. Reject web pages so no website can call this local server."""
    origin = request.headers.get("origin")
    if origin:
        ok = origin.startswith("chrome-extension://") and (not EXTENSION_ID or origin.endswith(EXTENSION_ID))
        if not ok:
            return JSONResponse({"error": "forbidden origin"}, status_code=403)
    return await call_next(request)


class Item(BaseModel):
    key: str
    sender_name: str = ""
    sender_email: str = ""
    subject: str = ""
    snippet: str = ""
    thread_id: str = ""


class Batch(BaseModel):
    items: list[Item]


class Link(BaseModel):
    text: str = ""
    href: str = ""


class OpenEmail(BaseModel):
    sender_name: str = ""
    sender_email: str = ""
    subject: str = ""
    body: str = ""
    links: list[Link] = []
    attachments: list[str] = []


_cache: dict[str, dict] = {}


def _remember(k: str, v: dict) -> dict:
    if len(_cache) > 3000:
        _cache.clear()
    _cache[k] = v
    return v


@app.get("/health")
def health():
    return {"ok": True, "llm": llm_analyzer.llm_available(), "ai_on_open": AI_ON_OPEN}


@app.post("/check-batch")
def check_batch(b: Batch):
    """Fast, free, offline rules only. Used for the badges in the inbox list."""
    results = []
    items = b.items[:100]
    full = storage.get_many([it.thread_id for it in items])       # results from the full Gmail scanner
    for it in items:
        if it.thread_id in full:
            results.append({"key": it.key, **full[it.thread_id], "source": "full"})
            continue
        ck = "q:" + hashlib.sha1(f"{it.sender_email}|{it.subject}|{it.snippet}".encode()).hexdigest()
        hit = _cache.get(ck)
        if hit is None:
            e = EmailData(id=it.key, sender_name=it.sender_name[:100], sender_email=it.sender_email.lower()[:200],
                          subject=it.subject[:300], body=it.snippet[:400])
            r = agent.analyze(e.analysis_text(), use_llm=False, extra_signals=email_signals.analyze_email(e))
            hit = _remember(ck, {"verdict": r.verdict, "score": r.score, "type": r.scam_type,
                                 "reasons": [s.title for s in r.signals[:3]]})
        results.append({"key": it.key, **hit, "source": "quick"})
    return {"results": results}


@app.post("/check-email")
def check_email(m: OpenEmail):
    """Deeper check of the email you opened: real link targets, attachments, plus AI on suspicious ones."""
    ck = "e:" + hashlib.sha1(f"{m.sender_email}|{m.subject}|{m.body[:1500]}|{len(m.links)}".encode()).hexdigest()
    if ck in _cache:
        return _cache[ck]
    e = EmailData(id="open", sender_name=m.sender_name[:100], sender_email=m.sender_email.lower()[:200],
                  subject=m.subject[:300], body=m.body[:6000],
                  links=[(l.text[:200], l.href[:500]) for l in m.links[:30]], attachments=m.attachments[:10])
    extra, text = email_signals.analyze_email(e), e.analysis_text()
    r = agent.analyze(text, use_llm=False, extra_signals=extra)
    if AI_ON_OPEN and llm_analyzer.llm_available() and r.heuristic_score >= LLM_MIN_RULE_SCORE:
        r = agent.analyze(text, use_llm=True, extra_signals=extra)
    agent.bulk_dampen(r, "unsubscribe" in m.body.lower())
    return _remember(ck, {
        "verdict": r.verdict, "label": r.verdict_label, "score": r.score, "type": r.scam_type,
        "summary": r.summary, "llm_used": r.llm_used,
        "signals": [{"title": s.title, "detail": s.detail, "critical": s.critical} for s in r.signals[:5]],
        "actions": r.actions[:3]})


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("SCAMGUARD_PORT", "8765"))
    print(f"ScamGuard server on http://127.0.0.1:{port}  (AI: {'on' if llm_analyzer.llm_available() else 'off'})")
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning")