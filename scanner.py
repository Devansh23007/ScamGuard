"""Auto-scan Gmail.   python scanner.py            (scan once)
                     python scanner.py --watch    (keep scanning every few minutes)"""
from __future__ import annotations
import argparse
import time

import agent
import config
import email_parser
import email_signals
import gmail_client
import llm_analyzer
import storage
import url_checker

LABELS = {"scam": "ScamGuard/Scam", "likely_scam": "ScamGuard/Scam", "suspicious": "ScamGuard/Suspicious"}
LLM_MIN_RULE_SCORE = 10   # only spend AI quota on emails the rules found at least slightly odd


def scan_once(service=None, query: str | None = None, max_emails: int = 50, use_llm: bool = True,
              max_llm: int = 25, log=print) -> dict:
    storage.init()
    service = service or gmail_client.get_service()
    ids = [i for i in gmail_client.list_message_ids(service, query or config.SCAN_QUERY, 300)
           if not storage.seen(i)][:max_emails]

    stats = {"scanned": 0, "scam": 0, "suspicious": 0, "llm_calls": 0, "errors": 0}
    label_ids: dict[str, str] = {}
    can_llm = use_llm and llm_analyzer.llm_available()

    for mid in ids:
        try:
            email = email_parser.parse_message(gmail_client.get_message(service, mid))
            sender = f"{email.sender_name} <{email.sender_email}>".strip()

            if email.sender_domain in config.SCAN_ALLOWLIST:
                storage.save(dict(id=mid, sender=sender, subject=email.subject, date=email.date, score=0,
                                  verdict="low_risk", scam_type="Allow-listed sender", summary="Trusted sender, skipped.",
                                  signals=[], llm_used=False, labeled=False))
                stats["scanned"] += 1
                continue

            extra = email_signals.analyze_email(email)
            text = email.analysis_text()
            report = agent.analyze(text, use_llm=False, extra_signals=extra)          # stage 1: free rules
            if can_llm and report.heuristic_score >= LLM_MIN_RULE_SCORE and stats["llm_calls"] < max_llm:
                report = agent.analyze(text, use_llm=True, extra_signals=extra)      # stage 2: AI second opinion
                stats["llm_calls"] += 1

            trusted = (email.auth.get("dmarc") == "pass"
                       and url_checker.registered_domain(email.sender_domain) not in email_signals.FREEMAIL)
            agent.bulk_dampen(report, trusted, ceiling=60 if email.list_unsub else 45)

            labeled = False
            name = LABELS.get(report.verdict)
            if name and config.APPLY_LABELS and not config.GMAIL_READONLY:
                if name not in label_ids:
                    label_ids[name] = gmail_client.ensure_label(service, name)
                gmail_client.add_label(service, mid, label_ids[name])
                labeled = True

            storage.save(dict(
                id=mid, sender=sender, subject=email.subject, date=email.date, score=report.score,
                verdict=report.verdict, scam_type=report.scam_type, summary=report.summary,
                signals=[dict(title=s.title, detail=s.detail, critical=s.critical, evidence=s.evidence)
                         for s in report.signals],
                llm_used=report.llm_used, labeled=labeled))
            stats["scanned"] += 1
            if report.verdict in ("scam", "likely_scam"):
                stats["scam"] += 1
                log(f"🚨 {report.score:>3}  {sender[:40]:<40} | {email.subject[:50]}")
            elif report.verdict == "suspicious":
                stats["suspicious"] += 1
                log(f"⚠️  {report.score:>3}  {sender[:40]:<40} | {email.subject[:50]}")
        except Exception as e:       # one bad email must never stop the scan
            stats["errors"] += 1
            log(f"error on {mid}: {type(e).__name__}: {e}")
    return stats


def main():
    p = argparse.ArgumentParser(description="ScamGuard Gmail scanner")
    p.add_argument("--watch", action="store_true", help="keep running and re-scan periodically")
    p.add_argument("--interval", type=int, default=config.SCAN_INTERVAL_MIN, help="minutes between scans")
    p.add_argument("--no-llm", action="store_true", help="rules only")
    p.add_argument("--query", default=None, help="Gmail search query, e.g. 'in:inbox is:unread'")
    a = p.parse_args()

    service = gmail_client.get_service()   # first run opens browser for consent
    mode = "READ-ONLY" if config.GMAIL_READONLY else ("labeling on" if config.APPLY_LABELS else "no labels")
    print(f"ScamGuard connected to Gmail ({mode}). AI: {'on' if llm_analyzer.llm_available() and not a.no_llm else 'off'}")
    while True:
        s = scan_once(service, a.query, use_llm=not a.no_llm)
        print(f"[{time.strftime('%H:%M:%S')}] scanned {s['scanned']} | scams {s['scam']} | "
              f"suspicious {s['suspicious']} | AI calls {s['llm_calls']} | errors {s['errors']}")
        if not a.watch:
            break
        time.sleep(a.interval * 60)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nstopped")