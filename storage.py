"""SQLite history of scanned emails. Stores metadata + verdict only, never the email body."""
from __future__ import annotations
import json
import sqlite3
import time

import config


def _conn() -> sqlite3.Connection:
    c = sqlite3.connect(config.DB_PATH)
    c.row_factory = sqlite3.Row
    return c


def init() -> None:
    with _conn() as c:
        c.execute("""CREATE TABLE IF NOT EXISTS scans (
            id TEXT PRIMARY KEY, scanned_at REAL, sender TEXT, subject TEXT, date TEXT,
            score INTEGER, verdict TEXT, scam_type TEXT, summary TEXT, signals TEXT,
            llm_used INTEGER, labeled INTEGER)""")


def seen(msg_id: str) -> bool:
    with _conn() as c:
        return c.execute("SELECT 1 FROM scans WHERE id=?", (msg_id,)).fetchone() is not None


def save(rec: dict) -> None:
    with _conn() as c:
        c.execute("INSERT OR REPLACE INTO scans VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", (
            rec["id"], time.time(), rec["sender"], rec["subject"], rec["date"], rec["score"],
            rec["verdict"], rec["scam_type"], rec["summary"], json.dumps(rec["signals"]),
            int(rec["llm_used"]), int(rec["labeled"])))


def recent(limit: int = 200, verdicts: list[str] | None = None) -> list[dict]:
    q, args = "SELECT * FROM scans", []
    if verdicts:
        q += f" WHERE verdict IN ({','.join('?' * len(verdicts))})"
        args = list(verdicts)
    q += " ORDER BY scanned_at DESC LIMIT ?"
    with _conn() as c:
        rows = [dict(r) for r in c.execute(q, (*args, limit))]
    for r in rows:
        r["signals"] = json.loads(r["signals"] or "[]")
    return rows


def counts() -> dict:
    with _conn() as c:
        return {r["verdict"]: r["n"] for r in c.execute("SELECT verdict, COUNT(*) n FROM scans GROUP BY verdict")}


def get_many(ids: list[str]) -> dict[str, dict]:
    """Brief stored results keyed by Gmail message/thread id (used by the extension)."""
    ids = [i for i in ids if i][:200]
    if not ids:
        return {}
    init()
    with _conn() as c:
        rows = c.execute(f"SELECT * FROM scans WHERE id IN ({','.join('?' * len(ids))})", ids).fetchall()
    out = {}
    for r in rows:
        sigs = json.loads(r["signals"] or "[]")
        out[r["id"]] = {"verdict": r["verdict"], "score": r["score"], "type": r["scam_type"],
                        "reasons": [x["title"] for x in sigs[:3]]}
    return out