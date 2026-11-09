import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from fastapi.testclient import TestClient
import server
c = TestClient(server.app)
EXT = {"Origin": "chrome-extension://abcdef"}

def test_blocks_web_origins():
    assert c.get("/health", headers={"Origin": "https://evil.com"}).status_code == 403
    assert c.get("/health", headers=EXT).status_code == 200

def test_batch_flags_scam_and_ignores_safe():
    items = [
      {"key": "a", "sender_name": "HR Team", "sender_email": "hr.jobs@gmail.com", "subject": "Work from home job",
       "snippet": "Earn Rs 5000 per day, no experience needed. Pay Rs 999 registration fee."},
      {"key": "b", "sender_name": "Riya", "sender_email": "riya@example.com", "subject": "Lunch?", "snippet": "1pm tomorrow?"},
      {"key": "c", "sender_name": "SBI Bank", "sender_email": "alert@gmail.com", "subject": "KYC expired", "snippet": "Update now"},
    ]
    res = {r["key"]: r for r in c.post("/check-batch", json={"items": items}, headers=EXT).json()["results"]}
    assert res["a"]["verdict"] in ("likely_scam", "scam") and res["a"]["type"] == "Fake job offer"
    assert res["b"]["verdict"] == "low_risk"
    assert res["c"]["verdict"] in ("likely_scam", "scam")

def test_open_email_catches_hidden_link():
    body = {"sender_name": "Amazon", "sender_email": "support@amazon-help.xyz", "subject": "Order problem",
            "body": "Please verify your payment urgently", "attachments": [],
            "links": [{"text": "www.amazon.in/orders", "href": "http://amazon-verify.top/login"}]}
    d = c.post("/check-email", json=body, headers=EXT).json()
    assert d["verdict"] in ("likely_scam", "scam") and d["signals"] and d["summary"]
