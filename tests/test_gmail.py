import base64, os, sys, tempfile
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import config
config.DB_PATH = os.path.join(tempfile.mkdtemp(), "t.db")
config.GMAIL_READONLY = False
import agent, email_parser, email_signals, scanner, storage, url_checker


def b64(s): return base64.urlsafe_b64encode(s.encode()).decode()

def make(id_, frm, subject, html="", plain="", auth="spf=pass dkim=pass dmarc=pass", reply="", atts=()):
    parts = []
    if plain: parts.append({"mimeType": "text/plain", "body": {"data": b64(plain)}})
    if html: parts.append({"mimeType": "text/html", "body": {"data": b64(html)}})
    for a in atts: parts.append({"mimeType": "application/octet-stream", "filename": a, "body": {}})
    hdr = [{"name": "From", "value": frm}, {"name": "Subject", "value": subject},
           {"name": "Date", "value": "Mon, 9 Nov 2026 10:00:00 +0530"},
           {"name": "Authentication-Results", "value": "mx.google.com; " + auth}]
    if reply: hdr.append({"name": "Reply-To", "value": reply})
    return {"id": id_, "threadId": id_, "payload": {"mimeType": "multipart/mixed", "headers": hdr, "parts": parts}}

PHISH = make("m1", "SBI Bank <alerts.sbi.help@gmail.com>", "URGENT: KYC expired",
             html='<p>Your account will be blocked today. <a href="http://sbi-kyc-verify.top/x">www.onlinesbi.com</a></p>',
             auth="spf=fail dkim=none dmarc=fail", reply="collect@mailbox.xyz", atts=["kyc_form.apk"])
SAFE = make("m2", "Riya <riya@example.com>", "Lunch tomorrow?", plain="Hey, want to grab lunch at 1pm tomorrow?")
JOB = make("m3", "HR Team <hr.careers@gmail.com>", "Work from home job",
           plain="Earn Rs 5000 per day, no experience needed. Pay Rs 999 registration fee. Contact on WhatsApp.")


def test_parser_extracts_links_and_auth():
    e = email_parser.parse_message(PHISH)
    assert e.sender_email == "alerts.sbi.help@gmail.com" and e.auth["dmarc"] == "fail"
    assert e.links and e.attachments == ["kyc_form.apk"]

def test_email_signals_catch_phish():
    ids = {s.id for s in email_signals.analyze_email(email_parser.parse_message(PHISH))}
    assert {"sender_spoof", "auth_fail", "link_mismatch", "att_danger", "reply_mismatch"} <= ids

def test_safe_email_has_no_signals():
    assert email_signals.analyze_email(email_parser.parse_message(SAFE)) == []


class _Exec:
    def __init__(self, v): self.v = v
    def execute(self): return self.v

class FakeGmail:
    def __init__(self, msgs): self.msgs = {m["id"]: m for m in msgs}; self.labeled = {}; self.lbl = {}
    def users(self): return self
    def messages(self): return self
    def labels(self): return self
    def list(self, **kw):
        if "q" in kw: return _Exec({"messages": [{"id": i} for i in self.msgs]})
        return _Exec({"labels": [{"name": n, "id": i} for n, i in self.lbl.items()]})
    def get(self, userId, id, format): return _Exec(self.msgs[id])
    def create(self, userId, body):
        self.lbl[body["name"]] = "L_" + str(len(self.lbl)); return _Exec({"id": self.lbl[body["name"]]})
    def modify(self, userId, id, body): self.labeled[id] = body["addLabelIds"]; return _Exec({})


def test_scanner_labels_scams_only_and_is_idempotent():
    g = FakeGmail([PHISH, SAFE, JOB])
    s = scanner.scan_once(g, use_llm=False, log=lambda *_: None)
    assert s["scanned"] == 3 and s["errors"] == 0
    assert g.labeled == {}   # labels off by default, verdicts saved to storage
    assert scanner.scan_once(g, use_llm=False, log=lambda *_: None)["scanned"] == 0   # no re-scan
    assert storage.counts().get("low_risk", 0) == 1
    assert storage.counts().get("scam", 0) + storage.counts().get("likely_scam", 0) == 2


def test_readonly_mode_adds_no_labels():
    config.APPLY_LABELS = True
    config.GMAIL_READONLY = True
    try:
        g = FakeGmail([make("m9", "Bank <x@gmail.com>", "KYC", plain="Update KYC now, account will be blocked. Share OTP")])
        scanner.scan_once(g, use_llm=False, log=lambda *_: None)
        assert g.labeled == {}
    finally:
        config.APPLY_LABELS = False
        config.GMAIL_READONLY = False


def test_unstop_newsletter_is_low_risk():
    unstop = make("n1", "Unstop <newsletter@unstop.com>", "Exciting opportunities",
                  html='<p>Apply now: <a href="https://click.unstop.com/track/123">View 500+ internships</a></p>',
                  auth="spf=pass dkim=pass dmarc=pass")
    e = email_parser.parse_message(unstop)
    extra = email_signals.analyze_email(e)
    rep = agent.analyze(e.analysis_text(), use_llm=False, extra_signals=extra)
    trusted = (e.auth.get("dmarc") == "pass" and url_checker.registered_domain(e.sender_domain) not in email_signals.FREEMAIL)
    rep = agent.bulk_dampen(rep, trusted, ceiling=60 if e.list_unsub else 45)
    assert rep.verdict == "low_risk"


def test_google_security_notice_is_low_risk():
    google = make("n2", "Google <no-reply@accounts.google.com>", "Security alert: Access granted to bolt.new",
                  html='<p>Access granted. <a href="https://myaccount.google.com/permissions">Check activity</a></p>',
                  auth="spf=pass dkim=pass dmarc=pass")
    e = email_parser.parse_message(google)
    extra = email_signals.analyze_email(e)
    rep = agent.analyze(e.analysis_text(), use_llm=False, extra_signals=extra)
    trusted = (e.auth.get("dmarc") == "pass" and url_checker.registered_domain(e.sender_domain) not in email_signals.FREEMAIL)
    rep = agent.bulk_dampen(rep, trusted, ceiling=60 if e.list_unsub else 45)
    assert rep.verdict == "low_risk"


def test_lablab_newsletter_is_low_risk():
    lablab = make("n3", "Lablab.ai <newsletter@lablab.ai>", "Join the latest AI Hackathon",
                  html='<p>Build AI apps this weekend: <a href="https://track.lablab.ai/clk/abc">Register now</a></p>',
                  auth="spf=pass dkim=pass dmarc=pass")
    e = email_parser.parse_message(lablab)
    extra = email_signals.analyze_email(e)
    rep = agent.analyze(e.analysis_text(), use_llm=False, extra_signals=extra)
    trusted = (e.auth.get("dmarc") == "pass" and url_checker.registered_domain(e.sender_domain) not in email_signals.FREEMAIL)
    rep = agent.bulk_dampen(rep, trusted, ceiling=60 if e.list_unsub else 45)
    assert rep.verdict == "low_risk"

