"""Scam signals that only exist in emails: sender spoofing, auth failures, link tricks, attachments."""
from __future__ import annotations
import re
from urllib.parse import urlparse

from models import Signal
from email_parser import EmailData
from url_checker import BRANDS, registered_domain

FREEMAIL = {"gmail.com", "yahoo.com", "yahoo.in", "outlook.com", "hotmail.com", "rediffmail.com",
            "proton.me", "protonmail.com", "icloud.com", "live.com", "aol.com"}
ROLE_WORDS = re.compile(r"\b(hr|recruit\w*|career\w*|hiring|bank|support|care|customer|security|"
                        r"accounts?|payroll|helpdesk|admin)\b", re.I)
DANGEROUS_EXT = {"apk", "exe", "scr", "js", "vbs", "bat", "cmd", "msi", "lnk", "hta", "jar", "ps1"}
RISKY_EXT = {"html", "htm", "zip", "rar", "7z", "iso", "img", "docm", "xlsm", "pptm"}
DOMAIN_TEXT_RE = re.compile(r"^(?:https?://)?(?:www\.)?((?:[a-z0-9-]+\.)+[a-z]{2,})(?:[/?#:].*)?$", re.I)


def _sig(id_, title, detail, w, critical=False, cat="email", ev=""):
    return Signal(id_, title, detail, w, critical, cat, ev[:90])


def analyze_email(e: EmailData) -> list[Signal]:
    out: list[Signal] = []
    sender_reg = registered_domain(e.sender_domain) if e.sender_domain else ""
    name_l = e.sender_name.lower()

    # 1) Display name pretends to be a known brand
    tokens = set(re.split(r"[^a-z0-9]+", name_l))
    for brand in BRANDS:
        if (brand in tokens or (len(brand) >= 5 and brand in name_l)) and brand not in e.sender_domain:
            freemail = sender_reg in FREEMAIL
            out.append(_sig("sender_spoof", f"Sender name says '{brand}' but address is {e.sender_email}",
                            "The display name is easy to fake. The real address doesn't belong to that company.",
                            0.65 if freemail else 0.5, critical=freemail, cat="impersonation",
                            ev=f"{e.sender_name} <{e.sender_email}>"))
            break

    # 2) Official-sounding role from a free mailbox
    if sender_reg in FREEMAIL and ROLE_WORDS.search(e.sender_name + " " + e.subject) and not any(
            s.id == "sender_spoof" for s in out):
        out.append(_sig("freemail_role", "Official-sounding sender using a free email address",
                        "Real banks and companies send from their own domain, not Gmail/Yahoo.",
                        0.3, cat="impersonation", ev=e.sender_email))

    # 3) Reply-To points somewhere else
    if e.reply_to and e.sender_domain and registered_domain(e.reply_to.rsplit("@", 1)[-1]) != sender_reg:
        out.append(_sig("reply_mismatch", "Replies go to a different address than the sender",
                        "Scammers send from one address but collect replies on another.",
                        0.3, ev=f"Reply-To: {e.reply_to}"))

    # 4) Failed authentication
    a = e.auth
    fails = [k for k, v in a.items() if v in ("fail", "softfail", "permerror")]
    if fails:
        strong = a.get("dmarc") == "fail" or ("spf" in fails and a.get("dkim") != "pass")
        out.append(_sig("auth_fail", "Sender authentication failed (" + ", ".join(k.upper() for k in fails) + ")",
                        "The email may be forged. Genuine mail from real companies normally passes these checks.",
                        0.45 if strong else 0.3, cat="impersonation", ev=str(a)))

    # 5) Link text shows one site, link goes to another
    for text, href in e.links:
        m = DOMAIN_TEXT_RE.match(text.strip())
        host = (urlparse(href).hostname or "").lower()
        if not m or not host:
            continue
        shown, real = registered_domain(m.group(1).lower()), registered_domain(host)
        if shown != real:
            brand_official = any(shown in official for official in BRANDS.values())
            if not brand_official and not fails:     # tracking redirects are normal in legit newsletters
                continue
            out.append(_sig("link_mismatch",
                            f"Link says {shown} but actually goes to {real}",
                            "The visible text and the real destination differ, and the sender failed authentication.",
                            0.6 if brand_official else 0.3, critical=brand_official, cat="link",
                            ev=f"{text[:40]} -> {href[:60]}"))
            break

    # 6) Risky attachments
    for fn in e.attachments:
        ext = fn.lower().rsplit(".", 1)[-1] if "." in fn else ""
        if ext in DANGEROUS_EXT or re.search(r"\.\w{2,4}\.(exe|scr|js|vbs|bat|apk|lnk)$", fn.lower()):
            out.append(_sig("att_danger", f"Dangerous attachment type (.{ext})",
                            "Executable/script files can install malware. Never open them.",
                            0.65, critical=True, cat="remote", ev=fn))
            break
        if ext in RISKY_EXT:
            out.append(_sig("att_risky", f"Risky attachment type (.{ext})",
                            "HTML, archive and macro files are often used to deliver phishing or malware.",
                            0.3, cat="remote", ev=fn))
            break
    return out