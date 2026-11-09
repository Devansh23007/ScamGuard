from __future__ import annotations
import re
from urllib.parse import urlparse

import requests

import config
from models import Signal

URL_RE = re.compile(
    r"(?i)\b(?:https?://|www\.)[^\s<>\"')\]]+"
    r"|\b(?:bit\.ly|tinyurl\.com|t\.co|cutt\.ly|rb\.gy|is\.gd|shorturl\.at|goo\.gl|wa\.me|t\.me)/[^\s<>\"')\]]+"
)

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "cutt.ly", "rb.gy", "is.gd",
              "shorturl.at", "goo.gl", "ow.ly", "tiny.cc", "s.id"}

RISKY_TLDS = {"xyz", "top", "club", "click", "icu", "vip", "work", "live", "buzz",
              "loan", "cfd", "sbs", "rest", "fit", "monster", "gq", "tk", "ml", "cf"}

# brand keyword -> official registered domains (edit/extend as needed)
BRANDS = {
    "sbi": {"sbi.co.in", "onlinesbi.sbi", "onlinesbi.com", "sbi.bank.in"},
    "hdfc": {"hdfcbank.com", "hdfcbank.net", "hdfc.com"},
    "icici": {"icicibank.com"},
    "axis": {"axisbank.com"},
    "kotak": {"kotak.com"},
    "paytm": {"paytm.com"},
    "phonepe": {"phonepe.com"},
    "gpay": {"google.com", "pay.google.com"},
    "amazon": {"amazon.in", "amazon.com"},
    "flipkart": {"flipkart.com"},
    "irctc": {"irctc.co.in"},
    "incometax": {"incometax.gov.in"},
    "epfo": {"epfindia.gov.in"},
    "indiapost": {"indiapost.gov.in"},
    "whatsapp": {"whatsapp.com", "wa.me"},
    "netflix": {"netflix.com"},
}

SECOND_LEVEL = {"co", "gov", "org", "ac", "net", "nic", "com"}


def extract_urls(text: str) -> list[str]:
    seen, out = set(), []
    for m in URL_RE.finditer(text or ""):
        u = m.group(0).rstrip(".,;:!?")
        if u.lower() not in seen:
            seen.add(u.lower())
            out.append(u)
    return out


def registered_domain(host: str) -> str:
    parts = host.lower().strip(".").split(".")
    if len(parts) >= 3 and parts[-2] in SECOND_LEVEL and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def analyze_url(url: str) -> list[Signal]:
    signals: list[Signal] = []
    full = url if re.match(r"(?i)https?://", url) else "http://" + url
    parsed = urlparse(full)
    host = (parsed.hostname or "").lower()
    if not host:
        return signals
    reg = registered_domain(host)
    tld = host.rsplit(".", 1)[-1]

    def add(id_, title, detail, w, critical=False):
        signals.append(Signal(id_, title, detail, w, critical, "link", url[:90]))

    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
        add("url_ip", "Link uses a raw IP address", "Real companies use domain names, not IP addresses.", 0.5)
    if reg in SHORTENERS:
        add("url_short", "Shortened link hides the real destination",
            "You can't see where it leads. Expand it with a link-preview tool first.", 0.3)
    if "xn--" in host:
        add("url_puny", "Look-alike (punycode) domain", "Uses special characters to imitate a real site.", 0.5)
    if "@" in parsed.netloc:
        add("url_at", "Link contains '@' trick", "Everything before '@' is ignored; the real site is after it.", 0.5)
    if tld in RISKY_TLDS:
        add("url_tld", f"Risky domain ending (.{tld})", "Cheap TLDs are heavily used by scam sites.", 0.3)
    if host.count("-") >= 3 or host.count(".") >= 4:
        add("url_struct", "Unusually complex domain", "Many hyphens/subdomains is a common phishing pattern.", 0.25)
    if parsed.scheme == "http":
        add("url_http", "Link is not HTTPS", "Legitimate login/payment pages use HTTPS.", 0.12)

    tokens = set(re.split(r"[.\-_]", host))
    for brand, official in BRANDS.items():
        hit = brand in tokens or (len(brand) >= 5 and brand in host)
        if hit and reg not in official:
            add("url_brand", f"Pretends to be '{brand}' but isn't",
                f"Domain is {reg}, not an official {brand} domain.", 0.65, critical=True)
            break
    return signals


def analyze_urls(text: str) -> list[Signal]:
    out, seen = [], set()
    for u in extract_urls(text):
        for sig in analyze_url(u):
            if sig.id not in seen:
                seen.add(sig.id)
                out.append(sig)
    return out


def safe_browsing_flagged(urls: list[str]) -> list[str]:
    """Optional live reputation check. Returns URLs Google flags as malicious."""
    if not urls or not config.SAFE_BROWSING_KEY:
        return []
    body = {
        "client": {"clientId": "scamguard", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": u} for u in urls[:20]],
        },
    }
    try:
        r = requests.post(
            "https://safebrowsing.googleapis.com/v4/threatMatches:find",
            params={"key": config.SAFE_BROWSING_KEY}, json=body, timeout=6)
        r.raise_for_status()
        return [m["threat"]["url"] for m in r.json().get("matches", [])]
    except Exception:
        return []