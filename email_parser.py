"""Turn a raw Gmail API message into a clean EmailData object."""
from __future__ import annotations
import base64
import re
from dataclasses import dataclass, field
from email.utils import parseaddr
from html.parser import HTMLParser


class _HTMLExtractor(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.text: list[str] = []
        self.links: list[tuple[str, str]] = []   # (visible text, href)
        self._skip = 0
        self._href: str | None = None
        self._atext: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style"):
            self._skip += 1
        elif tag == "a":
            self._href, self._atext = dict(attrs).get("href"), []
        elif tag in ("br", "p", "div", "tr", "li"):
            self.text.append("\n")

    def handle_endtag(self, tag):
        if tag in ("script", "style") and self._skip:
            self._skip -= 1
        elif tag == "a" and self._href is not None:
            if self._href.lower().startswith(("http://", "https://")):
                self.links.append(("".join(self._atext).strip(), self._href))
            self._href = None

    def handle_data(self, data):
        if self._skip:
            return
        self.text.append(data)
        if self._href is not None:
            self._atext.append(data)


@dataclass
class EmailData:
    id: str
    thread_id: str = ""
    sender_name: str = ""
    sender_email: str = ""
    reply_to: str = ""
    subject: str = ""
    date: str = ""
    body: str = ""
    links: list[tuple[str, str]] = field(default_factory=list)
    attachments: list[str] = field(default_factory=list)
    auth: dict = field(default_factory=dict)     # {'spf': 'pass', 'dkim': 'pass', 'dmarc': 'fail'}
    list_unsub: bool = False                     # has a List-Unsubscribe header (bulk/newsletter mail)

    @property
    def sender_domain(self) -> str:
        return self.sender_email.rsplit("@", 1)[-1].lower() if "@" in self.sender_email else ""

    def analysis_text(self, max_chars: int = 6000) -> str:
        """Compact text sent to the rules + AI (hrefs included so hidden links are visible)."""
        auth = ", ".join(f"{k.upper()}={v}" for k, v in self.auth.items()) or "unknown"
        parts = [
            f"From: {self.sender_name} <{self.sender_email}>",
            f"Reply-To: {self.reply_to}" if self.reply_to else "",
            f"Subject: {self.subject}",
            f"Email authentication: {auth}",
            f"Attachments: {', '.join(self.attachments)}" if self.attachments else "",
            "", self.body.strip()[:max_chars - 800],
        ]
        if self.links:
            parts += ["", "Links in email:"] + [f"- {t[:60]} -> {h[:200]}" for t, h in self.links[:15]]
        return "\n".join(p for p in parts if p is not None)[:max_chars]


def _b64(data: str) -> str:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4)).decode("utf-8", "replace")


def _walk(part: dict, plain: list, html: list, atts: list):
    mime, fname, body = part.get("mimeType", ""), part.get("filename", ""), part.get("body", {})
    if fname:
        atts.append(fname)
    elif mime == "text/plain" and body.get("data"):
        plain.append(_b64(body["data"]))
    elif mime == "text/html" and body.get("data"):
        html.append(_b64(body["data"]))
    for sub in part.get("parts", []) or []:
        _walk(sub, plain, html, atts)


def parse_auth(value: str) -> dict:
    out = {}
    for key in ("spf", "dkim", "dmarc"):
        m = re.search(rf"\b{key}=(\w+)", value or "", re.I)
        if m:
            out[key] = m.group(1).lower()
    return out


def parse_message(raw: dict) -> EmailData:
    payload = raw.get("payload", {})
    headers: dict[str, str] = {}
    for h in payload.get("headers", []):
        headers.setdefault(h["name"].lower(), h["value"])

    plain, html, atts = [], [], []
    _walk(payload, plain, html, atts)

    links: list[tuple[str, str]] = []
    body = "\n".join(plain).strip()
    if html:
        ex = _HTMLExtractor()
        ex.feed("\n".join(html))
        links = ex.links
        if not body:
            body = re.sub(r"\n\s*\n+", "\n\n", "".join(ex.text)).strip()

    name, addr = parseaddr(headers.get("from", ""))
    _, reply = parseaddr(headers.get("reply-to", ""))
    return EmailData(
        id=raw.get("id", ""), thread_id=raw.get("threadId", ""),
        sender_name=name.strip(), sender_email=addr.lower(), reply_to=reply.lower(),
        subject=headers.get("subject", ""), date=headers.get("date", ""),
        body=body, links=links, attachments=atts,
        auth=parse_auth(headers.get("authentication-results", "")),
        list_unsub="list-unsubscribe" in headers,
    )