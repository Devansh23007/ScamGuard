"""Rule-based scam signals tuned for Indian SMS / WhatsApp / UPI / job scams."""
from __future__ import annotations
import math
import re
from dataclasses import dataclass

from models import Signal


@dataclass
class Rule:
    id: str
    title: str
    pattern: str
    weight: float
    category: str
    detail: str
    critical: bool = False


RULES: list[Rule] = [
    Rule("urgency", "Pressure / urgency",
         r"\b(urgent(ly)?|immediately|right now|act now|last chance|expires? (today|soon|in)|"
         r"within \d+\s*(hours?|hrs?|minutes?|mins?)|final (notice|warning)|today only|hurry)\b",
         0.22, "pressure", "Scammers rush you so you don't stop to verify."),
    Rule("threat", "Threat of block / suspension",
         r"\b(account|sim|card|upi|number|wallet)\b[^.\n]{0,50}\b(blocked|suspended|deactivated|"
         r"disconnected|frozen|terminated|closed)\b|legal action|arrest warrant|\bcase (has been|will be) (filed|registered)",
         0.35, "pressure", "Fear is used to push you into acting without thinking."),
    Rule("kyc", "Fake KYC / verification demand",
         r"\bkyc\b[^.\n]{0,60}\b(expir\w*|pending|update|incomplete|suspend\w*|verif\w*)|"
         r"\b(update|complete|verify)\b[^.\n]{0,20}\bkyc\b",
         0.35, "impersonation", "Banks don't ask you to complete KYC through random links or SMS."),
    Rule("digital_arrest", "'Digital arrest' / fake authority",
         r"digital arrest|\b(cbi|narcotics|ncb|customs|enforcement directorate)\b[^.\n]{0,80}"
         r"\b(parcel|package|case|arrest|illegal|drugs?|money laundering)\b|"
         r"parcel[^.\n]{0,60}(seized|contains|illegal|drugs)",
         0.8, "authority", "No agency arrests people over a call or video call. This is a known scam.", True),
    Rule("secrecy", "Told to keep it secret",
         r"(don'?t|do not|never) (tell|inform|share this with|discuss)[^.\n]{0,30}(anyone|family|bank|police)|"
         r"keep (this )?(confidential|secret)|stay on (the )?(video )?call",
         0.35, "pressure", "Isolation is a classic manipulation tactic."),
    Rule("prize", "Prize / lottery claim",
         r"\b(you (have )?won|lottery|lucky (draw|winner)|congratulations[^.\n]{0,40}(won|selected|winner)|"
         r"kbc|prize money|claim your (prize|reward|gift))\b",
         0.4, "prize", "You can't win a contest you never entered."),
    Rule("refund_bait", "Refund / cashback bait",
         r"\b(refund|cashback|reward points?|redeem)\b", 0.1, "upi", "Common bait to get you to click or approve something."),
    Rule("upi_pin_receive", "Asks for UPI PIN to receive money",
         r"(enter|put|type|share|provide)\W+(?:\w+\W+){0,3}(upi\s*)?pin\b[^.\n]{0,40}\b(receive|get|credit|refund|cashback|claim|accept)|"
         r"\b(receive|get|credit|refund|cashback|claim|accept)\b[^.\n]{0,40}\b(enter|put|type|share|provide)\W+(?:\w+\W+){0,3}(upi\s*)?pin\b",
         0.8, "upi", "You NEVER need a PIN to receive money. A PIN only sends money out.", True),
    Rule("collect_request", "Asks you to approve a payment request",
         r"(collect|payment|money) request[^.\n]{0,60}\b(approve|accept|pay|enter)|"
         r"\b(approve|accept)\b[^.\n]{0,30}(collect|payment|money) request",
         0.5, "upi", "Approving a 'collect request' takes money out of your account."),
    Rule("qr_receive", "Scan QR to 'receive' money",
         r"scan[^.\n]{0,30}\bqr\b[^.\n]{0,60}\b(receive|get|refund|cashback|credit|claim)|"
         r"\bqr\b[^.\n]{0,40}\b(receive|get)\b[^.\n]{0,20}money",
         0.6, "upi", "Scanning a QR code is for paying, never for receiving money.", True),
    Rule("wrong_transfer", "'Sent money by mistake' story",
         r"(sent|transferred|credited|paid)[^.\n]{0,30}(by mistake|wrongly|wrong (number|account))|"
         r"(return|refund|send back)[^.\n]{0,25}(my |the )?(money|amount|payment)",
         0.4, "upi", "A common trick that ends with you sending real money back."),
    Rule("remote_access", "Asks to install remote-access app",
         r"\b(anydesk|teamviewer|quick ?support|rustdesk|airdroid)\b",
         0.75, "remote", "These apps let a stranger see and control your phone and bank apps.", True),
    Rule("apk", "Asks you to install an APK file",
         r"\b[\w-]+\.apk\b|install[^.\n]{0,30}\bapk\b|download[^.\n]{0,30}\bapk\b",
         0.7, "remote", "APKs outside the Play Store are a top way malware steals bank OTPs.", True),
    Rule("fees", "Asks for an upfront fee",
         r"(registration|processing|training|joining|security|refundable|kit|verification|clearance)\s+"
         r"(fee|fees|charges?|deposit|amount)\b",
         0.4, "job", "Real employers never charge you to get hired."),
    Rule("pay_to_join", "Pay money to get the job",
         r"(pay|deposit|transfer|send)[^.\n]{0,40}(to (get|receive|join|start|secure)|before)[^.\n]{0,30}"
         r"(job|offer|joining|salary|training|laptop|kit)",
         0.55, "job", "Paying to get a job is the hallmark of a fake job offer.", True),
    Rule("wfh", "Generic work-from-home pitch",
         r"\b(work from home|wfh|part[- ]?time job|online (job|work|earning)|home[- ]based|data entry job|typing job)\b",
         0.15, "job", "Frequently used as the hook in fake job offers."),
    Rule("salary_promise", "Unrealistic earning promise",
         r"\b(earn|income|salary|make|get paid)\b[^.\n]{0,40}(₹|rs\.?|inr|\$)\s?[\d,]{3,}[^.\n]{0,20}(per|a|/|each)\s*"
         r"(day|daily|hour|hr|task|week)|(₹|rs\.?|inr)\s?[\d,]{4,}\s*(/|per|a)\s*(day|daily|hour|hr)",
         0.35, "job", "High pay for little work is too good to be true."),
    Rule("no_experience", "'No experience / guaranteed' claims",
         r"no (prior )?(experience|interview|skills?|qualification|investment)( needed| required)?|"
         r"anyone can (apply|earn|do)|guaranteed (job|income|returns?|profit)|\b100% (guaranteed|genuine|safe|legit)\b",
         0.25, "job", "Real offers rarely guarantee results or skip screening."),
    Rule("task_scam", "Like/rate/review-to-earn task scam",
         r"\b(like|subscribe|follow|rate|review|watch)\b[^.\n]{0,40}\b(youtube|instagram|videos?|products?|hotels?|maps|google reviews?|posts?)\b"
         r"[^.\n]{0,80}(earn|pay|₹|rs\.?|commission|reward)",
         0.45, "job", "Task scams pay small amounts first, then ask you to 'invest' and vanish."),
    Rule("invest", "Guaranteed-returns investment pitch",
         r"guaranteed (returns?|profit)|double your (money|investment)|\d{2,3}\s?% (daily|weekly|monthly|returns?|profit)|"
         r"insider tips?|vip (group|signals?)|\busdt\b",
         0.35, "investment", "No legitimate investment guarantees returns."),
    Rule("off_channel", "Pushes you to WhatsApp/Telegram",
         r"\b(contact|message|msg|text|chat|ping|dm|reach)\b[^.\n]{0,30}\b(whatsapp|telegram|signal)\b|\bt\.me/|\bwa\.me/",
         0.2, "channel", "Moving you to a private chat avoids platform safeguards."),
    Rule("authority", "Claims to be a government body / bank",
         r"\b(rbi|reserve bank|income tax (dept|department)|trai|epfo|uidai|cyber ?crime|police|court|ministry|government of india)\b",
         0.12, "authority", "Impersonating authorities builds fake trust."),
    Rule("generic_greeting", "Generic greeting",
         r"dear (customer|user|sir|madam|valued|account holder|winner)", 0.1, "general",
         "Real banks usually address you by name."),
]

CRED_RE = re.compile(
    r"(share|send|enter|provide|tell|give|submit|confirm|verify|update|reply with)\W+(?:\w+\W+){0,4}"
    r"(otp|pin|cvv|password|passcode|aadhaar|aadhar|pan|card number|net ?banking)\b",
    re.I)
NEGATION_RE = re.compile(r"(do not|don'?t|dont|never|not to|avoid)\W+(?:\w+\W+){0,2}$", re.I)


def _credential_signal(text: str) -> Signal | None:
    for m in CRED_RE.finditer(text):
        before = text[max(0, m.start() - 25):m.start()]
        if NEGATION_RE.search(before):   # e.g. "Do not share OTP" is a warning, not a request
            continue
        return Signal("credential", "Asks for OTP / PIN / password / ID",
                      "Genuine banks and agencies never ask for these.", 0.5, True,
                      "credential", m.group(0)[:80])
    return None


def analyze_text(text: str) -> list[Signal]:
    signals: list[Signal] = []
    if not text or not text.strip():
        return signals
    for r in RULES:
        m = re.search(r.pattern, text, re.I | re.S)
        if m:
            signals.append(Signal(r.id, r.title, r.detail, r.weight, r.critical, r.category, m.group(0)[:80]))
    cred = _credential_signal(text)
    if cred:
        signals.append(cred)
    return signals


def combine_score(signals: list[Signal]) -> int:
    """Noisy-OR: each signal independently raises risk; criticals set a floor of 70."""
    if not signals:
        return 0
    p = 1.0
    for s in signals:
        p *= (1 - s.weight)
    score = round(100 * (1 - p))
    if any(s.critical for s in signals):
        score = max(score, 70)
    return min(score, 99)


CATEGORY_TO_TYPE = {
    "upi": "UPI / payment fraud",
    "job": "Fake job offer",
    "prize": "Lottery / prize scam",
    "investment": "Investment scam",
    "authority": "Fake authority / digital arrest",
    "impersonation": "Bank / brand impersonation",
    "credential": "Phishing (credential theft)",
    "remote": "Malware / remote-access fraud",
    "link": "Phishing link",
    "pressure": "Pressure tactics",
    "email": "Suspicious sender",
}
GENERIC = {"pressure", "channel", "general", "email"}


def guess_scam_type(signals: list[Signal]) -> str:
    """Pick the category with the most combined risk; generic ones only if nothing else matched."""
    if not signals:
        return "None detected"
    totals: dict[str, float] = {}
    for s in signals:
        totals[s.category] = totals.get(s.category, 0) + s.weight
    specific = {c: w for c, w in totals.items() if c not in GENERIC}
    pool = specific or totals
    top = max(pool, key=pool.get)
    return CATEGORY_TO_TYPE.get(top, "Suspicious message")
