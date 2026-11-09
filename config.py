import os

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:  # dotenv is optional
    pass

GROQ_API_KEY = os.getenv("GROQ_API_KEY")
MODEL = os.getenv("GROQ_MODEL", "openai/gpt-oss-120b")
REASONING_EFFORT = os.getenv("GROQ_REASONING_EFFORT", "low")   # low | medium | high (gpt-oss models only)
VISION_MODEL = os.getenv("GROQ_VISION_MODEL", "qwen/qwen3.6-27b")
SAFE_BROWSING_KEY = os.getenv("GOOGLE_SAFE_BROWSING_KEY")

# India-focused reporting resources
REPORT_RESOURCES = [
    ("National Cyber Crime Helpline", "Call 1930 immediately if money was lost"),
    ("cybercrime.gov.in", "File an online complaint"),
    ("Chakshu (Sanchar Saathi)", "Report suspicious calls/SMS/WhatsApp at sancharsaathi.gov.in"),
    ("Your bank", "Call the number on the back of your card to block cards/UPI"),
]

# ---- Gmail auto-scan ----
APPLY_LABELS = os.getenv("SCAN_APPLY_LABELS", "0") == "1"      # 0 = no Gmail labels; results show in the extension/dashboard
GMAIL_READONLY = os.getenv("SCAMGUARD_READONLY", "0") == "1"      # 1 = never modify Gmail (no labels)
SCAN_QUERY = os.getenv("SCAN_QUERY", "in:inbox newer_than:7d")
SCAN_INTERVAL_MIN = int(os.getenv("SCAN_INTERVAL_MIN", "5"))
DB_PATH = os.getenv("SCAMGUARD_DB", "scamguard.db")
# comma-separated sender domains you trust completely (skipped, never sent to the AI)
SCAN_ALLOWLIST = {d.strip().lower() for d in os.getenv("SCAN_ALLOWLIST", "").split(",") if d.strip()}