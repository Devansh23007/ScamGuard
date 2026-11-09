# 🛡️ ScamGuard: AI-Powered Scam & Phishing Detector

**ScamGuard** is an open-source security agent designed to detect, analyze, and explain digital scams—specialized for Indian threat patterns (UPI fraud, fake KYC, digital arrest threats, job task scams) as well as global phishing, brand spoofing, and malicious emails.

It combines an instant **rule engine**, an advanced **link reputation & brand checker**, and **Groq LLMs** (GPT-OSS 120B for reasoning and Qwen 27B for screenshot analysis) into a single unified risk score with plain-language explanations.

---

## 🚀 Key Features

- **Multi-Vector Detection:**
  - **UPI & Payment Tricks:** Detects "enter PIN to receive money", collect requests, fake refund QR codes.
  - **Impersonation & Extortion:** Catches fake KYC suspensions, "digital arrest" CBI/police threats, and lottery scams.
  - **Job & Task Scams:** Flags upfront registration fees, "earn ₹5000/day", and fake Telegram/WhatsApp tasks.
  - **Credentials & Malware:** Catches asks for OTP/PIN/CVV, APK attachments, and remote desktop tools (AnyDesk, TeamViewer).
- **Domain & Link Inspection:** Spoofed brand detection (SBI, HDFC, ICICI, Amazon, etc.), punycode/look-alikes, IP hosts, URL shorteners, risky TLDs, and Google Safe Browsing integration.
- **Gmail Chrome Extension:** Displays warning badges (`🚨 Scam`, `⚠️ Suspicious`) next to flagged email subjects in Gmail and an advisory banner inside opened emails—without modifying your mailbox.
- **Screenshot Analysis:** Upload screenshots of chats, SMS, or payment pages; the vision model extracts text and verifies visual cues.
- **Explainable Results:** Every verdict includes a 0–100 risk score, matched evidence, genuine signs, and immediate action steps (including India's 1930 helpline & cybercrime.gov.in reporting).

---

## 🧠 How It Works

```
 Message / Screenshot / Email
              │
              ├─► Rule Engine (heuristics.py)     ──┐
              ├─► Link Checker (url_checker.py)    ─┼─► agent.py (Fusion) ─► Score (0-100) + Verdict + Actions
              ├─► Email Signals (email_signals.py) ─┤   (40% Rules + 60% AI)
              └─► Groq LLM (llm_analyzer.py)       ─┘
```

1. **Rule Engine (`heuristics.py`):** Runs offline regex patterns using a *noisy-OR* probabilistic model. Correctly distinguishes genuine warnings (e.g., *"Do not share OTP"*) from phishing demands.
2. **Link Checker (`url_checker.py`):** Compares domains against known official brand dictionaries. Legit newsletters with tracking redirects are verified against sender authentication (SPF/DKIM/DMARC) to avoid false positives.
3. **Groq LLM (`llm_analyzer.py`):** Uses `openai/gpt-oss-120b` for deep contextual reasoning and `qwen/qwen3.6-27b` for screenshots. Untrusted message input is isolated to prevent prompt injection.
4. **Score Fusion (`agent.py`):** Fuses rules (40%) and AI (60%). Any critical threat (e.g., UPI PIN to receive money) triggers an automatic floor score of 75+.

---

## 📁 Repository Structure

```
scamguard/
├── agent.py               # Fuses heuristics, URL checks, and LLM verdicts
├── app.py                 # Streamlit web UI (text inspection & screenshot upload)
├── cli.py                 # Command-line interface
├── config.py              # Configuration & environment settings
├── dashboard.py           # Streamlit dashboard for scanned emails
├── email_parser.py        # RFC / Gmail message parser & auth extractor
├── email_signals.py       # Email-specific spoofing & attachment rules
├── gmail_client.py        # Optional Gmail API integration
├── heuristics.py          # Rule engine & scam pattern definitions
├── llm_analyzer.py        # Groq API integration (GPT-OSS 120B & Qwen Vision)
├── models.py              # Signal and Report data models
├── scanner.py             # Optional background Gmail inbox watcher
├── server.py              # Local API server for the Chrome extension
├── storage.py             # SQLite scan history storage
├── url_checker.py         # Link analysis & brand spoofing detection
├── extension/             # Chrome Extension (Manifest V3)
│   ├── manifest.json
│   ├── background.js
│   ├── content.js
│   ├── content.css
│   ├── popup.html
│   └── popup.js
└── tests/                 # Comprehensive test suite (19 passing tests)
    ├── test_heuristics.py
    ├── test_gmail.py
    └── test_server.py
```

---

## ⚡ Quickstart

### 1. Installation
Clone the repository and install requirements:
```bash
git clone https://github.com/yourusername/scamguard.git
cd scamguard

python -m venv venv
# Windows:
.\venv\Scripts\Activate.ps1
# Linux/macOS:
source venv/bin/activate

pip install -r requirements.txt
```

### 2. Configure Environment
Copy the example environment file and add your [Groq API Key](https://console.groq.com/keys):
```bash
cp .env.example .env
```
*(The rule engine and link checker work 100% offline even without an API key).*

### 3. Run Automated Tests
Verify everything is working:
```bash
pytest
```
*All 19 tests should pass.*

---

## 🖥️ Usage Modes

### Mode 1: Chrome Extension for Gmail (Recommended)
Protect your Gmail inbox in real-time without giving third-party cloud access:
1. Start the local server:
   ```bash
   python server.py
   ```
2. In Google Chrome, navigate to `chrome://extensions/`.
3. Enable **Developer mode** (top right) and click **Load unpacked**.
4. Select the `extension/` directory from this repository.
5. Open or refresh [Gmail](https://mail.google.com). Flagged scam emails will show badges beside the subject line, and opened emails will feature an analysis banner.

### Mode 2: Interactive Web UI
Launch the Streamlit web application:
```bash
streamlit run app.py
```
Paste suspicious text, test sample scams, or upload a screenshot.

### Mode 3: Command Line (CLI)
Analyze messages directly from the terminal:
```bash
python cli.py "URGENT: Your SBI account is suspended. Update KYC at http://sbi-kyc-verify.top"

# Rules-only mode (offline, no API needed):
python cli.py --no-llm "Pay Rs 999 registration fee for part-time job"

# JSON output (for scripts and pipelines):
python cli.py --json "Your OTP is 492018"
```

### Mode 4: Background Gmail Scanner
Optionally scan your inbox periodically via the Gmail API:
```bash
python scanner.py --watch
# View results dashboard:
streamlit run dashboard.py
```
*(Refer to `SETUP_GMAIL.md` for one-time Google Cloud desktop credentials setup).*

---

## 🇮🇳 Reporting Resources in India

When ScamGuard detects high-risk fraud, it prompts immediate reporting steps:
- **National Cyber Crime Helpline:** Call **1930** immediately to freeze stolen funds.
- **National Portal:** File an online report at [cybercrime.gov.in](https://cybercrime.gov.in).
- **Chakshu (Sanchar Saathi):** Report fraudulent calls, SMS, and WhatsApp senders at [sancharsaathi.gov.in](https://sancharsaathi.gov.in).
- **Bank Emergency:** Immediately call the official number on your debit/credit card to block compromised accounts and UPI access.

---

## 🔒 Security & Privacy

- **Untrusted Content Isolation:** Text inputs and extracted screenshot text are wrapped and treated as untrusted data to protect against prompt injection.
- **Local-First Processing:** The Chrome extension communicates strictly with `127.0.0.1:8765`. Nothing leaves your machine unless you configure Groq for LLM second opinions.
- **Data Minimization:** Scan history only stores sender, subject, score, and threat categories—email bodies are never persisted.
- **Sensitive files:** API keys, OAuth tokens (`token.json`), and database files (`*.db`) are strictly excluded via `.gitignore`.

---

## 📄 License

MIT License. Contributions and PRs welcome!
