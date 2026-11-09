# Connect ScamGuard to your Gmail (one-time setup, ~10 minutes)

## 1. Create a Google Cloud project and enable Gmail
1. Go to https://console.cloud.google.com and create a project (e.g. "ScamGuard").
2. **APIs & Services → Library → Gmail API → Enable.**

## 2. OAuth consent screen
1. **APIs & Services → OAuth consent screen** (or "Google Auth Platform").
2. User type: **External**. Fill in app name and your email.
3. **Audience / Test users → add your own Gmail address.**
4. Scopes: add `gmail.modify` (or `gmail.readonly` if you only want read-only mode).

## 3. Create credentials
1. **Credentials → Create credentials → OAuth client ID → Application type: Desktop app.**
2. **Download JSON**, rename it to `credentials.json`, and put it in the project folder.

## 4. Run
```bash
pip install -r requirements.txt
cp .env.example .env              # set GROQ_API_KEY
python scanner.py                 # first run opens your browser: click Allow
python scanner.py --watch         # keep scanning every 5 minutes
streamlit run dashboard.py        # visual dashboard
```
Google shows "Google hasn't verified this app". That is normal for your own personal app.
Click **Advanced → Go to ScamGuard (unsafe)**. You are the developer, so this is safe.

## Good to know
- **7-day token expiry:** while the app is in "Testing" mode Google expires the login every 7 days.
  ScamGuard detects this and reopens the browser consent. To avoid it, set the consent screen
  to **"In production"** (still no verification needed for personal use with your own account).
- **Safe by design:** `gmail.modify` can read and add labels but **cannot delete mail**. ScamGuard only
  adds labels. Set `SCAMGUARD_READONLY=1` to disable even that.
- **Privacy:** only emails that the free rule check finds slightly odd are sent to Groq (as text),
  never every email. The database stores sender, subject, score and reasons, **not the email body**.
- **Trusted senders:** put domains in `SCAN_ALLOWLIST` to skip them entirely.
- **Revoke access anytime:** https://myaccount.google.com/permissions
- Never commit `credentials.json`, `token.json` or `.env` (already in `.gitignore`).
