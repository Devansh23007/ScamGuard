# ScamGuard Chrome Extension: setup (3 minutes)

The extension shows a badge next to each scam email in your Gmail list, and a banner with the reasons
inside any email you open. It needs no Google Cloud setup and no Gmail login.

## 1. Start the local server (keep this window open)
```bash
pip install -r requirements.txt
cp .env.example .env        # optional: add GROQ_API_KEY for AI second opinions
python server.py
```
It listens on `127.0.0.1:8765` only, so nothing outside your computer can reach it.

## 2. Install the extension
1. Open `chrome://extensions`
2. Turn on **Developer mode** (top right)
3. Click **Load unpacked** and choose the `extension` folder
4. Click the puzzle icon and pin **ScamGuard**. The popup should say **Connected**.

## 3. Open Gmail
Reload https://mail.google.com. Flagged emails get a badge like:

- `🚨 Scam · Fake job offer`
- `🚨 Scam · Bank / brand impersonation`
- `⚠️ Suspicious · Phishing link`

Hover a badge to see the risk score and reasons. Open an email to see the full banner.

## How it works
| Where | What is checked | AI used? |
|---|---|---|
| Inbox list (badges) | Sender, subject, preview text, using the rule engine | No. Free, instant, offline |
| Opened email (banner) | Full text, real link destinations vs shown text, attachments | Yes, only if the rules found something odd and `GROQ_API_KEY` is set |

## Tips and limits
- **Server stopped?** Badges stop appearing. The popup shows a red message. Restart `python server.py`.
- **Badges look wrong or missing after a Gmail update:** Gmail's page structure is not an official API and
  changes occasionally. The selectors are at the top of `content.js` (`tr.zA`, `.bog`, `.y2`, `.a3s`).
- **Inbox badges only see the preview**, not the whole email, so some scams only show up when you open them.
  The banner is the more accurate check.
- **Wrongly flagged a real sender?** Tell me the domain and I'll add it to the safe list, or extend `BRANDS`
  in `url_checker.py`.
- **Lock it to your copy of the extension (optional):** copy the ID from `chrome://extensions` and set
  `EXTENSION_ID=...` in `.env`.
- **Privacy:** with no `GROQ_API_KEY`, nothing leaves your computer. With it, only the text of a suspicious
  email you *open* is sent to Groq.
- The extension can be used alongside the Gmail scanner (`scanner.py`). They are independent.
