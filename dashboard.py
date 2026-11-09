import streamlit as st

import config
import scanner
import storage

st.set_page_config(page_title="ScamGuard Inbox", page_icon="🛡️", layout="wide")
storage.init()
st.title("🛡️ ScamGuard: Inbox Protection")

with st.sidebar:
    st.subheader("Scan")
    if st.button("Scan Gmail now", type="primary", use_container_width=True):
        with st.spinner("Scanning your inbox..."):
            try:
                s = scanner.scan_once(log=lambda *_: None)
                st.success(f"Scanned {s['scanned']} · scams {s['scam']} · suspicious {s['suspicious']}")
            except Exception as e:
                st.error(f"{type(e).__name__}: {e}")
    st.caption(f"Query: `{config.SCAN_QUERY}`")
    st.caption("Read-only mode: no labels added" if config.GMAIL_READONLY
               else "Flagged mails get the **ScamGuard/Scam** or **ScamGuard/Suspicious** label in Gmail.")
    show = st.multiselect("Show", ["scam", "likely_scam", "suspicious", "low_risk"],
                          default=["scam", "likely_scam", "suspicious"])

c = storage.counts()
m = st.columns(4)
m[0].metric("Scams", c.get("scam", 0) + c.get("likely_scam", 0))
m[1].metric("Suspicious", c.get("suspicious", 0))
m[2].metric("Looks safe", c.get("low_risk", 0))
m[3].metric("Total scanned", sum(c.values()))

rows = storage.recent(300, show or None)
if not rows:
    st.info("Nothing here yet. Click **Scan Gmail now** (run `python scanner.py` once first to authorize Gmail).")
ICON = {"scam": "🚨", "likely_scam": "🚨", "suspicious": "⚠️", "low_risk": "✅"}
for r in rows:
    with st.expander(f"{ICON.get(r['verdict'], '')} {r['score']}/100 · {r['subject'][:70] or '(no subject)'} — {r['sender'][:50]}"):
        st.write(r["summary"])
        st.caption(f"{r['scam_type']} · {r['date']} · AI used: {'yes' if r['llm_used'] else 'no'}")
        for s in r["signals"]:
            st.markdown(f"{'🔴' if s['critical'] else '🟠'} **{s['title']}**  \n{s['detail']}")
            if s.get("evidence"):
                st.caption(f"Matched: “{s['evidence']}”")
        st.markdown(f"[Open in Gmail](https://mail.google.com/mail/u/0/#all/{r['id']})")
