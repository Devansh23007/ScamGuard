import streamlit as st

import agent
import config
import llm_analyzer

st.set_page_config(page_title="ScamGuard", page_icon="🛡️", layout="centered")
st.title("🛡️ ScamGuard")
st.caption("Paste a suspicious SMS, email, UPI request, or job offer. Or upload a screenshot.")

SAMPLES = {
    "— pick a sample —": "",
    "UPI refund trick": "Your refund of Rs 4,999 is pending. Enter your UPI PIN to receive the amount now.",
    "Fake bank KYC": "Dear customer, your SBI account will be blocked today. Update KYC: http://sbi-kyc-update.xyz/login",
    "Fake job offer": "Work from home! Earn Rs 5000 per day, no experience needed. Pay Rs 999 registration fee. WhatsApp us now.",
    "Digital arrest": "This is CBI. A parcel in your name contains illegal drugs. You are under digital arrest. Stay on the video call.",
    "Legit OTP": "123456 is your OTP for login. Do not share OTP with anyone. -HDFC Bank",
}

with st.sidebar:
    st.subheader("Settings")
    use_llm = st.toggle("Use AI analysis (Groq)", value=llm_analyzer.llm_available(),
                        disabled=not llm_analyzer.llm_available())
    if not llm_analyzer.llm_available():
        st.info("Add GROQ_API_KEY to .env to enable AI analysis and screenshot reading. "
                "Rule-based checks still work.")
    st.markdown("**Privacy:** never paste real OTPs, PINs, or passwords.")

sample = st.selectbox("Try an example", list(SAMPLES))
text = st.text_area("Message", value=SAMPLES[sample], height=160,
                    placeholder="Paste the suspicious message here...")
upload = st.file_uploader("Or upload a screenshot", type=["png", "jpg", "jpeg", "webp"])

if st.button("Check for scam", type="primary", use_container_width=True):
    images = []
    if upload:
        mt = {"jpg": "image/jpeg", "jpeg": "image/jpeg", "png": "image/png",
              "webp": "image/webp"}[upload.name.rsplit(".", 1)[-1].lower()]
        images = [(upload.getvalue(), mt)]
    if not text.strip() and not images:
        st.warning("Paste a message or upload a screenshot first.")
        st.stop()

    with st.spinner("Analyzing..."):
        r = agent.analyze(text, images, use_llm=use_llm)

    box = {"scam": st.error, "likely_scam": st.error, "suspicious": st.warning, "low_risk": st.success}[r.verdict]
    box(f"**{r.verdict_label}**  ·  {r.scam_type}")
    c1, c2, c3 = st.columns(3)
    c1.metric("Risk score", f"{r.score}/100")
    c2.metric("Rule-based", f"{r.heuristic_score}/100")
    c3.metric("AI", f"{r.llm_score}/100" if r.llm_score is not None else "off")
    st.progress(r.score / 100)
    st.write(r.summary)

    if r.llm_error:
        st.caption(f"⚠️ AI analysis unavailable: {r.llm_error}")
    if r.extracted_text:
        with st.expander("Text read from screenshot"):
            st.text(r.extracted_text)

    if r.signals:
        st.subheader("Red flags")
        for s in r.signals:
            st.markdown(f"{'🔴' if s.critical else '🟠'} **{s.title}**  \n{s.detail}")
            if s.evidence:
                st.caption(f"Matched: “{s.evidence}”")
    if r.safe_signs:
        st.subheader("Signs it may be genuine")
        for x in r.safe_signs:
            st.markdown(f"- {x}")

    st.subheader("What to do")
    for a in r.actions:
        st.markdown(f"- {a}")

    if r.verdict in ("scam", "likely_scam"):
        with st.expander("Where to report (India)", expanded=True):
            for name, how in config.REPORT_RESOURCES:
                st.markdown(f"**{name}:** {how}")
