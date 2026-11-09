import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import agent

def run(text):
    return agent.analyze(text, use_llm=False)

def test_upi_pin_receive_is_scam():
    r = run("Congrats! Your refund of Rs 4,999 is ready. Enter your UPI PIN to receive the amount.")
    assert r.score >= 75

def test_fake_kyc_with_brand_link():
    r = run("Dear customer, your SBI account will be blocked today. Update KYC now: http://sbi-kyc-update.xyz/login")
    assert r.verdict in ("scam", "likely_scam") and r.score >= 75

def test_fake_job_offer():
    r = run("Work from home! Earn Rs 5000 per day, no experience needed. Pay Rs 999 registration fee. Contact on WhatsApp.")
    assert r.score >= 60
    assert any(s.category == "job" for s in r.signals)

def test_digital_arrest():
    r = run("This is CBI. A parcel in your name contains illegal drugs. You are under digital arrest. Stay on the video call.")
    assert r.score >= 75

def test_legit_otp_warning_not_flagged():
    r = run("123456 is your OTP for login. Do not share OTP with anyone. -HDFC Bank")
    assert r.score < 25
    assert not any(s.id == "credential" for s in r.signals)

def test_normal_message_low_risk():
    r = run("Hey, are we still meeting at 6pm for dinner? I'll book a table.")
    assert r.score == 0

def test_official_domain_not_flagged_as_brand_spoof():
    r = run("Your statement is ready. View at https://www.hdfcbank.com/personal")
    assert not any(s.id == "url_brand" for s in r.signals)

def test_shortener_and_ip():
    r = run("Claim now http://192.168.4.5/win and https://bit.ly/abc123")
    ids = {s.id for s in r.signals}
    assert "url_ip" in ids and "url_short" in ids
