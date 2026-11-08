import asyncio
import pytest
from app.services.gemini_analyzer import analyze_phishing_message
from app.schemas.common import RiskLevel


def test_phishing_urgent_scam_detection():
    scam_text = (
        "URGENT: Your PayPal account has been suspended within 24 hours due to unauthorized activity. "
        "Click here immediately to verify your password and prevent closure: http://paypa1-security-verify.com/login"
    )
    result = asyncio.run(analyze_phishing_message(scam_text, message_type="email"))
    assert result.risk_level in (RiskLevel.HIGH, RiskLevel.CONFIRMED_MALICIOUS)
    assert result.risk_score >= 80
    assert result.confidence_score >= 70
    assert len(result.manipulation_techniques) > 0
    assert len(result.extracted_urls) > 0


def test_benign_message_decoupled_risk_and_confidence():
    benign_text = "Hey John, checking in about our team meeting tomorrow morning at 10 AM. See you in the conference room!"
    result = asyncio.run(analyze_phishing_message(benign_text, message_type="chat"))
    # Benign message should have LOW risk score (< 25) even when confidence is high!
    assert result.risk_level == RiskLevel.LOW
    assert result.risk_score < 25
    assert result.confidence_score >= 80  # High confidence that it is benign
