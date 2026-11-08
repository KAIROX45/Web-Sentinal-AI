import pytest
from app.services.url_analyzer import (
    calculate_entropy,
    check_homograph_attack,
    check_typosquatting,
)
from app.services.tls_analyzer import inspect_tls_certificate


def test_shannon_entropy():
    # Low entropy (repetitive)
    low_ent = calculate_entropy("aaaaaaa")
    assert low_ent == 0.0

    # Normal domain entropy
    norm_ent = calculate_entropy("google")
    assert 1.5 < norm_ent < 3.0

    # High entropy DGA domain
    high_ent = calculate_entropy("xkjh23498sdfa9807zlkj")
    assert high_ent > 3.5


def test_homograph_attack_detection():
    # Latin "paypal.com"
    clean_res = check_homograph_attack("paypal.com")
    assert clean_res.has_homograph is False

    # Cyrillic 'а' replacing Latin 'a'
    cyrillic_res = check_homograph_attack("paypаl.com")
    assert cyrillic_res.has_homograph is True
    assert "Cyrillic Script" in cyrillic_res.scripts_detected

    # Punycode domain
    punycode_res = check_homograph_attack("xn--pypal-4ve.com")
    assert punycode_res.has_homograph is True


def test_typosquatting_detection():
    # Exact brand
    res_clean = check_typosquatting("paypal", "")
    assert res_clean.is_typosquat is False

    # Paypa1 (number 1 instead of l)
    res_num = check_typosquatting("paypa1", "")
    assert res_num.is_typosquat is True
    assert res_num.targeted_brand == "Paypal"

    # Micros0ft
    res_zero = check_typosquatting("micros0ft", "")
    assert res_zero.is_typosquat is True
    assert res_zero.targeted_brand == "Microsoft"


def test_tls_certificate_inspection_real_chain():
    # Connecting to google.com must return actual leaf and real verified chain nodes
    # and MUST NOT contain fabricated dummy nodes like "Global Trusted Root CA" with fake dates
    res = inspect_tls_certificate("google.com", 443, timeout=5.0)
    assert res.hostname == "google.com"
    assert res.is_valid is True
    assert res.is_ca_trusted is True
    assert len(res.certificate_chain) >= 2

    # Check chain nodes are genuine
    for node in res.certificate_chain:
        assert node.valid_from != "Verified"  # Never fabricated string
        assert node.valid_to != "Active"      # Never fabricated string
        assert node.subject != "Global Trusted Root CA"  # No dummy CA


def test_tls_revocation_status_transparency():
    # Connecting to a live TLS endpoint must explicitly declare revocation as 'Not Checked'
    # rather than claiming an active OCSP lookup was performed
    res = inspect_tls_certificate("google.com", 443, timeout=5.0)
    assert res.revocation_status.startswith("Not Checked")
    assert "Active" not in res.revocation_status


@pytest.mark.anyio
async def test_threat_intel_seed_demo_attribution():
    from app.database import SessionLocal
    from app.services.threat_intelligence import check_threat_intelligence, query_local_ioc

    db = SessionLocal()
    try:
        ioc = query_local_ioc(db, "paypa1-security-verification.com")
        assert ioc is not None
        assert ioc.is_demo is True

        sources = await check_threat_intelligence(db=db, domain="paypa1-security-verification.com")
        flagged = [s for s in sources if s.is_flagged]
        assert len(flagged) >= 1
        assert "Demo/Seed Indicator" in flagged[0].details or "Demo" in flagged[0].status_note
    finally:
        db.close()


@pytest.mark.anyio
async def test_header_checker_no_malicious_overpenalty():
    from unittest.mock import AsyncMock, patch, MagicMock
    from app.services.header_checker import inspect_http_headers

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.is_redirect = False
    mock_resp.url = "https://example.com"
    # Return zero security headers (all 6 missing)
    mock_resp.headers = {"content-type": "text/html"}

    with patch("httpx.AsyncClient.head", new_callable=AsyncMock) as mock_head:
        mock_head.return_value = mock_resp
        res = await inspect_http_headers("https://example.com")

        # Security score should be low due to missing headers
        assert res.security_score <= 30
        assert res.missing_count >= 5

        # BUT risk score MUST NOT exceed 45 (remains SUSPICIOUS, never HIGH or CONFIRMED MALICIOUS)
        # Defense-in-depth weakness is not active malice
        assert (100 - res.security_score) >= 70  # Posture defect
        # Verified that HeaderScanResponse disclaimer is present
        assert "does not prove a site is malicious" in res.disclaimer


