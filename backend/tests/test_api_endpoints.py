import pytest
from starlette.testclient import TestClient
from app.main import app


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


def test_health_endpoint(client):
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] in ("healthy", "operational")
    assert "integrations" in data


def test_dashboard_stats_real_aggregation(client):
    res = client.get("/api/threats/stats")
    assert res.status_code == 200
    data = res.json()
    # Must use real database statistics
    assert "total_scans" in data
    assert "malicious_detected" in data
    assert "security_score" in data
    assert "recent_activity_trends" in data
    assert "threat_categories" in data
    assert "severity_distribution" in data
    assert isinstance(data["recent_activity_trends"], list)
    assert isinstance(data["threat_categories"], dict)


def test_unified_classify(client):
    # Test IP classification
    res_ip = client.post("/api/unified/classify", json={"query": "8.8.8.8"})
    assert res_ip.status_code == 200
    assert res_ip.json()["type"] == "ip"

    # Test URL classification
    res_url = client.post("/api/unified/classify", json={"query": "https://example.com/test"})
    assert res_url.status_code == 200
    assert res_url.json()["type"] == "url"

    # Test Message classification
    res_msg = client.post("/api/unified/classify", json={"query": "URGENT: Click here to verify your bank credentials immediately."})
    assert res_msg.status_code == 200
    assert res_msg.json()["type"] == "message"


def test_blockchain_status_no_fake_address(client):
    res = client.get("/api/blockchain/status")
    assert res.status_code == 200
    data = res.json()
    assert "network" in data
    assert "is_simulated" in data
    # When not connected to Sepolia, smart_contract_address is None (never a fake fabricated address)
    if not data["is_live_sepolia"]:
        assert data["is_simulated"] is True
        assert data["smart_contract_address"] is None


def test_url_scan_ssrf_blocking(client):
    # Prohibited local IP must be blocked with 100/100 risk score and SSRF explanation
    res = client.post("/api/url/scan", json={"url": "http://127.0.0.1:8000/internal", "deep_scan": False})
    assert res.status_code == 200
    data = res.json()
    assert data["risk_score"] == 100
    assert data["risk_level"] == "CONFIRMED MALICIOUS"
    assert "canonical_hash" in data
    assert any("SSRF" in e["category"] or "Prohibited IP" in e["indicator"] for e in data["evidence"])


def test_ip_scan_classification(client):
    # Private IP
    res_priv = client.post("/api/ip/scan", json={"ip_address": "10.0.0.1"})
    assert res_priv.status_code == 200
    data_priv = res_priv.json()
    assert data_priv["is_private"] is True
    assert "canonical_hash" in data_priv

    # Public IP
    res_pub = client.post("/api/ip/scan", json={"ip_address": "8.8.8.8"})
    assert res_pub.status_code == 200
    data_pub = res_pub.json()
    assert data_pub["is_private"] is False
    assert "Public" in data_pub["classification"]


def test_unified_scan_persists_to_history(client):
    # Scanning a test domain via unified endpoint must be persisted to database
    query_target = "https://example-test-threat.com"
    res = client.post("/api/unified/scan", json={"query": query_target, "forced_type": "url"})
    assert res.status_code == 200
    data = res.json()
    assert data["scan_type"] == "url"
    assert "canonical_hash" in data["data"]

    # Verify presence in /api/reports/history
    res_hist = client.get("/api/reports/history")
    assert res_hist.status_code == 200
    hist = res_hist.json()
    assert any(h["target"] == query_target for h in hist)


def test_settings_masking(client):
    res = client.get("/api/settings/")
    assert res.status_code == 200
    data = res.json()
    assert "database_url" in data
    assert "ethereum_rpc_url" in data
    # Credentials must be masked or clean
    assert "password" not in data["database_url"].lower()
    if data["gemini_api_key_configured"]:
        assert data["gemini_api_key_masked"].startswith("...")
    # Private keys must NEVER appear in output
    assert "wallet_private_key" not in data


def test_settings_admin_auth_and_validation(client):
    from app.config import settings
    # Enable test admin key
    settings.ADMIN_API_KEY = "super-secret-admin-pass"
    try:
        # 1. Update without authentication must return 401
        res_unauth = client.post("/api/settings/update", json={"contract_address": "0x1111111111111111111111111111111111111111"})
        assert res_unauth.status_code == 401
        assert "admin authorization required" in res_unauth.json()["detail"].lower()

        # 2. Update with invalid admin key must return 401
        res_bad_key = client.post(
            "/api/settings/update",
            json={"contract_address": "0x1111111111111111111111111111111111111111"},
            headers={"X-Admin-Key": "wrong-key"}
        )
        assert res_bad_key.status_code == 401

        # 3. Update with valid admin key but malformed contract address must return 400
        res_bad_addr = client.post(
            "/api/settings/update",
            json={"contract_address": "not-an-eth-address"},
            headers={"X-Admin-Key": "super-secret-admin-pass"}
        )
        assert res_bad_addr.status_code == 400
        assert "invalid contract address" in res_bad_addr.json()["detail"].lower()

        # 4. Update with valid admin key and valid address must succeed
        valid_addr = "0x1234567890123456789012345678901234567890"
        res_success = client.post(
            "/api/settings/update",
            json={"contract_address": valid_addr},
            headers={"X-Admin-Key": "super-secret-admin-pass"}
        )
        assert res_success.status_code == 200
        assert res_success.json()["message"] == "Settings updated successfully"
    finally:
        # Cleanup
        settings.ADMIN_API_KEY = None
        settings.CONTRACT_ADDRESS = None


def test_rate_limiter_throttling():
    from app.services.rate_limiter import SlidingWindowRateLimiter
    import asyncio

    async def run_limiter_test():
        limiter = SlidingWindowRateLimiter(limit_per_minute=5, window_seconds=60.0)
        # First 5 acquisitions succeed
        for _ in range(5):
            allowed, _ = await limiter.acquire("198.51.100.42")
            assert allowed is True

        # 6th acquisition within window must be rejected
        allowed, retry_after = await limiter.acquire("198.51.100.42")
        assert allowed is False
        assert retry_after > 0

        # Different IP should succeed
        allowed_other, _ = await limiter.acquire("203.0.113.99")
        assert allowed_other is True

    asyncio.run(run_limiter_test())


def test_report_export_json_branding(client):
    # Retrieve scan history to obtain an existing record
    res_hist = client.get("/api/reports/history")
    records = res_hist.json()
    if records:
        scan_id = records[0]["id"]
        res_exp = client.get(f"/api/reports/{scan_id}/export/json")
        assert res_exp.status_code == 200
        data = res_exp.json()
        assert "websentinel_meta" in data
        assert "WebSentinel AI Threat Intelligence" in data["websentinel_meta"]["platform"]

