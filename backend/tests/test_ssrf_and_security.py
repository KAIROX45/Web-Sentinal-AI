import pytest
import asyncio
from unittest.mock import AsyncMock, patch, MagicMock
import httpx
from app.services.ssrf_protection import (
    is_ip_private_or_restricted,
    resolve_hostname_safely,
    validate_url_for_ssrf,
    SSRFSafeNetworkBackend,
    create_ssrf_safe_transport
)
from app.services.url_analyzer import inspect_redirect_chain
from app.services.header_checker import inspect_http_headers


def test_private_and_restricted_ips():
    # IPv4 Loopback
    for ip in ["127.0.0.1", "127.0.1.1", "127.255.255.254"]:
        is_restr, reason = is_ip_private_or_restricted(ip)
        assert is_restr is True
        assert "loopback" in reason.lower() or "restricted" in reason.lower()

    # IPv6 Loopback
    for ip in ["::1", "0:0:0:0:0:0:0:1"]:
        is_restr, reason = is_ip_private_or_restricted(ip)
        assert is_restr is True
        assert "loopback" in reason.lower() or "restricted" in reason.lower()

    # AWS / Azure / GCP Cloud Metadata
    is_restr, reason = is_ip_private_or_restricted("169.254.169.254")
    assert is_restr is True
    assert "link-local" in reason.lower() or "metadata" in reason.lower() or "restricted" in reason.lower()

    # Alibaba Cloud Metadata / CGNAT (100.64.0.0/10)
    for ip in ["100.100.100.200", "100.64.0.1", "100.127.255.254"]:
        is_restr, reason = is_ip_private_or_restricted(ip)
        assert is_restr is True
        assert "cgnat" in reason.lower() or "metadata" in reason.lower() or "shared" in reason.lower() or "restricted" in reason.lower()

    # RFC 1918 Private Ranges
    for ip in ["10.0.0.1", "10.255.255.255", "172.16.0.1", "172.31.255.255", "192.168.0.1", "192.168.1.100"]:
        is_restr, reason = is_ip_private_or_restricted(ip)
        assert is_restr is True
        assert "private" in reason.lower() or "restricted" in reason.lower()

    # IPv6 Unique Local (ULA) & Link-Local
    for ip in ["fc00::1", "fd12:3456:789a::1", "fe80::1", "fe80::200:5aee:feaa:20a2"]:
        is_restr, reason = is_ip_private_or_restricted(ip)
        assert is_restr is True

    # IPv4-Mapped IPv6
    for ip in ["::ffff:127.0.0.1", "::ffff:169.254.169.254", "::ffff:10.0.0.1", "::ffff:192.168.1.1"]:
        is_restr, reason = is_ip_private_or_restricted(ip)
        assert is_restr is True

    # 0.0.0.0 / Unspecified & Broadcast / Multicast
    for ip in ["0.0.0.0", "::", "224.0.0.1", "255.255.255.255", "ff02::1"]:
        is_restr, reason = is_ip_private_or_restricted(ip)
        assert is_restr is True

    # Reserved Documentation IP ranges (RFC 5737 / RFC 3849)
    for ip in ["192.0.2.1", "198.51.100.1", "203.0.113.1", "2001:db8::1"]:
        is_restr, reason = is_ip_private_or_restricted(ip)
        assert is_restr is True

    # Public Routable IPs must NOT be restricted
    for ip in ["8.8.8.8", "1.1.1.1", "93.184.215.14", "2606:4700:4700::1111"]:
        is_restr, reason = is_ip_private_or_restricted(ip)
        assert is_restr is False
        assert "Public" in reason


def test_url_ssrf_validation_blocks_internal_hosts():
    # Direct loopback URLs
    for target in ["http://127.0.0.1:8000/api/threats", "http://localhost:3000", "http://[::1]:8080/admin"]:
        safe, msg, _ = validate_url_for_ssrf(target)
        assert safe is False
        assert "restricted" in msg.lower() or "prohibited" in msg.lower() or "loopback" in msg.lower()

    # Cloud Metadata URLs
    for target in ["http://169.254.169.254/latest/meta-data/", "http://[::ffff:169.254.169.254]/"]:
        safe, msg, _ = validate_url_for_ssrf(target)
        assert safe is False

    # Private Subnets in URLs
    for target in ["http://10.0.0.5:8080/", "http://192.168.1.1/router", "http://172.16.0.1/status"]:
        safe, msg, _ = validate_url_for_ssrf(target)
        assert safe is False

    # Prohibited & Unsupported Schemes
    for target in [
        "file:///etc/passwd",
        "ftp://internal.backup/data",
        "gopher://127.0.0.1:70/",
        "javascript:alert(document.cookie)",
        "data:text/html,<h1>PWNED</h1>"
    ]:
        safe, msg, _ = validate_url_for_ssrf(target)
        assert safe is False
        assert "unsupported scheme" in msg.lower() or "missing scheme" in msg.lower()

    # Malformed URLs
    for target in ["", "not-a-url", "http://", "https://:443"]:
        safe, msg, _ = validate_url_for_ssrf(target)
        assert safe is False


def test_dns_failure_not_classified_as_safe():
    # Non-existent randomized domain must return False and NOT classify missing info as safe
    safe, ips, msg = resolve_hostname_safely("this-domain-definitely-does-not-exist-xyz-982341.com")
    assert safe is False
    assert len(ips) == 0
    assert "failed or produced no records" in msg.lower() or "no dns records" in msg.lower()


@pytest.mark.anyio
async def test_ssrf_safe_network_backend_dns_rebinding():
    # Simulate DNS rebinding: host looks like an external domain, but resolves/pins to a private IP
    backend = SSRFSafeNetworkBackend(pinned_ips={"evil-rebinding-domain.com": "127.0.0.1"})

    with pytest.raises(ValueError) as excinfo:
        await backend.connect_tcp("evil-rebinding-domain.com", 80)
    assert "SSRF Protection blocked connection to IP" in str(excinfo.value)
    assert "127.0.0.1" in str(excinfo.value)

    # Cloud metadata rebinding simulation
    backend_meta = SSRFSafeNetworkBackend(pinned_ips={"metadata-rebind.com": "169.254.169.254"})
    with pytest.raises(ValueError) as excinfo_meta:
        await backend_meta.connect_tcp("metadata-rebind.com", 80)
    assert "SSRF Protection blocked connection to IP" in str(excinfo_meta.value)
    assert "169.254.169.254" in str(excinfo_meta.value)


@pytest.mark.anyio
async def test_public_to_private_redirect_blocking():
    # Mock redirect chain: initial safe URL redirects to internal cloud metadata
    hops = await inspect_redirect_chain("http://127.0.0.1:8000/initial")
    # First hop itself is blocked because initial is loopback
    assert len(hops) == 1
    assert hops[0].status_code == 403
    assert hops[0].is_safe is False

    # Simulate multi-hop where hop 1 returns 302 to 169.254.169.254
    mock_resp1 = MagicMock()
    mock_resp1.status_code = 302
    mock_resp1.headers = {"location": "http://169.254.169.254/latest/meta-data/"}

    with patch("httpx.AsyncClient.head", new_callable=AsyncMock) as mock_head:
        mock_head.return_value = mock_resp1
        hops = await inspect_redirect_chain("https://google.com/redirect-test")
        # Hop 1 succeeded, hop 2 target is 169.254.169.254 which must be BLOCKED
        assert len(hops) == 2
        assert hops[0].status_code == 302
        assert hops[0].is_safe is True
        assert hops[1].status_code == 403
        assert hops[1].is_safe is False
        assert "169.254.169.254" in hops[1].url


@pytest.mark.anyio
async def test_redirect_hop_limit_enforced():
    # Mock redirect chain looping endlessly
    mock_loop_resp = MagicMock()
    mock_loop_resp.status_code = 301
    mock_loop_resp.headers = {"location": "https://google.com/loop"}

    with patch("httpx.AsyncClient.head", new_callable=AsyncMock) as mock_head:
        mock_head.return_value = mock_loop_resp
        hops = await inspect_redirect_chain("https://google.com/loop", max_hops=5)
        # Must not exceed max_hops
        assert len(hops) == 5

    # In header_checker, exceeding max_hops must raise ValueError
    with patch("httpx.AsyncClient.head", new_callable=AsyncMock) as mock_head:
        mock_head.return_value = mock_loop_resp
        with pytest.raises(ValueError) as excinfo:
            await inspect_http_headers("https://google.com/loop")
        assert "Maximum redirect hops (5) exceeded" in str(excinfo.value)
