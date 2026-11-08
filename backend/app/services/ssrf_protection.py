import ipaddress
import dns.resolver
from urllib.parse import urlparse
from typing import Tuple, List, Optional, Dict, Any
import httpcore
import httpx


# Blocked IPv4 networks
BLOCKED_IPV4_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),          # "This host on this network"
    ipaddress.ip_network("10.0.0.0/8"),         # RFC 1918 Private
    ipaddress.ip_network("100.64.0.0/10"),      # Shared Address Space (RFC 6598 / CGNAT & Cloud Internal)
    ipaddress.ip_network("127.0.0.0/8"),        # Loopback
    ipaddress.ip_network("169.254.0.0/16"),     # Link-Local (AWS/GCP/Azure metadata: 169.254.169.254)
    ipaddress.ip_network("172.16.0.0/12"),      # RFC 1918 Private
    ipaddress.ip_network("192.168.0.0/16"),     # RFC 1918 Private
    ipaddress.ip_network("192.0.2.0/24"),       # TEST-NET-1
    ipaddress.ip_network("198.51.100.0/24"),    # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),     # TEST-NET-3
    ipaddress.ip_network("224.0.0.0/4"),        # Multicast
    ipaddress.ip_network("240.0.0.0/4"),        # Reserved for Future Use
    ipaddress.ip_network("255.255.255.255/32")  # Broadcast
]

# Blocked IPv6 networks
BLOCKED_IPV6_NETWORKS = [
    ipaddress.ip_network("::1/128"),            # Loopback
    ipaddress.ip_network("::/128"),             # Unspecified
    ipaddress.ip_network("fc00::/7"),           # Unique Local Address (ULA)
    ipaddress.ip_network("fe80::/10"),          # Link-Local
    ipaddress.ip_network("ff00::/8"),           # Multicast
    ipaddress.ip_network("2001:db8::/32"),      # Documentation
    ipaddress.ip_network("64:ff9b::/96"),       # IPv4/IPv6 translation
    ipaddress.ip_network("::ffff:0:0/96")       # IPv4-mapped IPv6 (re-checked as IPv4)
]


def is_ip_private_or_restricted(ip_str: str) -> Tuple[bool, str]:
    """
    Evaluates whether an IP address is private, loopback, link-local, multicast, or reserved.
    Returns (is_restricted, reason).
    """
    try:
        clean = ip_str.strip()
        if clean.startswith("[") and clean.endswith("]"):
            clean = clean[1:-1]
        ip = ipaddress.ip_address(clean)
    except ValueError:
        return True, f"Invalid IP address format: {ip_str}"

    # Handle IPv4-mapped IPv6 (e.g., ::ffff:127.0.0.1 or ::ffff:169.254.169.254)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped

    if isinstance(ip, ipaddress.IPv4Address):
        for net in BLOCKED_IPV4_NETWORKS:
            if ip in net:
                return True, f"IPv4 address {ip} falls inside restricted/internal range {net}"
    elif isinstance(ip, ipaddress.IPv6Address):
        for net in BLOCKED_IPV6_NETWORKS:
            if ip in net:
                return True, f"IPv6 address {ip} falls inside restricted/internal range {net}"

    if ip.is_private:
        return True, f"IP address {ip} is in RFC private space"
    if ip.is_loopback:
        return True, f"IP address {ip} is a loopback address"
    if ip.is_link_local:
        return True, f"IP address {ip} is a link-local address"
    if ip.is_multicast:
        return True, f"IP address {ip} is a multicast address"
    if ip.is_reserved:
        return True, f"IP address {ip} is reserved"

    return False, "Public routable IP"


def resolve_hostname_safely(hostname: str) -> Tuple[bool, List[str], str]:
    """
    Resolves hostname to IP addresses using dnspython with safe timeouts
    and evaluates each against SSRF restrictions. Correctly handles IPv6 brackets,
    ports, and literal IP addresses.
    Returns (is_safe, resolved_ips, message).
    """
    if not hostname:
        return False, [], "Empty hostname"

    # Clean brackets or single colon for host:port
    clean_host = hostname.strip()
    if clean_host.startswith("[") and "]" in clean_host:
        clean_host = clean_host[1:clean_host.index("]")]
    elif clean_host.count(":") == 1:
        clean_host = clean_host.split(":")[0]

    # 1. Check if already a literal IP (IPv4 or IPv6)
    try:
        ip = ipaddress.ip_address(clean_host)
        is_restricted, reason = is_ip_private_or_restricted(str(ip))
        if is_restricted:
            return False, [str(ip)], f"Literal IP is prohibited: {reason}"
        return True, [str(ip)], "Public literal IP"
    except ValueError:
        pass

    # 2. Query DNS A and AAAA records with safe timeouts
    resolved_ips: List[str] = []
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2.0
        resolver.lifetime = 3.0
        try:
            answers = resolver.resolve(clean_host, "A")
            for rdata in answers:
                resolved_ips.append(str(rdata))
        except Exception:
            pass

        try:
            answers = resolver.resolve(clean_host, "AAAA")
            for rdata in answers:
                resolved_ips.append(str(rdata))
        except Exception:
            pass
    except Exception:
        pass

    if not resolved_ips:
        return False, [], f"DNS resolution failed or produced no records for host '{clean_host}'"

    # 3. Check every resolved IP for SSRF
    for ip in resolved_ips:
        is_restricted, reason = is_ip_private_or_restricted(ip)
        if is_restricted:
            return False, resolved_ips, f"DNS resolved to restricted IP {ip}: {reason}"

    return True, resolved_ips, "Public routable host"


def validate_url_for_ssrf(url: str) -> Tuple[bool, str, Optional[str]]:
    """
    Validates a URL for SSRF protection:
    - Scheme must be http or https
    - Hostname must resolve to safe, public IP addresses
    Returns (is_safe, error_or_reason, primary_resolved_ip)
    """
    try:
        parsed = urlparse(url)
        if parsed.scheme.lower() not in ("http", "https"):
            return False, f"Unsupported scheme '{parsed.scheme}'. Only HTTP and HTTPS are permitted.", None

        hostname = parsed.hostname
        if not hostname:
            return False, "URL does not contain a valid hostname.", None

        is_safe, resolved_ips, reason = resolve_hostname_safely(hostname)
        if not is_safe:
            return False, reason, resolved_ips[0] if resolved_ips else None

        primary_ip = resolved_ips[0] if resolved_ips else None
        return True, reason or "URL is safe for outbound inspection", primary_ip
    except Exception as e:
        return False, f"URL validation failed: {str(e)}", None


class SSRFSafeNetworkBackend(httpcore.AnyIOBackend):
    """
    Custom NetworkBackend for httpcore/httpx that enforces connection-time IP binding.
    Every TCP connection is pinned to a pre-validated public IP address, preventing
    Time-of-Check to Time-of-Use (TOCTOU) DNS rebinding attacks while preserving
    correct TLS SNI hostname verification.
    """
    def __init__(self, pinned_ips: Optional[Dict[str, str]] = None):
        super().__init__()
        self.pinned_ips = pinned_ips or {}

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: Optional[float] = None,
        local_address: Optional[str] = None,
        socket_options: Any = None
    ) -> httpcore.AsyncNetworkStream:
        target_ip = self.pinned_ips.get(host)
        if not target_ip:
            is_safe, resolved_ips, reason = resolve_hostname_safely(host)
            if not is_safe or not resolved_ips:
                raise ValueError(f"SSRF Protection blocked connection to '{host}': {reason}")
            target_ip = resolved_ips[0]

        is_restricted, reason = is_ip_private_or_restricted(target_ip)
        if is_restricted:
            raise ValueError(f"SSRF Protection blocked connection to IP '{target_ip}': {reason}")

        # Connect directly to the validated IP address
        return await super().connect_tcp(
            target_ip,
            port,
            timeout=timeout,
            local_address=local_address,
            socket_options=socket_options
        )


def create_ssrf_safe_transport(
    verify: bool = True,
    pinned_ips: Optional[Dict[str, str]] = None
) -> httpx.AsyncHTTPTransport:
    """
    Instantiates an HTTPX AsyncHTTPTransport backed by SSRFSafeNetworkBackend
    for connection-time IP enforcement and DNS rebinding prevention.
    """
    transport = httpx.AsyncHTTPTransport(verify=verify)
    transport._pool._network_backend = SSRFSafeNetworkBackend(pinned_ips=pinned_ips)
    return transport
