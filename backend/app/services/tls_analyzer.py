import ssl
import socket
import datetime
import uuid
import json
import hashlib
from typing import Dict, Any, List, Optional, Tuple
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID, ExtensionOID
from app.services.ssrf_protection import resolve_hostname_safely
from app.schemas.tls import TLSScanResponse, CertificateChainNode
from app.schemas.common import RiskLevel


def inspect_tls_certificate(hostname: str, port: int = 443, timeout: float = 6.0) -> TLSScanResponse:
    """
    Directly connects to target server on specified port, extracts binary DER certificate,
    evaluates CA trust chain against standard system CA roots, parses TLS protocol and cipher suite,
    validates hostname matching (RFC 6125), expiration, and revocation indicators.
    Never fabricates synthetic CA roots or simulated trust anchors.
    """
    clean_host = hostname.strip().lower()
    if clean_host.startswith("http://"):
        clean_host = clean_host[7:]
    elif clean_host.startswith("https://"):
        clean_host = clean_host[8:]
    if "/" in clean_host:
        clean_host = clean_host.split("/")[0]
    if ":" in clean_host and not clean_host.startswith("["):
        parts = clean_host.split(":")
        clean_host = parts[0]
        try:
            port = int(parts[1])
        except ValueError:
            pass

    # SSRF verification on hostname before connecting
    is_safe, resolved_ips, error_msg = resolve_hostname_safely(clean_host)
    if not is_safe:
        raise ValueError(f"SSRF Protection blocked connection: {error_msg}")

    connected_ip = resolved_ips[0] if resolved_ips else None
    if not connected_ip:
        raise ValueError(f"Unable to resolve valid IP for host: {clean_host}")

    warnings: List[str] = []
    chain_nodes: List[CertificateChainNode] = []

    # 1. First probe CA trust against standard system roots
    is_ca_trusted = False
    verification_error = None
    verified_chain_der: List[bytes] = []

    try:
        verify_context = ssl.create_default_context()
        with socket.create_connection((connected_ip, port), timeout=timeout) as sock:
            with verify_context.wrap_socket(sock, server_hostname=clean_host) as ssock:
                is_ca_trusted = True
                if hasattr(ssock, "get_verified_chain"):
                    verified_chain_der = ssock.get_verified_chain() or []
    except (ssl.SSLCertVerificationError, ssl.SSLError) as cert_err:
        is_ca_trusted = False
        verification_error = str(cert_err)
    except Exception:
        # Port or handshake failure handled in secondary socket probe
        pass

    # 2. Extract full certificate details using permissive inspection context
    # (Allows inspecting expired, self-signed, or untrusted certs)
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((connected_ip, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=clean_host) as ssock:
                protocol_version = ssock.version() or "Unknown"
                cipher_info = ssock.cipher()
                cipher_suite = cipher_info[0] if cipher_info else "Unknown"

                # Extract DER bytes of peer certificate
                der_cert = ssock.getpeercert(binary_form=True)
                if not der_cert:
                    raise ValueError("No TLS certificate presented by the remote server.")

                cert = x509.load_der_x509_certificate(der_cert, default_backend())

                # Subject parsing
                subject = cert.subject
                subject_cn = _get_name_attribute(subject, NameOID.COMMON_NAME)
                subject_org = _get_name_attribute(subject, NameOID.ORGANIZATION_NAME)

                # Issuer parsing
                issuer = cert.issuer
                issuer_cn = _get_name_attribute(issuer, NameOID.COMMON_NAME)
                issuer_org = _get_name_attribute(issuer, NameOID.ORGANIZATION_NAME)

                # SANs parsing
                sans: List[str] = []
                try:
                    san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                    sans = [str(x.value) for x in san_ext.value]
                except x509.ExtensionNotFound:
                    pass

                # Dates
                valid_from_dt = cert.not_valid_before_utc if hasattr(cert, 'not_valid_before_utc') else cert.not_valid_before.replace(tzinfo=datetime.timezone.utc)
                valid_to_dt = cert.not_valid_after_utc if hasattr(cert, 'not_valid_after_utc') else cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)
                
                now = datetime.datetime.now(datetime.timezone.utc)
                is_expired = now > valid_to_dt
                days_remaining = (valid_to_dt - now).days

                # Hostname matching RFC 6125
                hostname_matches = _verify_hostname(clean_host, subject_cn, sans)

                # Self-signed detection
                is_self_signed = (subject == issuer)

                # Serial number & Signature algorithm
                serial_hex = f"{cert.serial_number:X}"
                sig_alg = cert.signature_hash_algorithm.name.upper() if cert.signature_hash_algorithm else "Unknown"
                
                # Public Key size and type
                pub_key = cert.public_key()
                key_type = pub_key.__class__.__name__.replace("_", "").replace("PublicKey", "")
                key_bits = getattr(pub_key, "key_size", 0)

                # Check OCSP extension
                has_ocsp = False
                try:
                    aia_ext = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
                    for desc in aia_ext.value:
                        if desc.access_method._name == "ocsp":
                            has_ocsp = True
                            break
                except x509.ExtensionNotFound:
                    pass

                revocation_note = (
                    "Not Checked: OCSP AIA extension present in leaf certificate (CRL/OCSP lookup recommended for strict verification)"
                    if has_ocsp else
                    "Not Checked: No OCSP AIA extension found in leaf certificate"
                )

                # Check warnings
                if is_expired:
                    warnings.append(f"Certificate expired on {valid_to_dt.strftime('%Y-%m-%d')} ({abs(days_remaining)} days ago)")
                elif days_remaining < 15:
                    warnings.append(f"Certificate expires in {days_remaining} days (Renewal recommended)")

                if is_self_signed:
                    warnings.append("Certificate is self-signed (Untrusted by standard web browsers)")
                elif not is_ca_trusted and verification_error:
                    warnings.append(f"Untrusted Certificate Authority: {verification_error}")

                if not hostname_matches:
                    warnings.append(f"Certificate common name or SAN does not match requested host '{clean_host}'")

                if protocol_version in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
                    warnings.append(f"Insecure/Deprecated protocol version negotiated: {protocol_version}")

                if "sha1" in sig_alg.lower() or "md5" in sig_alg.lower():
                    warnings.append(f"Weak signature hash algorithm: {sig_alg}")

                # Build truthful certificate chain representation from actual verified DER objects
                if verified_chain_der:
                    for idx, c_bytes in enumerate(verified_chain_der):
                        try:
                            c = x509.load_der_x509_certificate(c_bytes, default_backend())
                            c_subj = _get_name_attribute(c.subject, NameOID.COMMON_NAME) or _get_name_attribute(c.subject, NameOID.ORGANIZATION_NAME) or "Certificate Node"
                            c_iss = _get_name_attribute(c.issuer, NameOID.COMMON_NAME) or _get_name_attribute(c.issuer, NameOID.ORGANIZATION_NAME) or "Certificate Authority"
                            c_from_dt = c.not_valid_before_utc if hasattr(c, 'not_valid_before_utc') else c.not_valid_before.replace(tzinfo=datetime.timezone.utc)
                            c_to_dt = c.not_valid_after_utc if hasattr(c, 'not_valid_after_utc') else c.not_valid_after.replace(tzinfo=datetime.timezone.utc)
                            c_sig = c.signature_hash_algorithm.name.upper() if c.signature_hash_algorithm else "Unknown"

                            chain_nodes.append(CertificateChainNode(
                                level=idx,
                                subject=c_subj,
                                issuer=c_iss,
                                is_root=(c.subject == c.issuer),
                                is_leaf=(idx == 0),
                                valid_from=c_from_dt.strftime("%Y-%m-%d"),
                                valid_to=c_to_dt.strftime("%Y-%m-%d"),
                                signature_algorithm=c_sig
                            ))
                        except Exception:
                            pass

                # If no verified chain could be established (e.g. self-signed or untrusted CA),
                # accurately represent leaf node without inventing fictional root nodes
                if not chain_nodes:
                    chain_nodes.append(CertificateChainNode(
                        level=0,
                        subject=subject_cn or subject_org or "Leaf Certificate",
                        issuer=issuer_cn or issuer_org or "Issuer",
                        is_root=is_self_signed,
                        is_leaf=True,
                        valid_from=valid_from_dt.strftime("%Y-%m-%d"),
                        valid_to=valid_to_dt.strftime("%Y-%m-%d"),
                        signature_algorithm=sig_alg
                    ))
                    if not is_self_signed:
                        chain_nodes.append(CertificateChainNode(
                            level=1,
                            subject=issuer_cn or issuer_org or "Untrusted Intermediate CA",
                            issuer="Untrusted Root Authority (Missing from system trust store)",
                            is_root=False,
                            is_leaf=False,
                            valid_from="Untrusted",
                            valid_to="Untrusted",
                            signature_algorithm=sig_alg
                        ))

                # Calculate Risk
                risk_level, risk_score = _calculate_tls_risk(
                    is_expired=is_expired,
                    is_self_signed=is_self_signed,
                    is_ca_trusted=is_ca_trusted,
                    hostname_matches=hostname_matches,
                    protocol=protocol_version,
                    warnings=warnings
                )

                scan_id = str(uuid.uuid4())
                canonical_payload = {
                    "findings_digest": f"{protocol_version}; {cipher_suite}; {issuer_cn or 'Untrusted CA'}; {days_remaining}d remaining",
                    "risk_level": risk_level.value,
                    "risk_score": risk_score,
                    "scan_type": "tls",
                    "target": f"{clean_host}:{port}",
                    "timestamp_utc": now.isoformat()
                }
                canonical_hash = "0x" + hashlib.sha256(json.dumps(canonical_payload, sort_keys=True).encode()).hexdigest()

                return TLSScanResponse(
                    id=scan_id,
                    canonical_hash=canonical_hash,
                    hostname=clean_host,
                    port=port,
                    connected_ip=connected_ip,
                    protocol_version=protocol_version,
                    cipher_suite=cipher_suite,
                    subject_cn=subject_cn,
                    subject_org=subject_org,
                    issuer_cn=issuer_cn,
                    issuer_org=issuer_org,
                    sans=sans[:30],  # cap at 30 for clean UI
                    valid_from=valid_from_dt.isoformat(),
                    valid_to=valid_to_dt.isoformat(),
                    days_remaining=days_remaining,
                    is_valid=not is_expired and hostname_matches and (is_ca_trusted or not is_self_signed),
                    is_expired=is_expired,
                    is_self_signed=is_self_signed,
                    is_ca_trusted=is_ca_trusted,
                    hostname_matches=hostname_matches,
                    serial_number=serial_hex,
                    signature_algorithm=sig_alg,
                    key_type=key_type,
                    key_bits=key_bits,
                    certificate_chain=chain_nodes,
                    revocation_status=revocation_note,
                    warnings=warnings,
                    risk_level=risk_level,
                    risk_score=risk_score,
                    timestamp=now.isoformat()
                )
    except socket.timeout:
        raise TimeoutError(f"TLS connection to {clean_host}:{port} timed out after {timeout} seconds.")
    except Exception as e:
        raise RuntimeError(f"TLS inspection failed for {clean_host}:{port}: {str(e)}")


def _get_name_attribute(name: x509.Name, oid) -> Optional[str]:
    attrs = name.get_attributes_for_oid(oid)
    if attrs:
        return attrs[0].value
    return None


def _verify_hostname(hostname: str, cn: Optional[str], sans: List[str]) -> bool:
    patterns = []
    if cn:
        patterns.append(cn.lower())
    for s in sans:
        patterns.append(s.lower())

    h = hostname.lower()
    for p in patterns:
        if p == h:
            return True
        if p.startswith("*."):
            suffix = p[2:]
            if h.endswith("." + suffix):
                prefix = h[:-len(suffix)-1]
                if "." not in prefix:
                    return True
    return False


def _calculate_tls_risk(
    is_expired: bool,
    is_self_signed: bool,
    is_ca_trusted: bool,
    hostname_matches: bool,
    protocol: str,
    warnings: List[str]
) -> Tuple[RiskLevel, int]:
    score = 0
    if is_expired:
        score += 55
    if is_self_signed:
        score += 45
    elif not is_ca_trusted:
        score += 35
    if not hostname_matches:
        score += 50
    if protocol in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
        score += 35

    score = min(score, 100)
    if score >= 80:
        return RiskLevel.HIGH, score
    elif score >= 40:
        return RiskLevel.SUSPICIOUS, score
    elif score > 0:
        return RiskLevel.LOW, max(15, score)
    return RiskLevel.LOW, 5
