import uuid
import json
import hashlib
import ssl
import httpx
import logging
from datetime import datetime, timezone
from typing import List, Dict, Any, Tuple, Optional
from urllib.parse import urljoin
from app.services.ssrf_protection import validate_url_for_ssrf, create_ssrf_safe_transport
from app.schemas.headers import HeaderItem, HeaderScanResponse

logger = logging.getLogger("websentinel.header_checker")

SECURITY_HEADER_SPECS = [
    {
        "name": "Strict-Transport-Security",
        "importance": "HIGH",
        "recommended": "max-age=63072000; includeSubDomains; preload",
        "purpose": "Enforces secure HTTPS connections and prevents SSL-stripping man-in-the-middle attacks.",
        "evaluator": lambda val: "PRESENT_OPTIMAL" if val and "max-age" in val.lower() and int("".join(filter(str.isdigit, val.split("max-age=")[1].split(";")[0])) or 0) >= 31536000 else ("PRESENT_WEAK" if val else "MISSING"),
        "impact": "Without HSTS, attackers on insecure networks can downgrade requests to plaintext HTTP."
    },
    {
        "name": "Content-Security-Policy",
        "importance": "HIGH",
        "recommended": "default-src 'self'; script-src 'self'; object-src 'none';",
        "purpose": "Restricts execution of unauthorized scripts, preventing Cross-Site Scripting (XSS) and data injection.",
        "evaluator": lambda val: "PRESENT_OPTIMAL" if val and ("default-src" in val or "script-src" in val) and "'unsafe-inline'" not in val else ("PRESENT_WEAK" if val else "MISSING"),
        "impact": "Absent CSP dramatically increases blast radius if user-controlled input reaches HTML templates."
    },
    {
        "name": "X-Frame-Options",
        "importance": "HIGH",
        "recommended": "DENY or SAMEORIGIN",
        "purpose": "Protects users against Clickjacking attacks by forbidding rendering in iframes.",
        "evaluator": lambda val: "PRESENT_OPTIMAL" if val and val.upper() in ("DENY", "SAMEORIGIN") else ("PRESENT_WEAK" if val else "MISSING"),
        "impact": "Without clickjacking protection, malicious sites can overlay invisible frames over sensitive buttons."
    },
    {
        "name": "X-Content-Type-Options",
        "importance": "MEDIUM",
        "recommended": "nosniff",
        "purpose": "Prevents MIME-type sniffing, ensuring browsers do not interpret files as executable scripts.",
        "evaluator": lambda val: "PRESENT_OPTIMAL" if val and val.lower().strip() == "nosniff" else ("PRESENT_WEAK" if val else "MISSING"),
        "impact": "MIME sniffing can lead to drive-by code execution if attackers upload scripts masked as images."
    },
    {
        "name": "Referrer-Policy",
        "importance": "MEDIUM",
        "recommended": "strict-origin-when-cross-origin",
        "purpose": "Controls how much referrer information is leaked to third-party endpoints on link clicks.",
        "evaluator": lambda val: "PRESENT_OPTIMAL" if val and ("strict-origin" in val.lower() or val.lower() in ("no-referrer", "same-origin")) else ("PRESENT_WEAK" if val else "MISSING"),
        "impact": "Loose referrer policies can leak private query parameters or token IDs in HTTP referer headers."
    },
    {
        "name": "Permissions-Policy",
        "importance": "LOW",
        "recommended": "camera=(), microphone=(), geolocation=()",
        "purpose": "Restricts browser features and sensitive device APIs available to third-party frames.",
        "evaluator": lambda val: "PRESENT_OPTIMAL" if val else "MISSING",
        "impact": "Unrestricted device permissions can expose sensors or cameras to untrusted embedded widgets."
    }
]


async def inspect_http_headers(url: str, timeout: float = 6.0) -> HeaderScanResponse:
    """
    Fetches HTTP response headers with strict SSRF validation and provides
    a structured compliance assessment for each security header.
    """
    target = url.strip()
    if not target.startswith("http://") and not target.startswith("https://"):
        target = "https://" + target

    # SSRF verification on initial URL
    is_safe, reason, _ = validate_url_for_ssrf(target)
    if not is_safe:
        raise ValueError(f"SSRF Protection blocked request: {reason}")

    headers_table: List[HeaderItem] = []
    missing_count = 0
    optimal_count = 0
    weak_count = 0
    info_leakage: List[str] = []
    server_banner: Optional[str] = None
    final_url = target
    status_code = 0
    raw_headers: Dict[str, str] = {}
    current_url = target

    try:
        transport = create_ssrf_safe_transport(verify=True)
        async with httpx.AsyncClient(transport=transport, timeout=timeout, follow_redirects=False) as client:
            max_hops = 5
            for hop in range(max_hops):
                # Validate every hop URL before request to prevent redirect SSRF
                hop_safe, hop_reason, _ = validate_url_for_ssrf(current_url)
                if not hop_safe:
                    raise ValueError(f"SSRF Protection blocked redirect hop #{hop+1} to '{current_url}': {hop_reason}")

                resp = await client.head(current_url)
                if resp.status_code == 405:  # Method Not Allowed on HEAD
                    # Stream fallback GET with byte chunk limit to prevent memory exhaustion / DoS
                    async with client.stream("GET", current_url, headers={"Range": "bytes=0-1024"}) as stream_resp:
                        _ = await anext(stream_resp.aiter_bytes(1024), b"")
                        final_url = str(stream_resp.url)
                        status_code = stream_resp.status_code
                        raw_headers = {k.lower(): v for k, v in stream_resp.headers.items()}
                else:
                    final_url = str(resp.url)
                    status_code = resp.status_code
                    raw_headers = {k.lower(): v for k, v in resp.headers.items()}

                # Check if response is a redirect and follow safely
                if resp.is_redirect and "location" in raw_headers:
                    redirect_location = raw_headers["location"]
                    current_url = urljoin(str(resp.url), redirect_location)
                    if hop == max_hops - 1:
                        raise ValueError(f"Maximum redirect hops ({max_hops}) exceeded for '{target}'")
                    continue
                else:
                    break

            # Server banner disclosure check
            if "server" in raw_headers:
                server_banner = raw_headers["server"]
                info_leakage.append(f"Server header exposes technology: '{server_banner}'")
            if "x-powered-by" in raw_headers:
                info_leakage.append(f"X-Powered-By header exposes runtime: '{raw_headers['x-powered-by']}'")

            # Evaluate each standardized security header
            for spec in SECURITY_HEADER_SPECS:
                h_name = spec["name"]
                val = raw_headers.get(h_name.lower())
                status = spec["evaluator"](val)

                if status == "PRESENT_OPTIMAL":
                    optimal_count += 1
                elif status == "PRESENT_WEAK":
                    weak_count += 1
                else:
                    missing_count += 1

                headers_table.append(HeaderItem(
                    name=h_name,
                    status=status,
                    actual_value=val,
                    importance=spec["importance"],
                    recommended_value=spec["recommended"],
                    purpose=spec["purpose"],
                    security_impact=spec["impact"]
                ))

            # Compute Security Score (0-100)
            score = 100 - (missing_count * 15) - (weak_count * 8) - (len(info_leakage) * 5)
            score = max(10, min(100, score))

            scan_id = str(uuid.uuid4())
            timestamp = datetime.now(timezone.utc).isoformat()
            # Missing headers represent defensive weaknesses, not active malice:
            # Risk level is capped at SUSPICIOUS (max risk score 45)
            risk_level_str = "SUSPICIOUS" if missing_count >= 3 else "LOW"
            risk_score_val = min(45, max(5, int((100 - score) * 0.45)))

            canonical_payload = {
                "findings_digest": f"Score {score}/100; {missing_count} missing headers; {len(info_leakage)} leaks",
                "risk_level": risk_level_str,
                "risk_score": risk_score_val,
                "scan_type": "headers",
                "target": target,
                "timestamp_utc": timestamp
            }
            canonical_hash = "0x" + hashlib.sha256(json.dumps(canonical_payload, sort_keys=True).encode()).hexdigest()

            return HeaderScanResponse(
                id=scan_id,
                canonical_hash=canonical_hash,
                url=target,
                final_url=final_url,
                status_code=status_code,
                headers_table=headers_table,
                security_score=score,
                missing_count=missing_count,
                optimal_count=optimal_count,
                weak_count=weak_count,
                server_banner=server_banner,
                information_disclosure=info_leakage,
                disclaimer="An absent or misconfigured header alone does not prove a site is malicious, but weakens defense-in-depth.",
                timestamp=timestamp
            )
    except httpx.TimeoutException:
        raise TimeoutError(f"HTTP connection to '{target}' timed out after {timeout} seconds.")
    except (ssl.SSLCertVerificationError, httpx.ConnectError) as e:
        err_msg = str(e)
        if "certificate verify failed" in err_msg.lower() or "ssl" in err_msg.lower() or "cert" in err_msg.lower():
            raise RuntimeError(f"TLS certificate verification failed for '{target}': {err_msg}")
        raise RuntimeError(f"HTTP connection to '{target}' failed: {err_msg}")
    except ValueError:
        raise
    except Exception as e:
        raise RuntimeError(f"Header inspection failed: {str(e)}")

