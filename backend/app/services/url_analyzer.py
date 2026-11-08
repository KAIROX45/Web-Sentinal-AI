import re
import math
import uuid
import hashlib
import json
import socket
import datetime
from urllib.parse import urlparse, urlunparse, urljoin
from typing import List, Dict, Any, Tuple, Optional
import tldextract
import dns.resolver
import httpx
from sqlalchemy.orm import Session

# Initialize offline extractor to prevent network retries
tld_extractor = tldextract.TLDExtract(suffix_list_urls=())

from app.config import settings
from app.services.ssrf_protection import validate_url_for_ssrf, resolve_hostname_safely, create_ssrf_safe_transport
from app.services.threat_intelligence import check_threat_intelligence
from app.schemas.url import (
    URLScanResponse, DomainInfo, TyposquattingFinding, HomographFinding,
    DNSRecords, RedirectHop, ThreatIntelSource
)
from app.schemas.common import RiskLevel, EvidenceItem, RecommendedAction, SecurityScore

# High-profile brand targets for typosquatting checks
PROTECTED_BRANDS = [
    "google", "microsoft", "apple", "paypal", "amazon", "chase",
    "bankofamerica", "wellsfargo", "netflix", "facebook", "instagram",
    "twitter", "binance", "coinbase", "metamask", "whatsapp", "telegram",
    "dropbox", "linkedin", "adobe", "walmart", "fedex", "usps", "dhl"
]

SUSPICIOUS_TLDS = {
    "top", "xyz", "buzz", "work", "icu", "loan", "tk", "ml", "ga", "cf", "gq",
    "click", "link", "rest", "surf", "casa", "country", "live", "quest"
}

SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "verification", "secure", "security",
    "account", "update", "banking", "wallet", "recover", "recovery",
    "suspended", "alert", "billing", "confirm", "free", "claim", "airdrop"
]

# Cyrillic lookalikes to Latin characters
CYRILLIC_LOOKALIKES = {
    'а': 'a', 'с': 'c', 'е': 'e', 'о': 'o', 'р': 'p', 'х': 'x', 'у': 'y',
    'і': 'i', 'ј': 'j', 'ѕ': 's', 'ԁ': 'd', 'ԛ': 'q', 'ԝ': 'w'
}


def normalize_url(raw_url: str) -> Tuple[str, str, str]:
    """
    Normalizes submitted URL:
    - Trims whitespace
    - Ensures scheme is present (defaults to https://)
    - Lowercases hostname
    Returns (normalized_url, scheme, hostname)
    """
    clean = raw_url.strip()
    if not clean.startswith("http://") and not clean.startswith("https://"):
        clean = "https://" + clean

    parsed = urlparse(clean)
    scheme = parsed.scheme.lower()
    hostname = (parsed.hostname or "").lower()
    
    # Reconstruct normalized URL
    netloc = hostname
    if parsed.port and ((scheme == "http" and parsed.port != 80) or (scheme == "https" and parsed.port != 443)):
        netloc = f"{hostname}:{parsed.port}"
    if parsed.username or parsed.password:
        auth = f"{parsed.username or ''}:{parsed.password or ''}@"
        netloc = f"{auth}{netloc}"

    normalized = urlunparse((
        scheme,
        netloc,
        parsed.path or "/",
        parsed.params,
        parsed.query,
        ""  # strip fragments
    ))
    return normalized, scheme, hostname


def calculate_entropy(text: str) -> float:
    """Calculates Shannon entropy of string to detect algorithmic randomization."""
    if not text:
        return 0.0
    freq = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1
    entropy = 0.0
    length = len(text)
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 3)


def check_homograph_attack(hostname: str) -> HomographFinding:
    """
    Detects Internationalized Domain Name (IDN) homograph attacks where Cyrillic
    or foreign unicode glyphs mimic Latin alphabet characters.
    """
    has_homograph = False
    scripts_detected = []
    spoofed = []
    punycode = None
    explanation = None

    if hostname.startswith("xn--") or ".xn--" in hostname:
        punycode = hostname
        has_homograph = True
        scripts_detected.append("Punycode (IDN)")
        try:
            decoded = hostname.encode('ascii').decode('idna')
            explanation = f"Punycode encoded domain decodes to: '{decoded}', indicating potential visual spoofing."
        except Exception:
            explanation = "Punycode encoded domain detected."

    for char in hostname:
        if char in CYRILLIC_LOOKALIKES:
            has_homograph = True
            if "Cyrillic Script" not in scripts_detected:
                scripts_detected.append("Cyrillic Script")
            spoofed.append(f"'{char}' mimics Latin '{CYRILLIC_LOOKALIKES[char]}'")

    if has_homograph and not explanation:
        explanation = f"Detected mixed-script visual homoglyphs: {', '.join(spoofed[:4])}. Attackers use these to impersonate legitimate brands."

    return HomographFinding(
        has_homograph=has_homograph,
        punycode=punycode,
        scripts_detected=scripts_detected,
        spoofed_characters=spoofed,
        explanation=explanation
    )


def levenshtein_distance(s1: str, s2: str) -> int:
    """Computes Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


def check_typosquatting(domain: str, subdomain: str) -> TyposquattingFinding:
    """
    Inspects domain and subdomain for typosquatting targeting protected brands:
    - Character swaps (e.g. paypa1, micros0ft)
    - Omission / addition (e.g. googel, amzon)
    - Brand embedded in subdomain (e.g. paypal.security-login.com)
    """
    clean_domain = domain.lower()
    
    # 1. Direct brand impersonation in subdomain
    for brand in PROTECTED_BRANDS:
        if brand in subdomain.lower().split("."):
            return TyposquattingFinding(
                is_typosquat=True,
                targeted_brand=brand.title(),
                similarity_score=95.0,
                technique="Subdomain Brand Hijacking",
                explanation=f"Brand '{brand.title()}' is embedded in the subdomain while hosted on an unrelated root domain '{domain}'."
            )

    # 2. Levenshtein edit distance on SLD
    for brand in PROTECTED_BRANDS:
        if clean_domain == brand:
            # Exact legitimate brand domain
            return TyposquattingFinding(is_typosquat=False)

        dist = levenshtein_distance(clean_domain, brand)
        if 1 <= dist <= 2 and len(clean_domain) >= 4:
            similarity = round(100.0 - (dist / max(len(clean_domain), len(brand)) * 100), 1)
            return TyposquattingFinding(
                is_typosquat=True,
                targeted_brand=brand.title(),
                similarity_score=similarity,
                technique="Edit Distance Typosquatting",
                explanation=f"Domain '{domain}' is suspiciously close to recognized brand '{brand.title()}' (Edit distance: {dist})."
            )

        # Common number-for-letter substitutions
        substituted = clean_domain.replace("0", "o").replace("1", "l").replace("rn", "m").replace("vv", "w")
        if substituted == brand:
            return TyposquattingFinding(
                is_typosquat=True,
                targeted_brand=brand.title(),
                similarity_score=98.0,
                technique="Character Substitution Spoofing",
                explanation=f"Domain '{domain}' uses visual glyph substitution to disguise imitation of '{brand.title()}'."
            )

    return TyposquattingFinding(is_typosquat=False)


def resolve_dns_records(hostname: str) -> DNSRecords:
    """Performs DNS queries for A, AAAA, MX, NS, and TXT records with dnspython."""
    a_records = []
    aaaa_records = []
    mx_records = []
    ns_records = []
    txt_records = []
    resolved_ip = None

    resolver = dns.resolver.Resolver()
    resolver.timeout = 2.0
    resolver.lifetime = 3.0

    has_records = False
    try:
        answers = resolver.resolve(hostname, "A")
        for rdata in answers:
            a_records.append(str(rdata))
        if a_records:
            resolved_ip = a_records[0]
            has_records = True
    except Exception:
        pass

    try:
        answers = resolver.resolve(hostname, "AAAA")
        for rdata in answers:
            aaaa_records.append(str(rdata))
            has_records = True
    except Exception:
        pass

    # Only query MX/NS/TXT if domain actually has active A or AAAA records
    if has_records:
        try:
            answers = resolver.resolve(hostname, "MX")
            for rdata in answers:
                mx_records.append(f"{rdata.exchange} (Priority: {rdata.preference})")
        except Exception:
            pass

        try:
            answers = resolver.resolve(hostname, "NS")
            for rdata in answers:
                ns_records.append(str(rdata.target))
        except Exception:
            pass

        try:
            answers = resolver.resolve(hostname, "TXT")
            for rdata in answers:
                txt_records.append(str(rdata))
        except Exception:
            pass

    return DNSRecords(
        a_records=a_records,
        aaaa_records=aaaa_records,
        mx_records=mx_records[:5],
        ns_records=ns_records[:5],
        txt_records=txt_records[:5],
        resolved_ip=resolved_ip,
        lookup_status="Resolved" if (a_records or aaaa_records) else "No A/AAAA records"
    )


async def inspect_redirect_chain(start_url: str, max_hops: int = 5) -> List[RedirectHop]:
    """
    Follows redirect chain hop-by-hop, verifying SSRF compliance at EVERY hop
    and recording status code, location, and destination IP with connection-time IP pinning.
    """
    hops: List[RedirectHop] = []
    current_url = start_url

    transport = create_ssrf_safe_transport(verify=True)
    async with httpx.AsyncClient(transport=transport, verify=True, timeout=5.0, follow_redirects=False) as client:
        for hop_idx in range(1, max_hops + 1):
            is_safe, reason, resolved_ip = validate_url_for_ssrf(current_url)
            if not is_safe:
                hops.append(RedirectHop(
                    hop_number=hop_idx,
                    url=current_url,
                    status_code=403,
                    resolved_ip=resolved_ip or "Blocked",
                    response_time_ms=0.0,
                    is_safe=False
                ))
                break

            t0 = datetime.datetime.now()
            try:
                resp = await client.head(current_url)
                if resp.status_code == 405:
                    async with client.stream("GET", current_url, headers={"Range": "bytes=0-1024"}) as stream_resp:
                        _ = await anext(stream_resp.aiter_bytes(1024), b"")
                        status_code = stream_resp.status_code
                        headers = stream_resp.headers
                else:
                    status_code = resp.status_code
                    headers = resp.headers
                elapsed_ms = round((datetime.datetime.now() - t0).total_seconds() * 1000, 2)
            except Exception:
                hops.append(RedirectHop(
                    hop_number=hop_idx,
                    url=current_url,
                    status_code=0,
                    resolved_ip=resolved_ip or "0.0.0.0",
                    response_time_ms=0.0,
                    is_safe=False
                ))
                break

            hops.append(RedirectHop(
                hop_number=hop_idx,
                url=current_url,
                status_code=status_code,
                resolved_ip=resolved_ip or "0.0.0.0",
                response_time_ms=elapsed_ms,
                is_safe=True
            ))

            if status_code in (301, 302, 303, 307, 308) and "location" in headers:
                next_url = headers["location"]
                current_url = urljoin(current_url, next_url)
            else:
                break

    return hops


async def analyze_url(raw_url: str, db: Session, deep_scan: bool = True) -> URLScanResponse:
    """
    Main URL threat analysis engine:
    - SSRF verification
    - Normalization & domain extraction
    - Typosquatting & Homograph checks
    - Pattern heuristics
    - DNS queries
    - Redirect chain analysis
    - Threat intelligence feeds
    - Risk scoring and evidence compilation
    """
    scan_id = str(uuid.uuid4())
    timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
    evidence: List[EvidenceItem] = []
    recommendations: List[RecommendedAction] = []
    suspicious_patterns: List[str] = []

    # 1. Normalization
    normalized_url, scheme, hostname = normalize_url(raw_url)

    # 2. SSRF Protection Validation
    is_safe_ssrf, ssrf_reason, primary_ip = validate_url_for_ssrf(normalized_url)
    if not is_safe_ssrf:
        evidence.append(EvidenceItem(
            category="Infrastructure Security",
            indicator="Prohibited IP / SSRF Vector",
            description=ssrf_reason,
            severity=RiskLevel.CONFIRMED_MALICIOUS,
            source="WebSentinel SSRF Guard"
        ))
        recommendations.append(RecommendedAction(
            title="Block Connection Immediately",
            priority="Critical",
            action="Do not communicate with this address. It attempts to access internal or reserved infrastructure."
        ))
        
        canonical_payload = {
            "target": raw_url,
            "scan_type": "url",
            "risk_level": "CONFIRMED MALICIOUS",
            "risk_score": 100,
            "findings_digest": ssrf_reason,
            "timestamp_utc": timestamp
        }
        canonical_hash = "0x" + hashlib.sha256(json.dumps(canonical_payload, sort_keys=True).encode()).hexdigest()

        return URLScanResponse(
            id=scan_id,
            submitted_url=raw_url,
            normalized_url=normalized_url,
            scheme=scheme,
            risk_level=RiskLevel.CONFIRMED_MALICIOUS,
            risk_score=100,
            security_score=SecurityScore(score=0, grade="F", risk_level=RiskLevel.CONFIRMED_MALICIOUS, label="Severe Threat"),
            domain_info=DomainInfo(
                raw_domain=hostname,
                subdomain="",
                domain=hostname,
                suffix="",
                registered_domain=hostname,
                is_ip=True,
                entropy=0.0,
                length=len(hostname)
            ),
            typosquatting=TyposquattingFinding(is_typosquat=False),
            homograph=HomographFinding(has_homograph=False),
            suspicious_patterns=["SSRF / Private network targeting"],
            dns=DNSRecords(),
            redirect_chain=[],
            threat_intel=[],
            evidence=evidence,
            recommendations=recommendations,
            canonical_hash=canonical_hash,
            timestamp=timestamp
        )

    # 3. Domain decomposition
    extracted = tld_extractor(hostname)
    domain_name = extracted.domain
    suffix = extracted.suffix
    subdomain = extracted.subdomain
    registered_domain = getattr(extracted, "top_domain_under_public_suffix", None) or extracted.registered_domain or hostname

    # Entropy & Length analysis
    entropy = calculate_entropy(hostname)
    length = len(hostname)
    tld_tier = "High-Risk" if suffix in SUSPICIOUS_TLDS else "Standard"

    domain_info = DomainInfo(
        raw_domain=hostname,
        subdomain=subdomain,
        domain=domain_name,
        suffix=suffix,
        registered_domain=registered_domain,
        is_ip=bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", hostname)),
        entropy=entropy,
        length=length,
        tld_risk_tier=tld_tier
    )

    # 4. Homograph & Typosquatting Analysis
    homograph_res = check_homograph_attack(hostname)
    if homograph_res.has_homograph:
        evidence.append(EvidenceItem(
            category="Domain Obfuscation",
            indicator="Homograph / IDN Spoofing",
            description=homograph_res.explanation or "Contains mixed-script lookalikes.",
            severity=RiskLevel.HIGH,
            source="WebSentinel Homograph Engine"
        ))

    typosquat_res = check_typosquatting(domain_name, subdomain)
    if typosquat_res.is_typosquat:
        evidence.append(EvidenceItem(
            category="Brand Impersonation",
            indicator=f"Targeting {typosquat_res.targeted_brand}",
            description=typosquat_res.explanation or "Typosquatting detected.",
            severity=RiskLevel.HIGH,
            source="WebSentinel Typosquatting Detector"
        ))

    # 5. Pattern heuristics
    if domain_info.is_ip:
        suspicious_patterns.append("Host utilizes raw IP address instead of registered domain name")
        evidence.append(EvidenceItem(
            category="Evasion Techniques",
            indicator="Direct IP Addressing",
            description="Legitimate consumer services rarely utilize raw IP URLs.",
            severity=RiskLevel.SUSPICIOUS,
            source="WebSentinel Heuristic Core"
        ))

    if suffix in SUSPICIOUS_TLDS:
        suspicious_patterns.append(f"Domain is registered on high-abuse TLD: .{suffix}")
        evidence.append(EvidenceItem(
            category="Domain Reputation",
            indicator=f"High-Abuse TLD (.{suffix})",
            description=f"The top-level domain .{suffix} exhibits a disproportionately elevated rate of spam and phishing.",
            severity=RiskLevel.SUSPICIOUS,
            source="WebSentinel TLD Reputation"
        ))

    if entropy > 4.2 and len(hostname) > 15:
        suspicious_patterns.append("Elevated Shannon entropy suggests machine-generated DGA domain")
        evidence.append(EvidenceItem(
            category="Algorithmic Signatures",
            indicator="High Shannon Entropy",
            description="Domain naming structure resembles Domain Generation Algorithms (DGA) used by malware.",
            severity=RiskLevel.SUSPICIOUS,
            source="WebSentinel Entropy Analyzer"
        ))

    # Keyword inspection in subdomains and path
    url_lower = normalized_url.lower()
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in subdomain.lower() or f"/{kw}" in url_lower:
            suspicious_patterns.append(f"Security/auth keyword detected in URL structure: '{kw}'")

    if "@" in normalized_url:
        suspicious_patterns.append("Embedded credential sign ('@') detected in URL authority")
        evidence.append(EvidenceItem(
            category="Social Engineering",
            indicator="Credential Smuggling In URL",
            description="Use of '@' in URL structure attempts to confuse browsers into redirecting to unexpected endpoints.",
            severity=RiskLevel.HIGH,
            source="WebSentinel URL Parser"
        ))

    # 6. DNS Resolution
    dns_records = resolve_dns_records(hostname)

    # 7. Redirect Chain Inspection
    redirect_chain: List[RedirectHop] = []
    if deep_scan:
        try:
            redirect_chain = await inspect_redirect_chain(normalized_url)
            if len(redirect_chain) > 3:
                suspicious_patterns.append(f"Excessive redirect hops detected ({len(redirect_chain)} hops)")
        except Exception:
            pass

    # 8. Threat Intelligence Lookup
    threat_intel = await check_threat_intelligence(
        db=db,
        domain=registered_domain,
        ip=primary_ip or dns_records.resolved_ip,
        url=normalized_url
    )

    # Check if any threat feed flagged it
    flagged_sources = [s for s in threat_intel if s.is_flagged]
    if flagged_sources:
        for s in flagged_sources:
            evidence.append(EvidenceItem(
                category="Threat Intelligence Match",
                indicator=s.source_name,
                description=s.details or "Target indicator is actively listed as malicious.",
                severity=RiskLevel.CONFIRMED_MALICIOUS,
                source=s.source_name
            ))

    # 9. Compute Overall Risk Level and Risk Score
    risk_score = 0
    if flagged_sources:
        risk_score = 98
        risk_level = RiskLevel.CONFIRMED_MALICIOUS
    elif typosquat_res.is_typosquat and homograph_res.has_homograph:
        risk_score = 92
        risk_level = RiskLevel.HIGH
    elif typosquat_res.is_typosquat or homograph_res.has_homograph:
        risk_score = 75
        risk_level = RiskLevel.HIGH
    else:
        # Heuristic scoring
        base_score = 5
        if domain_info.is_ip:
            base_score += 25
        if suffix in SUSPICIOUS_TLDS:
            base_score += 20
        if entropy > 4.2:
            base_score += 15
        if len(suspicious_patterns) > 2:
            base_score += 20
        if not dns_records.a_records and not dns_records.aaaa_records:
            base_score += 10

        risk_score = min(85, base_score)
        if risk_score >= 60:
            risk_level = RiskLevel.HIGH
        elif risk_score >= 30:
            risk_level = RiskLevel.SUSPICIOUS
        else:
            risk_level = RiskLevel.LOW

    # 10. Generate Security Score Grade
    if risk_score >= 85:
        sec_score = SecurityScore(score=100 - risk_score, grade="F", risk_level=risk_level, label="Severe Threat")
    elif risk_score >= 60:
        sec_score = SecurityScore(score=100 - risk_score, grade="D", risk_level=risk_level, label="Elevated Risk")
    elif risk_score >= 30:
        sec_score = SecurityScore(score=100 - risk_score, grade="C", risk_level=risk_level, label="Suspicious Posture")
    elif risk_score >= 15:
        sec_score = SecurityScore(score=100 - risk_score, grade="B", risk_level=risk_level, label="Acceptable")
    else:
        sec_score = SecurityScore(score=100 - risk_score, grade="A+", risk_level=risk_level, label="Clean / Benign")

    # 11. Recommendations
    if risk_level == RiskLevel.CONFIRMED_MALICIOUS:
        recommendations.append(RecommendedAction(
            title="Block and Blacklist Domain",
            priority="Critical",
            action="Immediately block this domain at firewall, DNS filter, and endpoint EDR layers."
        ))
        recommendations.append(RecommendedAction(
            title="Revoke Compromised Credentials",
            priority="Critical",
            action="If users may have entered credentials on this URL, immediately initiate password resets and terminate active sessions."
        ))
    elif risk_level == RiskLevel.HIGH:
        recommendations.append(RecommendedAction(
            title="Isolate from Corporate Network",
            priority="High",
            action="Restrict access and warn end users against submitting financial or login details."
        ))
    elif risk_level == RiskLevel.SUSPICIOUS:
        recommendations.append(RecommendedAction(
            title="Exercise Caution and Verify Identity",
            priority="Medium",
            action="Inspect sender communication context and do not download executable files or provide personal data."
        ))
    else:
        recommendations.append(RecommendedAction(
            title="Standard Browsing Precautions",
            priority="Informational",
            action="No active threat signals detected. Ensure HTTPS certificate remains valid during transactions."
        ))

    # 12. Generate Canonical Fingerprint for Blockchain Verification
    canonical_payload = {
        "target": normalized_url,
        "scan_type": "url",
        "risk_level": risk_level.value,
        "risk_score": risk_score,
        "findings_digest": f"{len(evidence)} evidence items; {len(suspicious_patterns)} suspicious indicators",
        "timestamp_utc": timestamp
    }
    canonical_hash = "0x" + hashlib.sha256(json.dumps(canonical_payload, sort_keys=True).encode()).hexdigest()

    return URLScanResponse(
        id=scan_id,
        submitted_url=raw_url,
        normalized_url=normalized_url,
        scheme=scheme,
        risk_level=risk_level,
        risk_score=risk_score,
        security_score=sec_score,
        domain_info=domain_info,
        typosquatting=typosquat_res,
        homograph=homograph_res,
        suspicious_patterns=suspicious_patterns,
        dns=dns_records,
        redirect_chain=redirect_chain,
        threat_intel=threat_intel,
        evidence=evidence,
        recommendations=recommendations,
        canonical_hash=canonical_hash,
        timestamp=timestamp
    )
