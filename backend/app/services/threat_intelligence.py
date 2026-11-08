import httpx
import logging
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session
from app.config import settings
from app.models.threat_ioc import ThreatIOC
from app.schemas.url import ThreatIntelSource
from app.schemas.common import RiskLevel

logger = logging.getLogger("websentinel.threat_intel")

# Pre-seeded curated IOC database for cyber intelligence analysis
DEFAULT_IOC_DATA = [
    {
        "ioc_value": "paypa1-security-verification.com",
        "ioc_type": "domain",
        "threat_category": "credential_theft",
        "severity": "CONFIRMED MALICIOUS",
        "source": "WebSentinel Global Threat Feed",
        "description": "Active typosquatting credential harvesting campaign targeting PayPal users.",
        "confidence": 99
    },
    {
        "ioc_value": "appleid-recovery-alert.top",
        "ioc_type": "domain",
        "threat_category": "brand_impersonation",
        "severity": "CONFIRMED MALICIOUS",
        "source": "WebSentinel Global Threat Feed",
        "description": "SMS smishing landing page mimicking Apple iCloud lock screen to steal 2FA OTP codes.",
        "confidence": 98
    },
    {
        "ioc_value": "metamask-seed-validation.io",
        "ioc_type": "domain",
        "threat_category": "crypto_scam",
        "severity": "CONFIRMED MALICIOUS",
        "source": "Cryptocurrency Fraud Consortium",
        "description": "Web3 wallet drainer designed to harvest 12-word BIP39 seed phrases.",
        "confidence": 100
    },
    {
        "ioc_value": "secure-login-chasebank.xyz",
        "ioc_type": "domain",
        "threat_category": "phishing",
        "severity": "CONFIRMED MALICIOUS",
        "source": "Financial Cyber Coalition",
        "description": "Fake banking portal designed to harvest online banking usernames, passwords, and security questions.",
        "confidence": 99
    },
    {
        "ioc_value": "netflix-billing-update-urgent.com",
        "ioc_type": "domain",
        "threat_category": "payment_fraud",
        "severity": "HIGH",
        "source": "PhishTank Threat Exchange",
        "description": "Subscription cancellation lure requesting credit card numbers and CVV codes.",
        "confidence": 94
    },
    {
        "ioc_value": "dhl-express-tracking-delivery.info",
        "ioc_type": "domain",
        "threat_category": "package_smishing",
        "severity": "HIGH",
        "source": "Postal Threat Intelligence",
        "description": "Package customs fee scam requesting small payment to initiate recurring credit card charges.",
        "confidence": 92
    },
    {
        "ioc_value": "185.220.101.5",
        "ioc_type": "ip",
        "threat_category": "tor_exit_abuse",
        "severity": "SUSPICIOUS",
        "source": "AbuseIPDB Verified Feed",
        "description": "Tor exit node frequently utilized for automated brute-force attempts and web scrapers.",
        "confidence": 85
    },
    {
        "ioc_value": "45.154.255.89",
        "ioc_type": "ip",
        "threat_category": "malware_c2",
        "severity": "CONFIRMED MALICIOUS",
        "source": "MalwareBazaar Botnet Feed",
        "description": "Command and control server associated with RedLine Infostealer payload delivery.",
        "confidence": 98
    },
    {
        "ioc_value": "194.26.29.112",
        "ioc_type": "ip",
        "threat_category": "bulletproof_hosting",
        "severity": "HIGH",
        "source": "WebSentinel Infrastructure Intel",
        "description": "Autonomous System bulletproof hosting range associated with illicit phishing kits.",
        "confidence": 91
    },
    {
        "ioc_value": "update-windows11-patch.xyz",
        "ioc_type": "domain",
        "threat_category": "malware_distribution",
        "severity": "CONFIRMED MALICIOUS",
        "source": "ThreatConnect Intel",
        "description": "Trojanized executable masquerading as critical Windows security update.",
        "confidence": 97
    }
]


def seed_ioc_database(db: Session):
    """Initializes the database with pre-seeded curated threat IOCs if empty."""
    try:
        count = db.query(ThreatIOC).count()
        now_utc = datetime.now(timezone.utc).replace(tzinfo=None)
        if count == 0:
            logger.info("Seeding initial threat IOC database with curated threat intelligence...")
            for item in DEFAULT_IOC_DATA:
                ioc = ThreatIOC(
                    ioc_value=item["ioc_value"].lower(),
                    ioc_type=item["ioc_type"],
                    threat_category=item["threat_category"],
                    severity=item["severity"],
                    source=item["source"],
                    description=item["description"],
                    confidence=item["confidence"],
                    is_demo=True,
                    first_seen=now_utc - timedelta(days=14),
                    last_seen=now_utc,
                    is_active=True
                )
                db.add(ioc)
            db.commit()
            logger.info(f"Successfully seeded {len(DEFAULT_IOC_DATA)} threat IOCs.")
        else:
            # Ensure existing seed records have is_demo correctly set
            db.query(ThreatIOC).filter(ThreatIOC.is_demo == None).update({ThreatIOC.is_demo: True})
            db.commit()
    except Exception as e:
        logger.error(f"Error seeding IOC database: {e}")
        db.rollback()


def query_local_ioc(db: Session, target: str) -> Optional[ThreatIOC]:
    """Queries local ThreatIOC table for exact or subdomain matches."""
    cleaned = target.strip().lower()
    # Strip protocols and paths if passed
    if "://" in cleaned:
        cleaned = cleaned.split("://")[1].split("/")[0].split(":")[0]

    match = db.query(ThreatIOC).filter(
        ThreatIOC.ioc_value == cleaned,
        ThreatIOC.is_active == True
    ).first()

    if match:
        return match

    # Subdomain check: if user provided test.paypa1-security-verification.com
    parts = cleaned.split(".")
    if len(parts) > 2:
        parent_domain = ".".join(parts[-2:])
        match = db.query(ThreatIOC).filter(
            ThreatIOC.ioc_value == parent_domain,
            ThreatIOC.is_active == True
        ).first()
        if match:
            return match

    return None


async def check_threat_intelligence(
    db: Session,
    domain: str,
    ip: Optional[str] = None,
    url: Optional[str] = None
) -> List[ThreatIntelSource]:
    """
    Checks multiple threat intelligence providers:
    1. WebSentinel AI Local IOC Database (Active & Persistent)
    2. Google Safe Browsing API (if API key configured)
    3. VirusTotal API (if API key configured)
    """
    sources: List[ThreatIntelSource] = []

    # 1. WebSentinel Curated IOC Feed
    local_match = query_local_ioc(db, domain)
    if not local_match and ip:
        local_match = query_local_ioc(db, ip)
    if not local_match and url:
        local_match = query_local_ioc(db, url)

    if local_match:
        is_demo_entry = bool(getattr(local_match, "is_demo", False))
        attribution_tag = " [Demo/Seed Indicator]" if is_demo_entry else ""
        source_label = f"{local_match.source}{attribution_tag}"
        sources.append(ThreatIntelSource(
            source_name="WebSentinel Threat Feed",
            checked=True,
            is_flagged=True,
            category=local_match.threat_category,
            details=f"{local_match.severity}: {local_match.description} (Confidence: {local_match.confidence}%){attribution_tag}",
            status_note=f"Flagged by {source_label}"
        ))
    else:
        sources.append(ThreatIntelSource(
            source_name="WebSentinel Threat Feed",
            checked=True,
            is_flagged=False,
            category=None,
            details="No matching indicator in WebSentinel threat database.",
            status_note="Clean in local IOC registry"
        ))

    # 2. Google Safe Browsing API
    if settings.GOOGLE_SAFE_BROWSING_API_KEY:
        try:
            gsb_result = await _query_google_safe_browsing(url or f"https://{domain}")
            sources.append(gsb_result)
        except Exception as e:
            sources.append(ThreatIntelSource(
                source_name="Google Safe Browsing",
                checked=False,
                is_flagged=False,
                category=None,
                details=f"Lookup failed: {str(e)}",
                status_note="API lookup error"
            ))
    else:
        sources.append(ThreatIntelSource(
            source_name="Google Safe Browsing",
            checked=False,
            is_flagged=False,
            category=None,
            details="API key not configured in environment (GOOGLE_SAFE_BROWSING_API_KEY).",
            status_note="Not configured (Optional)"
        ))

    # 3. VirusTotal API
    if settings.VIRUSTOTAL_API_KEY:
        try:
            vt_result = await _query_virustotal(domain)
            sources.append(vt_result)
        except Exception as e:
            sources.append(ThreatIntelSource(
                source_name="VirusTotal Intelligence",
                checked=False,
                is_flagged=False,
                category=None,
                details=f"Lookup failed: {str(e)}",
                status_note="API lookup error"
            ))
    else:
        sources.append(ThreatIntelSource(
            source_name="VirusTotal Intelligence",
            checked=False,
            is_flagged=False,
            category=None,
            details="API key not configured in environment (VIRUSTOTAL_API_KEY).",
            status_note="Not configured (Optional)"
        ))

    return sources


async def _query_google_safe_browsing(target_url: str) -> ThreatIntelSource:
    endpoint = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
    headers = {
        "x-goog-api-key": settings.GOOGLE_SAFE_BROWSING_API_KEY,
        "Content-Type": "application/json"
    }
    payload = {
        "client": {
            "clientId": "websentinel-scanner",
            "clientVersion": "1.0.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": target_url}]
        }
    }
    async with httpx.AsyncClient(timeout=4.0) as client:
        resp = await client.post(endpoint, json=payload, headers=headers)
        if resp.status_code == 200:
            data = resp.json()
            matches = data.get("matches", [])
            if matches:
                first = matches[0]
                threat_type = first.get("threatType", "THREAT")
                return ThreatIntelSource(
                    source_name="Google Safe Browsing",
                    checked=True,
                    is_flagged=True,
                    category=threat_type,
                    details=f"Flagged as {threat_type} on Google Safe Browsing list.",
                    status_note="Malicious Match Found"
                )
            return ThreatIntelSource(
                source_name="Google Safe Browsing",
                checked=True,
                is_flagged=False,
                details="No threats identified on Google Safe Browsing lists.",
                status_note="Clean"
            )
        return ThreatIntelSource(
            source_name="Google Safe Browsing",
            checked=False,
            is_flagged=False,
            details=f"API returned status {resp.status_code}",
            status_note="Query Error"
        )


async def _query_virustotal(domain: str) -> ThreatIntelSource:
    endpoint = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": settings.VIRUSTOTAL_API_KEY}
    async with httpx.AsyncClient(timeout=4.0) as client:
        resp = await client.get(endpoint, headers=headers)
        if resp.status_code == 200:
            data = resp.json()
            attributes = data.get("data", {}).get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            if malicious > 0 or suspicious > 2:
                return ThreatIntelSource(
                    source_name="VirusTotal Intelligence",
                    checked=True,
                    is_flagged=True,
                    category="multiscanner_flag",
                    details=f"Flagged by {malicious} security vendors as malicious ({suspicious} suspicious).",
                    status_note="Vendor Flags Detected"
                )
            return ThreatIntelSource(
                source_name="VirusTotal Intelligence",
                checked=True,
                is_flagged=False,
                details=f"Scanned across {sum(stats.values())} security vendor engines without malicious flags.",
                status_note="Clean"
            )
        return ThreatIntelSource(
            source_name="VirusTotal Intelligence",
            checked=False,
            is_flagged=False,
            details=f"VirusTotal API returned HTTP {resp.status_code}",
            status_note="Query Failed"
        )

