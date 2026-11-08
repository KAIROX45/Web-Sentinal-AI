import os
import re
import json
import uuid
import hashlib
import logging
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Tuple
import tldextract
import httpx

tld_extractor = tldextract.TLDExtract(suffix_list_urls=())

from app.config import settings
from app.schemas.message import (
    MessageScanResponse, ExtractedUrlItem, SuspiciousEntity
)
from app.schemas.common import RiskLevel, EvidenceItem, RecommendedAction

logger = logging.getLogger("websentinel.gemini_analyzer")

# Predefined high-profile spoofed entities and brand signatures
KNOWN_TARGETED_BRANDS = [
    "Apple", "Microsoft", "Google", "PayPal", "Amazon", "Chase Bank",
    "Wells Fargo", "Bank of America", "Netflix", "USPS", "FedEx", "DHL",
    "Internal Revenue Service (IRS)", "Coinbase", "MetaMask", "Binance"
]

MANIPULATION_PATTERNS = [
    (r"(urgent|immediately|within 24 hours|action required|suspended within|final notice|account termination)", "Artificial Urgency & Fear Induction"),
    (r"(unauthorized transaction|fraudulent activity|suspicious login|unusual activity detected|security alert)", "Alarmist Security Alert Pretext"),
    (r"(verify your (password|identity|account|credentials|ssn|social security)|confirm your details|re-activate)", "Credential Harvesting Lure"),
    (r"(wire transfer|bitcoin|crypto|gift card|refund of \$|overdue invoice|payment remittance|customs fee)", "Financial Coercion or Scam Fee"),
    (r"(won|lottery|inheritance|selected to receive|exclusive prize|claim your \$)", "Unsolicited Financial Windfall Bait"),
    (r"(delivery failed|package pending|update delivery address|reschedule shipment)", "Postal / Delivery Smishing Pretext")
]


def extract_embedded_urls_and_contacts(text: str) -> Tuple[List[ExtractedUrlItem], List[SuspiciousEntity]]:
    """Extracts URLs, domains, and suspicious contact entities from message text."""
    urls: List[ExtractedUrlItem] = []
    entities: List[SuspiciousEntity] = []

    # Regex for URLs
    url_pattern = r'https?://[^\s<>"]+|www\.[^\s<>"]+'
    found_urls = re.findall(url_pattern, text)

    for raw_url in set(found_urls):
        url_to_parse = raw_url if raw_url.startswith("http") else f"https://{raw_url}"
        extracted = tld_extractor(url_to_parse)
        domain = getattr(extracted, "top_domain_under_public_suffix", None) or extracted.registered_domain or raw_url

        # Check if domain looks deceptive or mimics a brand
        is_suspicious = False
        indicator = None
        for brand in ["paypal", "apple", "chase", "netflix", "wellsfargo", "amazon", "microsoft", "usps"]:
            if brand in domain.lower() and not domain.lower().endswith(f"{brand}.com"):
                is_suspicious = True
                indicator = f"Domain mimics {brand.title()} but registers under third-party TLD"
                break

        if extracted.suffix in ("xyz", "top", "buzz", "work", "icu", "tk"):
            is_suspicious = True
            indicator = indicator or f"Suspicious high-abuse TLD .{extracted.suffix}"

        urls.append(ExtractedUrlItem(
            url=raw_url,
            domain=domain,
            is_suspicious=is_suspicious,
            risk_indicator=indicator
        ))

    # Regex for phone numbers
    phone_pattern = r'(\+?1[-.\s]?)?(\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4})'
    phones = re.findall(phone_pattern, text)
    for p in phones:
        full_phone = "".join(p).strip()
        if len(full_phone) >= 10:
            entities.append(SuspiciousEntity(
                entity=full_phone,
                entity_type="Callback Phone Number",
                context="Phone number listed in message; common vector in fake tech support or payment invoice fraud."
            ))

    # Brand detection
    text_lower = text.lower()
    for brand in KNOWN_TARGETED_BRANDS:
        if brand.lower() in text_lower:
            entities.append(SuspiciousEntity(
                entity=brand,
                entity_type="Impersonated Organization",
                context=f"Message references {brand} to establish false trust."
            ))

    return urls, entities


async def analyze_message_with_gemini(content: str, message_type: str = "auto") -> Optional[Dict[str, Any]]:
    """
    Calls Google Gemini API using structured JSON output to analyze cyber threat signals.
    """
    api_key = settings.GEMINI_API_KEY
    if not api_key:
        return None

    # Use Google Gemini REST endpoint (v1beta) with secure header authentication
    url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent"
    headers = {
        "x-goog-api-key": api_key,
        "Content-Type": "application/json"
    }
    
    prompt = f"""
You are WebSentinel AI Cyber Threat Intelligence Engine. Analyze the following message for phishing, scam, social engineering, or fraudulent intent.

Message Content:
\"\"\"
{content}
\"\"\"

Message Type Hint: {message_type}

You MUST reply ONLY with a valid JSON object matching this schema:
{{
  "risk_level": "LOW" | "SUSPICIOUS" | "HIGH",
  "confidence_score": <integer 0-100>,
  "attack_category": "<string category, e.g. Credential Harvesting Phishing, Invoice Fraud, Package Smishing, Benign Message>",
  "manipulation_techniques": ["<technique 1>", "<technique 2>"],
  "explanation": "<2-3 sentence technical explanation>",
  "evidence": [
    {{
      "category": "<category>",
      "indicator": "<indicator>",
      "description": "<detail>",
      "severity": "LOW" | "SUSPICIOUS" | "HIGH"
    }}
  ],
  "recommended_actions": [
    {{
      "title": "<action title>",
      "priority": "Critical" | "High" | "Medium" | "Informational",
      "action": "<action description>"
    }}
  ]
}}
IMPORTANT: Do NOT return markdown fences like ```json. Return ONLY raw JSON. Never output 'CONFIRMED MALICIOUS' solely from AI prediction; reserve that for verified external threat feeds.
"""

    payload = {
        "contents": [
            {
                "parts": [{"text": prompt}]
            }
        ],
        "generationConfig": {
            "temperature": 0.1,
            "responseMimeType": "application/json"
        }
    }

    try:
        async with httpx.AsyncClient(timeout=12.0) as client:
            resp = await client.post(url, json=payload, headers=headers)
            if resp.status_code == 200:
                data = resp.json()
                candidates = data.get("candidates", [])
                if candidates:
                    text_out = candidates[0].get("content", {}).get("parts", [{}])[0].get("text", "")
                    clean_text = text_out.strip()
                    if clean_text.startswith("```"):
                        clean_text = re.sub(r"^```(?:json)?\n", "", clean_text)
                        clean_text = re.sub(r"\n```$", "", clean_text)
                    return json.loads(clean_text)
            else:
                logger.warning(f"Gemini API returned status {resp.status_code}: {resp.text}")
                return None
    except Exception as e:
        logger.error(f"Gemini API invocation error: {e}")
        return None


def analyze_message_heuristics(content: str, message_type: str = "auto") -> Dict[str, Any]:
    """
    Deterministic rule-based cyber intelligence heuristic engine.
    Runs when Gemini API is unconfigured or unavailable, providing accurate threat detection.
    """
    manipulation_techniques = []
    evidence = []
    recommendations = []
    
    # Check manipulation techniques
    for pattern, technique_name in MANIPULATION_PATTERNS:
        match = re.search(pattern, content, re.IGNORECASE)
        if match:
            if technique_name not in manipulation_techniques:
                manipulation_techniques.append(technique_name)
            evidence.append({
                "category": "Social Engineering",
                "indicator": technique_name,
                "description": f"Trigger phrase detected: '{match.group(0)}'",
                "severity": "HIGH" if "Credential" in technique_name or "Financial" in technique_name else "SUSPICIOUS"
            })

    # Extracted URLs and phone numbers
    urls, entities = extract_embedded_urls_and_contacts(content)
    for u in urls:
        if u.is_suspicious:
            evidence.append({
                "category": "Embedded Infrastructure",
                "indicator": f"Suspicious Link ({u.domain})",
                "description": u.risk_indicator or "Embedded link exhibits deceptive domain characteristics.",
                "severity": "HIGH"
            })

    for e in entities:
        if e.entity_type == "Impersonated Organization" and manipulation_techniques:
            evidence.append({
                "category": "Identity Deception",
                "indicator": f"Brand Masquerading ({e.entity})",
                "description": f"Message purports to represent {e.entity} alongside coercive pressure tactics.",
                "severity": "HIGH"
            })

    # Classify Attack Category and Risk
    technique_count = len(manipulation_techniques)
    has_suspicious_url = any(u.is_suspicious for u in urls)

    if has_suspicious_url or (technique_count >= 2 and any("Credential" in t or "Financial" in t for t in manipulation_techniques)):
        risk_level = "HIGH"
        risk_score = 92 if has_suspicious_url else 85
        confidence_score = 92
        attack_category = "Credential Harvesting & Brand Phishing" if any("Credential" in t for t in manipulation_techniques) else "Urgent Financial Coercion Scam"
        explanation = f"High-confidence threat signature detected. The message employs {technique_count} psychological coercion patterns combined with deceptive infrastructure to manipulate the recipient."
        recommendations.append({
            "title": "Do NOT Click Links or Call Numbers",
            "priority": "Critical",
            "action": "Do not interact with any links, phone numbers, or attachments contained within this communication."
        })
        recommendations.append({
            "title": "Report and Delete",
            "priority": "High",
            "action": "Forward this message to your security operations team or abuse reporting provider and delete it."
        })
    elif technique_count >= 1:
        risk_level = "SUSPICIOUS"
        risk_score = 55
        confidence_score = 74
        attack_category = "Suspicious Social Engineering Lure"
        explanation = "The communication displays anomalous urgency or unverified claims typical of phishing lures, but lacks confirmed malicious infrastructure."
        recommendations.append({
            "title": "Verify Through Official Channels",
            "priority": "Medium",
            "action": "Navigate directly to the organization's verified official portal rather than following links in this message."
        })
    else:
        risk_level = "LOW"
        risk_score = 5
        confidence_score = 88
        attack_category = "Benign Communication"
        explanation = "No overt manipulation heuristics, credential requests, or deceptive threat indicators were identified in this content."
        recommendations.append({
            "title": "Maintain Standard Vigilance",
            "priority": "Informational",
            "action": "Ensure communications asking for sensitive credentials are authenticated through known independent channels."
        })

    return {
        "risk_level": risk_level,
        "risk_score": risk_score,
        "confidence_score": confidence_score,
        "attack_category": attack_category,
        "manipulation_techniques": manipulation_techniques,
        "explanation": explanation,
        "evidence": evidence,
        "recommended_actions": recommendations
    }


async def analyze_phishing_message(content: str, message_type: str = "auto") -> MessageScanResponse:
    """
    Main entry point for AI Phishing & Scam Analyzer:
    - Extracts URLs, contacts, and entities
    - Attempts Google Gemini API with structured cyber intelligence schema
    - Gracefully falls back to comprehensive rule-based heuristic engine if API key is not configured
    - Generates canonical SHA-256 fingerprint for blockchain verification
    """
    scan_id = str(uuid.uuid4())
    timestamp = datetime.now(timezone.utc).isoformat()
    urls, entities = extract_embedded_urls_and_contacts(content)

    source = "heuristic_engine"
    analysis_data = None

    if settings.GEMINI_API_KEY:
        try:
            analysis_data = await analyze_message_with_gemini(content, message_type)
            if analysis_data:
                source = "gemini_ai"
        except Exception as e:
            logger.warning(f"Fallback to heuristic engine after Gemini error: {e}")

    if not analysis_data:
        analysis_data = analyze_message_heuristics(content, message_type)

    # Map risk level
    raw_risk = analysis_data.get("risk_level", "LOW").upper()
    if raw_risk == "HIGH":
        risk_level = RiskLevel.HIGH
    elif raw_risk == "SUSPICIOUS":
        risk_level = RiskLevel.SUSPICIOUS
    else:
        risk_level = RiskLevel.LOW

    # Convert evidence items
    evidence_items = [
        EvidenceItem(
            category=ev.get("category", "General Security"),
            indicator=ev.get("indicator", "Indicator"),
            description=ev.get("description", ""),
            severity=RiskLevel(ev.get("severity", "LOW")) if ev.get("severity") in [r.value for r in RiskLevel] else RiskLevel.LOW,
            source="Gemini Cyber Reasoning" if source == "gemini_ai" else "WebSentinel AI Heuristic Core"
        )
        for ev in analysis_data.get("evidence", [])
    ]

    # Convert recommendations
    rec_items = [
        RecommendedAction(
            title=r.get("title", "Action"),
            priority=r.get("priority", "Medium"),
            action=r.get("action", "")
        )
        for r in analysis_data.get("recommended_actions", [])
    ]

    # Determine risk score accurately
    risk_score = analysis_data.get("risk_score")
    if risk_score is None:
        if risk_level == RiskLevel.HIGH:
            risk_score = 88
        elif risk_level == RiskLevel.SUSPICIOUS:
            risk_score = 55
        else:
            risk_score = 5

    # Canonical hash for blockchain verification
    canonical_payload = {
        "findings_digest": f"{analysis_data.get('attack_category', 'General')} - {len(evidence_items)} evidence flags",
        "risk_level": risk_level.value,
        "risk_score": risk_score,
        "scan_type": "message",
        "target": content[:120],
        "timestamp_utc": timestamp
    }
    canonical_hash = "0x" + hashlib.sha256(json.dumps(canonical_payload, sort_keys=True).encode()).hexdigest()

    return MessageScanResponse(
        id=scan_id,
        message_type=message_type if message_type != "auto" else ("email" if "@" in content else "message"),
        risk_level=risk_level,
        risk_score=risk_score,
        confidence_score=analysis_data.get("confidence_score", 85),
        attack_category=analysis_data.get("attack_category", "Cybersecurity Threat Analysis"),
        extracted_urls=urls,
        suspicious_entities=entities,
        manipulation_techniques=analysis_data.get("manipulation_techniques", []),
        explanation=analysis_data.get("explanation", "Analysis completed."),
        evidence=evidence_items,
        recommended_actions=rec_items,
        source=source,
        ai_disclaimer="AI-generated conclusions are probabilistic assessments and are maintained distinct from verified deterministic threat intelligence.",
        canonical_hash=canonical_hash,
        timestamp=timestamp
    )
