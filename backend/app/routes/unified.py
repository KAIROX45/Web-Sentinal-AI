import re
import json
import ipaddress
from typing import Dict, Any
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel

from app.database import get_db
from app.models.scan_history import ScanRecord
from app.services.url_analyzer import analyze_url
from app.services.ip_analyzer import analyze_ip
from app.services.gemini_analyzer import analyze_phishing_message

router = APIRouter(prefix="/unified", tags=["Unified Search & Classifier"])


class ClassifyRequest(BaseModel):
    query: str


class UnifiedScanRequest(BaseModel):
    query: str
    forced_type: str = "auto"  # auto, url, ip, message


def classify_input(text: str) -> Dict[str, Any]:
    """
    Classifies user input into:
    - 'ip': valid IPv4 or IPv6 format
    - 'url': starts with http/https or contains domain with valid TLD or path
    - 'email': contains email headers (From:, Subject:) or standard email format
    - 'sms': short text with delivery/urgent triggers or phone numbers
    - 'message': arbitrary scam / phishing text
    """
    cleaned = text.strip()

    # Check for IP address
    try:
        ipaddress.ip_address(cleaned)
        return {
            "type": "ip",
            "confidence": 1.0,
            "target": cleaned,
            "label": "IP Address",
            "route": "/ip"
        }
    except ValueError:
        pass

    # Check for explicit or implicit URL
    is_url = False
    if cleaned.startswith("http://") or cleaned.startswith("https://"):
        is_url = True
    elif re.match(r"^[a-zA-Z0-9-]+\.[a-zA-Z]{2,}(?:/[^\s]*)?$", cleaned):
        is_url = True
    elif " " not in cleaned and "." in cleaned and ("/" in cleaned or "?" in cleaned or len(cleaned.split(".")) >= 2):
        is_url = True

    if is_url:
        return {
            "type": "url",
            "confidence": 0.95,
            "target": cleaned,
            "label": "Website URL / Domain",
            "route": "/url"
        }

    # Check for email headers
    if any(h in cleaned for h in ("From:", "Subject:", "To:", "Received:", "Return-Path:")):
        return {
            "type": "message",
            "subtype": "email",
            "confidence": 0.9,
            "target": cleaned,
            "label": "Suspicious Email",
            "route": "/message"
        }

    # Check for SMS (length < 300 and contains typical SMS triggers like 'txt STOP', carrier notifications, etc.)
    if len(cleaned) < 300 and any(kw in cleaned.lower() for kw in ("stop to opt out", "reply stop", "msg&data", "tracking #", "usps:", "fedex:", "dhl:")):
        return {
            "type": "message",
            "subtype": "sms",
            "confidence": 0.88,
            "target": cleaned,
            "label": "SMS / Smishing Text",
            "route": "/message"
        }

    # Default to general scam / chat message analysis
    return {
        "type": "message",
        "subtype": "chat",
        "confidence": 0.8,
        "target": cleaned,
        "label": "Suspicious Message / Communication",
        "route": "/message"
    }


@router.post("/classify")
def classify_target(req: ClassifyRequest):
    """Detects input type for real-time frontend routing preview."""
    if not req.query or not req.query.strip():
        raise HTTPException(status_code=400, detail="Query cannot be empty")
    return classify_input(req.query)


@router.post("/scan")
async def execute_unified_scan(req: UnifiedScanRequest, db: Session = Depends(get_db)):
    """
    Automatically classifies submitted target and executes the appropriate analysis engine:
    URL analyzer, IP intelligence, or AI phishing/message analyzer.
    """
    if not req.query or not req.query.strip():
        raise HTTPException(status_code=400, detail="Query cannot be empty")

    classification = classify_input(req.query)
    scan_type = req.forced_type if req.forced_type != "auto" else classification["type"]

    if scan_type == "url":
        res = await analyze_url(req.query, db=db, deep_scan=True)
        evidence_dicts = [e.model_dump() for e in res.evidence]
        recs_dicts = [r.model_dump() for r in res.recommendations]
        scan_record = ScanRecord(
            id=res.id,
            target=res.submitted_url,
            scan_type="url",
            risk_level=res.risk_level.value,
            risk_score=res.risk_score,
            summary=f"Analyzed {res.domain_info.registered_domain}. Identified {len(res.evidence)} evidence items and {len(res.suspicious_patterns)} suspicious patterns.",
            evidence_json=json.dumps(evidence_dicts),
            recommendations_json=json.dumps(recs_dicts),
            raw_data_json=json.dumps(res.model_dump()),
            blockchain_hash=res.canonical_hash
        )
        db.add(scan_record)
        db.commit()
        return {"scan_type": "url", "classification": classification, "data": res.model_dump()}
    elif scan_type == "ip":
        res = await analyze_ip(req.query, db=db)
        evidence_dicts = [e.model_dump() for e in res.evidence]
        recs_dicts = [r.model_dump() for r in res.recommendations]
        scan_record = ScanRecord(
            id=res.id,
            target=res.ip_address,
            scan_type="ip",
            risk_level=res.risk_level.value,
            risk_score=res.reputation_score,
            summary=f"Investigated {res.ip_address} ({res.classification}). ASN: {res.network_info.asn_org or 'N/A'}. Country: {res.geo_info.country}.",
            evidence_json=json.dumps(evidence_dicts),
            recommendations_json=json.dumps(recs_dicts),
            raw_data_json=json.dumps(res.model_dump()),
            blockchain_hash=res.canonical_hash
        )
        db.add(scan_record)
        db.commit()
        return {"scan_type": "ip", "classification": classification, "data": res.model_dump()}
    else:
        res = await analyze_phishing_message(req.query, message_type=classification.get("subtype", "message"))
        evidence_dicts = [e.model_dump() for e in res.evidence]
        recs_dicts = [r.model_dump() for r in res.recommended_actions]
        scan_record = ScanRecord(
            id=res.id,
            target=req.query[:150] + ("..." if len(req.query) > 150 else ""),
            scan_type="message",
            risk_level=res.risk_level.value,
            risk_score=res.risk_score,
            summary=f"Analyzed {res.message_type} message. Category: {res.attack_category}. Engine: {res.source}.",
            evidence_json=json.dumps(evidence_dicts),
            recommendations_json=json.dumps(recs_dicts),
            raw_data_json=json.dumps(res.model_dump()),
            blockchain_hash=res.canonical_hash
        )
        db.add(scan_record)
        db.commit()
        return {"scan_type": "message", "classification": classification, "data": res.model_dump()}

