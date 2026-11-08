import json
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.scan_history import ScanRecord
from app.schemas.message import MessageScanRequest, MessageScanResponse
from app.services.gemini_analyzer import analyze_phishing_message

router = APIRouter(prefix="/message", tags=["AI Phishing Analyzer"])


@router.post("/analyze", response_model=MessageScanResponse)
async def analyze_message(req: MessageScanRequest, db: Session = Depends(get_db)):
    """
    AI-powered phishing and scam analyzer:
    Examines email, SMS, or chat content for psychological manipulation,
    extracted deceptive URLs, brand abuse, and social engineering coercion.
    """
    if not req.content or not req.content.strip():
        raise HTTPException(status_code=400, detail="Message content cannot be empty")

    try:
        result = await analyze_phishing_message(req.content, message_type=req.message_type)

        # Persist to Investigation History
        evidence_dicts = [e.model_dump() for e in result.evidence]
        recs_dicts = [r.model_dump() for r in result.recommended_actions]

        scan_record = ScanRecord(
            id=result.id,
            target=req.content[:150] + ("..." if len(req.content) > 150 else ""),
            scan_type="message",
            risk_level=result.risk_level.value,
            risk_score=result.risk_score,
            summary=f"Analyzed {result.message_type} message. Category: {result.attack_category}. Engine: {result.source}.",
            evidence_json=json.dumps(evidence_dicts),
            recommendations_json=json.dumps(recs_dicts),
            raw_data_json=json.dumps(result.model_dump()),
            blockchain_hash=result.canonical_hash
        )
        db.add(scan_record)
        db.commit()

        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Phishing analysis error: {str(e)}")

