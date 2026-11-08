import json
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.scan_history import ScanRecord
from app.schemas.url import URLScanRequest, URLScanResponse
from app.services.url_analyzer import analyze_url

router = APIRouter(prefix="/url", tags=["URL Investigation"])


@router.post("/scan", response_model=URLScanResponse)
async def scan_url(req: URLScanRequest, db: Session = Depends(get_db)):
    """
    Performs full cyber threat analysis on submitted URL:
    SSRF validation, domain extraction, typosquatting, homographs,
    DNS queries, redirect chain, and threat intelligence.
    """
    if not req.url or not req.url.strip():
        raise HTTPException(status_code=400, detail="URL cannot be empty")

    try:
        result = await analyze_url(req.url, db=db, deep_scan=req.deep_scan)

        # Persist to Investigation History
        evidence_dicts = [e.model_dump() for e in result.evidence]
        recs_dicts = [r.model_dump() for r in result.recommendations]

        scan_record = ScanRecord(
            id=result.id,
            target=result.submitted_url,
            scan_type="url",
            risk_level=result.risk_level.value,
            risk_score=result.risk_score,
            summary=f"Analyzed {result.domain_info.registered_domain}. Identified {len(result.evidence)} evidence items and {len(result.suspicious_patterns)} suspicious patterns.",
            evidence_json=json.dumps(evidence_dicts),
            recommendations_json=json.dumps(recs_dicts),
            raw_data_json=json.dumps(result.model_dump()),
            blockchain_hash=result.canonical_hash
        )
        db.add(scan_record)
        db.commit()

        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"URL analysis error: {str(e)}")

