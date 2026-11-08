import json
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.scan_history import ScanRecord
from app.schemas.ip import IPScanRequest, IPScanResponse
from app.services.ip_analyzer import analyze_ip

router = APIRouter(prefix="/ip", tags=["IP Intelligence"])


@router.post("/scan", response_model=IPScanResponse)
async def scan_ip(req: IPScanRequest, db: Session = Depends(get_db)):
    """
    Investigates IP address:
    IPv4/IPv6 classification, SSRF protection for private ranges,
    reverse DNS PTR, ASN ownership, geolocation, and abuse reputation.
    """
    if not req.ip_address or not req.ip_address.strip():
        raise HTTPException(status_code=400, detail="IP address cannot be empty")

    try:
        result = await analyze_ip(req.ip_address, db=db)

        # Persist to Investigation History
        evidence_dicts = [e.model_dump() for e in result.evidence]
        recs_dicts = [r.model_dump() for r in result.recommendations]

        scan_record = ScanRecord(
            id=result.id,
            target=result.ip_address,
            scan_type="ip",
            risk_level=result.risk_level.value,
            risk_score=result.reputation_score,
            summary=f"Investigated {result.ip_address} ({result.classification}). ASN: {result.network_info.asn_org or 'N/A'}. Country: {result.geo_info.country}.",
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
        raise HTTPException(status_code=500, detail=f"IP analysis error: {str(e)}")

