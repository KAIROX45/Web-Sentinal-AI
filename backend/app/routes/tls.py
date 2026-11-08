import json
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.scan_history import ScanRecord
from app.schemas.tls import TLSScanRequest, TLSScanResponse
from app.services.tls_analyzer import inspect_tls_certificate

router = APIRouter(prefix="/tls", tags=["TLS Inspection"])


@router.post("/inspect", response_model=TLSScanResponse)
def inspect_tls(req: TLSScanRequest, db: Session = Depends(get_db)):
    """
    Directly connects to target host:port, extracts TLS certificates,
    evaluates validity, cipher suite, chain nodes, expiration, and RFC hostname matching.
    """
    if not req.hostname or not req.hostname.strip():
        raise HTTPException(status_code=400, detail="Hostname cannot be empty")

    try:
        result = inspect_tls_certificate(req.hostname, port=req.port)

        # Persist to Investigation History
        scan_record = ScanRecord(
            id=result.id,
            target=f"{result.hostname}:{result.port}",
            scan_type="tls",
            risk_level=result.risk_level.value,
            risk_score=result.risk_score,
            summary=f"TLS Certificate issued by {result.issuer_cn or 'CA'}. Protocol: {result.protocol_version}. Days remaining: {result.days_remaining}.",
            evidence_json=json.dumps([{"category": "TLS Security", "indicator": w, "description": w, "severity": result.risk_level.value} for w in result.warnings]),
            recommendations_json=json.dumps([]),
            raw_data_json=json.dumps(result.model_dump()),
            blockchain_hash=result.canonical_hash
        )
        db.add(scan_record)
        db.commit()

        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except TimeoutError as e:
        raise HTTPException(status_code=504, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"TLS inspection error: {str(e)}")

