import json
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.scan_history import ScanRecord
from app.schemas.headers import HeaderScanRequest, HeaderScanResponse
from app.services.header_checker import inspect_http_headers

router = APIRouter(prefix="/headers", tags=["HTTP Security Headers"])


@router.post("/inspect", response_model=HeaderScanResponse)
async def check_headers(req: HeaderScanRequest, db: Session = Depends(get_db)):
    """
    Connects with SSRF validation to inspect HTTP response headers:
    HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy.
    """
    if not req.url or not req.url.strip():
        raise HTTPException(status_code=400, detail="Target URL cannot be empty")

    try:
        result = await inspect_http_headers(req.url)

        # Persist to Investigation History
        scan_record = ScanRecord(
            id=result.id,
            target=result.url,
            scan_type="headers",
            risk_level="SUSPICIOUS" if result.missing_count >= 3 else "LOW",
            risk_score=min(45, max(5, int((100 - result.security_score) * 0.45))),
            summary=f"Security headers evaluation. Optimal: {result.optimal_count}, Weak: {result.weak_count}, Missing: {result.missing_count}.",
            evidence_json=json.dumps([{"category": "HTTP Configuration", "indicator": h.name, "description": h.status, "severity": "LOW"} for h in result.headers_table]),
            recommendations_json=json.dumps([{"title": f"Configure {h.name}", "priority": "Medium", "action": h.recommended_value} for h in result.headers_table if h.status == "MISSING"]),
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
        raise HTTPException(status_code=500, detail=f"Header inspection error: {str(e)}")

