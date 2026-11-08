import json
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.scan_history import ScanRecord
from app.services.report_generator import generate_threat_report_pdf

router = APIRouter(prefix="/reports", tags=["Investigation History & Reports"])


@router.get("/history")
def get_history(
    scan_type: Optional[str] = None,
    risk_level: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = Query(50, ge=1, le=100),
    db: Session = Depends(get_db)
):
    """Retrieves previous investigations with filtering and search."""
    q = db.query(ScanRecord)
    if scan_type and scan_type != "all":
        q = q.filter(ScanRecord.scan_type == scan_type.lower())
    if risk_level and risk_level != "all":
        q = q.filter(ScanRecord.risk_level == risk_level.upper())
    if search:
        term = f"%{search.strip().lower()}%"
        q = q.filter(
            (ScanRecord.target.ilike(term)) |
            (ScanRecord.summary.ilike(term))
        )

    records = q.order_by(ScanRecord.created_at.desc()).limit(limit).all()
    results = []
    for r in records:
        evidence = json.loads(r.evidence_json) if r.evidence_json else []
        recs = json.loads(r.recommendations_json) if r.recommendations_json else []
        results.append({
            "id": r.id,
            "target": r.target,
            "scan_type": r.scan_type,
            "risk_level": r.risk_level,
            "risk_score": r.risk_score,
            "summary": r.summary,
            "evidence_count": len(evidence),
            "recommendations_count": len(recs),
            "blockchain_hash": r.blockchain_hash,
            "blockchain_tx": r.blockchain_tx,
            "created_at": r.created_at.isoformat()
        })
    return results


@router.get("/{scan_id}")
def get_report_detail(scan_id: str, db: Session = Depends(get_db)):
    """Retrieves full details of a specific investigation report."""
    record = db.query(ScanRecord).filter(ScanRecord.id == scan_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Investigation record not found")

    return {
        "id": record.id,
        "target": record.target,
        "scan_type": record.scan_type,
        "risk_level": record.risk_level,
        "risk_score": record.risk_score,
        "summary": record.summary,
        "evidence": json.loads(record.evidence_json) if record.evidence_json else [],
        "recommendations": json.loads(record.recommendations_json) if record.recommendations_json else [],
        "raw_data": json.loads(record.raw_data_json) if record.raw_data_json else {},
        "blockchain_hash": record.blockchain_hash,
        "blockchain_tx": record.blockchain_tx,
        "created_at": record.created_at.isoformat()
    }


@router.get("/{scan_id}/export/json")
def export_report_json(scan_id: str, db: Session = Depends(get_db)):
    """Exports structured machine-readable report JSON."""
    record = db.query(ScanRecord).filter(ScanRecord.id == scan_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Investigation record not found")

    report_meta = {
        "platform": "WebSentinel AI Threat Intelligence",
        "report_id": record.id,
        "generated_at_utc": record.created_at.isoformat(),
        "canonical_hash": record.blockchain_hash,
        "blockchain_tx": record.blockchain_tx
    }
    report_payload = {
        "websentinel_meta": report_meta,
        "sentinelx_meta": report_meta,  # Backwards compatibility alias
        "target": record.target,
        "scan_type": record.scan_type,
        "assessment": {
            "risk_level": record.risk_level,
            "risk_score": record.risk_score,
            "summary": record.summary
        },
        "evidence": json.loads(record.evidence_json) if record.evidence_json else [],
        "recommendations": json.loads(record.recommendations_json) if record.recommendations_json else [],
        "technical_payload": json.loads(record.raw_data_json) if record.raw_data_json else {}
    }

    return Response(
        content=json.dumps(report_payload, indent=2),
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename=websentinel_report_{record.id[:8]}.json"}
    )


@router.get("/{scan_id}/export/pdf")
def export_report_pdf(scan_id: str, db: Session = Depends(get_db)):
    """Generates and downloads print-ready PDF cyber threat intelligence briefing."""
    record = db.query(ScanRecord).filter(ScanRecord.id == scan_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Investigation record not found")

    report_dict = {
        "id": record.id,
        "target": record.target,
        "risk_level": record.risk_level,
        "risk_score": record.risk_score,
        "evidence": json.loads(record.evidence_json) if record.evidence_json else [],
        "recommendations": json.loads(record.recommendations_json) if record.recommendations_json else [],
        "canonical_hash": record.blockchain_hash
    }

    pdf_bytes = generate_threat_report_pdf(report_dict)

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=websentinel_threat_brief_{record.id[:8]}.pdf"}
    )

