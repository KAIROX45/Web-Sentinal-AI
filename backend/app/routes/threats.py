from datetime import datetime, timedelta, timezone
from typing import List, Optional
from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.database import get_db
from app.models.threat_ioc import ThreatIOC
from app.models.scan_history import ScanRecord
from app.schemas.threats import IOCItem, IOCCreateRequest, ThreatStatsResponse

router = APIRouter(prefix="/threats", tags=["Threat Intelligence Center"])


@router.get("/iocs", response_model=List[IOCItem])
def list_iocs(
    query: Optional[str] = None,
    ioc_type: Optional[str] = None,
    category: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db)
):
    """Retrieves threat IOCs with filtering and search."""
    q = db.query(ThreatIOC).filter(ThreatIOC.is_active == True)
    if query:
        term = f"%{query.strip().lower()}%"
        q = q.filter(
            (ThreatIOC.ioc_value.ilike(term)) |
            (ThreatIOC.description.ilike(term)) |
            (ThreatIOC.source.ilike(term))
        )
    if ioc_type and ioc_type != "all":
        q = q.filter(ThreatIOC.ioc_type == ioc_type.lower())
    if category and category != "all":
        q = q.filter(ThreatIOC.threat_category == category.lower())
    if severity and severity != "all":
        q = q.filter(ThreatIOC.severity == severity.upper())

    records = q.order_by(ThreatIOC.last_seen.desc()).limit(limit).all()
    return [
        IOCItem(
            id=r.id,
            ioc_value=r.ioc_value,
            ioc_type=r.ioc_type,
            threat_category=r.threat_category,
            severity=r.severity,
            source=r.source,
            description=r.description,
            confidence=r.confidence,
            is_demo=bool(getattr(r, "is_demo", False)),
            first_seen=r.first_seen.isoformat(),
            last_seen=r.last_seen.isoformat(),
            is_active=r.is_active
        )
        for r in records
    ]


@router.post("/iocs", response_model=IOCItem)
def create_ioc(req: IOCCreateRequest, db: Session = Depends(get_db)):
    """Registers a new IOC entry into the central threat registry."""
    existing = db.query(ThreatIOC).filter(ThreatIOC.ioc_value == req.ioc_value.strip().lower()).first()
    now_utc = datetime.now(timezone.utc).replace(tzinfo=None)
    if existing:
        existing.last_seen = now_utc
        existing.severity = req.severity.value
        existing.description = req.description or existing.description
        if hasattr(existing, "is_demo"):
            existing.is_demo = req.is_demo
        db.commit()
        db.refresh(existing)
        target = existing
    else:
        new_ioc = ThreatIOC(
            ioc_value=req.ioc_value.strip().lower(),
            ioc_type=req.ioc_type.lower(),
            threat_category=req.threat_category.lower(),
            severity=req.severity.value,
            source=req.source,
            description=req.description,
            confidence=req.confidence,
            is_demo=req.is_demo,
            first_seen=now_utc,
            last_seen=now_utc,
            is_active=True
        )
        db.add(new_ioc)
        db.commit()
        db.refresh(new_ioc)
        target = new_ioc

    return IOCItem(
        id=target.id,
        ioc_value=target.ioc_value,
        ioc_type=target.ioc_type,
        threat_category=target.threat_category,
        severity=target.severity,
        source=target.source,
        description=target.description,
        confidence=target.confidence,
        is_demo=bool(getattr(target, "is_demo", False)),
        first_seen=target.first_seen.isoformat(),
        last_seen=target.last_seen.isoformat(),
        is_active=target.is_active
    )


CATEGORY_LABELS = {
    "phishing": "Phishing",
    "credential_theft": "Credential Theft",
    "brand_impersonation": "Brand Impersonation",
    "malware_c2": "Malware C2",
    "crypto_scam": "Crypto Scam",
    "payment_fraud": "Payment Fraud",
    "package_smishing": "Package Smishing",
    "tor_exit_abuse": "Tor Exit Abuse",
    "bulletproof_hosting": "Bulletproof Hosting",
    "malware_distribution": "Malware Distribution"
}


@router.get("/stats", response_model=ThreatStatsResponse)
def get_threat_stats(db: Session = Depends(get_db)):
    """Aggregates real security metrics and trends from the database for the analyst dashboard."""
    total_scans = db.query(ScanRecord).count()
    malicious_scans = db.query(ScanRecord).filter(ScanRecord.risk_level == "CONFIRMED MALICIOUS").count()
    high_scans = db.query(ScanRecord).filter(ScanRecord.risk_level == "HIGH").count()
    suspicious_scans = db.query(ScanRecord).filter(ScanRecord.risk_level == "SUSPICIOUS").count()
    low_scans = db.query(ScanRecord).filter(ScanRecord.risk_level == "LOW").count()

    blocked_count = malicious_scans + high_scans

    # Compute overall platform security score (0-100) based strictly on actual investigations
    if total_scans == 0:
        security_score = 100
    else:
        avg_risk = db.query(func.avg(ScanRecord.risk_score)).scalar() or 0.0
        security_score = max(0, min(100, int(100 - avg_risk)))

    # Real threat category distribution from active IOC registry
    categories: dict = {}
    ioc_groups = db.query(
        ThreatIOC.threat_category,
        func.count(ThreatIOC.id)
    ).filter(ThreatIOC.is_active == True).group_by(ThreatIOC.threat_category).all()

    for cat_slug, count in ioc_groups:
        label = CATEGORY_LABELS.get(cat_slug.lower(), cat_slug.replace("_", " ").title())
        categories[label] = count

    # Real severity distribution across all recorded scans
    severity_dist = {
        "Low Risk": low_scans,
        "Suspicious": suspicious_scans,
        "High Severity": high_scans,
        "Confirmed Malicious": malicious_scans
    }

    # Aggregate actual 7-day timeline trends from scan records
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    trends = []
    days = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
    for i in range(7):
        day_date = now - timedelta(days=6-i)
        day_start = datetime(day_date.year, day_date.month, day_date.day, 0, 0, 0)
        day_end = day_start + timedelta(days=1)
        day_label = days[day_date.weekday()]

        scanned_cnt = db.query(ScanRecord).filter(
            ScanRecord.created_at >= day_start,
            ScanRecord.created_at < day_end
        ).count()

        threats_cnt = db.query(ScanRecord).filter(
            ScanRecord.created_at >= day_start,
            ScanRecord.created_at < day_end,
            ScanRecord.risk_level.in_(["SUSPICIOUS", "HIGH", "CONFIRMED MALICIOUS"])
        ).count()

        blocked_cnt = db.query(ScanRecord).filter(
            ScanRecord.created_at >= day_start,
            ScanRecord.created_at < day_end,
            ScanRecord.risk_level.in_(["HIGH", "CONFIRMED MALICIOUS"])
        ).count()

        trends.append({
            "date": day_label,
            "scanned": scanned_cnt,
            "threats": threats_cnt,
            "blocked": blocked_cnt
        })

    return ThreatStatsResponse(
        total_scans=total_scans,
        malicious_detected=malicious_scans,
        suspicious_detected=suspicious_scans,
        threats_blocked=blocked_count,
        security_score=security_score,
        threat_categories=categories,
        severity_distribution=severity_dist,
        recent_activity_trends=trends
    )

