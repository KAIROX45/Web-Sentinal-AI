from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel
from app.schemas.common import RiskLevel


class IOCItem(BaseModel):
    id: str
    ioc_value: str
    ioc_type: str
    threat_category: str
    severity: RiskLevel
    source: str
    description: Optional[str] = None
    confidence: int
    is_demo: bool = False
    first_seen: str
    last_seen: str
    is_active: bool


class IOCCreateRequest(BaseModel):
    ioc_value: str
    ioc_type: str
    threat_category: str
    severity: RiskLevel
    source: str = "Analyst Submission"
    description: Optional[str] = None
    confidence: int = 90
    is_demo: bool = False


class ThreatStatsResponse(BaseModel):
    total_scans: int
    malicious_detected: int
    suspicious_detected: int
    threats_blocked: int
    security_score: int
    threat_categories: dict
    severity_distribution: dict
    recent_activity_trends: List[dict]

