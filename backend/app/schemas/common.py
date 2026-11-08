from enum import Enum
from typing import List, Optional, Any, Dict
from pydantic import BaseModel, Field


class RiskLevel(str, Enum):
    LOW = "LOW"
    SUSPICIOUS = "SUSPICIOUS"
    HIGH = "HIGH"
    CONFIRMED_MALICIOUS = "CONFIRMED MALICIOUS"


class EvidenceItem(BaseModel):
    category: str
    indicator: str
    description: str
    severity: RiskLevel
    source: str = "WebSentinel AI Core Engine"


class RecommendedAction(BaseModel):
    title: str
    priority: str  # Critical, High, Medium, Informational
    action: str
    target_audience: str = "All Users"  # All Users, SOC Analysts, System Administrators


class SecurityScore(BaseModel):
    score: int = Field(ge=0, le=100)
    grade: str  # A+, A, B, C, D, F
    risk_level: RiskLevel
    label: str


class CanonicalReportPayload(BaseModel):
    target: str
    scan_type: str
    risk_level: RiskLevel
    risk_score: int
    findings_digest: str
    timestamp_utc: str

