from typing import List, Optional
from pydantic import BaseModel
from app.schemas.common import RiskLevel


class HeaderItem(BaseModel):
    name: str
    status: str  # PRESENT_OPTIMAL, PRESENT_WEAK, MISSING, INSECURE
    actual_value: Optional[str] = None
    importance: str  # HIGH, MEDIUM, LOW
    recommended_value: str
    purpose: str
    security_impact: str


class HeaderScanRequest(BaseModel):
    url: str


class HeaderScanResponse(BaseModel):
    id: Optional[str] = None
    canonical_hash: Optional[str] = None
    url: str
    final_url: str
    status_code: int
    headers_table: List[HeaderItem]
    security_score: int
    missing_count: int
    optimal_count: int
    weak_count: int
    server_banner: Optional[str] = None
    information_disclosure: List[str] = []
    disclaimer: str = "An absent or misconfigured header alone does not prove a site is malicious, but weakens defense-in-depth."
    timestamp: str

