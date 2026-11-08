from typing import List, Optional, Dict, Any
from pydantic import BaseModel, HttpUrl
from app.schemas.common import RiskLevel, EvidenceItem, RecommendedAction, SecurityScore


class URLScanRequest(BaseModel):
    url: str
    deep_scan: bool = True


class DomainInfo(BaseModel):
    raw_domain: str
    subdomain: str
    domain: str
    suffix: str
    registered_domain: str
    is_ip: bool = False
    entropy: float = 0.0
    length: int = 0
    tld_risk_tier: str = "Standard"
    domain_age_days: Optional[int] = None
    registrar: Optional[str] = None


class TyposquattingFinding(BaseModel):
    is_typosquat: bool
    targeted_brand: Optional[str] = None
    similarity_score: float = 0.0
    technique: Optional[str] = None
    explanation: Optional[str] = None


class HomographFinding(BaseModel):
    has_homograph: bool
    punycode: Optional[str] = None
    scripts_detected: List[str] = []
    spoofed_characters: List[str] = []
    explanation: Optional[str] = None


class DNSRecords(BaseModel):
    a_records: List[str] = []
    aaaa_records: List[str] = []
    mx_records: List[str] = []
    ns_records: List[str] = []
    txt_records: List[str] = []
    resolved_ip: Optional[str] = None
    lookup_status: str = "Resolved"


class RedirectHop(BaseModel):
    hop_number: int
    url: str
    status_code: int
    resolved_ip: str
    response_time_ms: float
    is_safe: bool = True


class ThreatIntelSource(BaseModel):
    source_name: str
    checked: bool
    is_flagged: bool
    category: Optional[str] = None
    details: Optional[str] = None
    status_note: str


class URLScanResponse(BaseModel):
    id: str
    submitted_url: str
    normalized_url: str
    scheme: str
    risk_level: RiskLevel
    risk_score: int
    security_score: SecurityScore
    domain_info: DomainInfo
    typosquatting: TyposquattingFinding
    homograph: HomographFinding
    suspicious_patterns: List[str]
    dns: DNSRecords
    redirect_chain: List[RedirectHop]
    threat_intel: List[ThreatIntelSource]
    evidence: List[EvidenceItem]
    recommendations: List[RecommendedAction]
    canonical_hash: str
    timestamp: str

