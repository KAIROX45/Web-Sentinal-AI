from typing import List, Optional
from pydantic import BaseModel
from app.schemas.common import RiskLevel, EvidenceItem, RecommendedAction


class IPScanRequest(BaseModel):
    ip_address: str


class GeolocationInfo(BaseModel):
    country: str = "Unknown"
    country_code: str = "XX"
    city: str = "Unknown"
    region: str = "Unknown"
    latitude: float = 0.0
    longitude: float = 0.0
    timezone: str = "UTC"


class NetworkInfo(BaseModel):
    asn: Optional[str] = None
    asn_org: Optional[str] = None
    isp: Optional[str] = None
    reverse_dns: Optional[str] = None
    is_hosting: bool = False
    is_vpn_tor: bool = False


class IPScanResponse(BaseModel):
    id: str
    ip_address: str
    ip_version: str  # IPv4 or IPv6
    is_private: bool
    is_loopback: bool
    is_reserved: bool
    classification: str  # Public Internet, RFC1918 Private, Loopback, Reserved
    network_info: NetworkInfo
    geo_info: GeolocationInfo
    reputation_score: int  # 0 (clean) - 100 (abusive)
    risk_level: RiskLevel
    abuse_categories: List[str] = []
    associated_domains: List[str] = []
    threat_intel_matches: List[str] = []
    evidence: List[EvidenceItem] = []
    recommendations: List[RecommendedAction] = []
    canonical_hash: str
    timestamp: str

