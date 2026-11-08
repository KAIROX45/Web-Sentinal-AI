from typing import List, Optional
from pydantic import BaseModel
from app.schemas.common import RiskLevel


class TLSScanRequest(BaseModel):
    hostname: str
    port: int = 443


class CertificateChainNode(BaseModel):
    level: int
    subject: str
    issuer: str
    is_root: bool = False
    is_leaf: bool = False
    valid_from: str
    valid_to: str
    signature_algorithm: str


class TLSScanResponse(BaseModel):
    id: Optional[str] = None
    canonical_hash: Optional[str] = None
    hostname: str
    port: int
    connected_ip: Optional[str] = None
    protocol_version: str
    cipher_suite: str
    subject_cn: Optional[str] = None
    subject_org: Optional[str] = None
    issuer_cn: Optional[str] = None
    issuer_org: Optional[str] = None
    sans: List[str] = []
    valid_from: str
    valid_to: str
    days_remaining: int
    is_valid: bool
    is_expired: bool
    is_self_signed: bool
    is_ca_trusted: bool = True
    hostname_matches: bool
    serial_number: str
    signature_algorithm: str
    key_type: str
    key_bits: int
    certificate_chain: List[CertificateChainNode]
    revocation_status: str  # e.g., "OCSP Stapling: Not active / CRL check required"
    warnings: List[str] = []
    risk_level: RiskLevel
    risk_score: int
    timestamp: str

