from typing import List, Optional, Any, Dict
from pydantic import BaseModel


class BlockchainRecordRequest(BaseModel):
    scan_id: str
    target: str
    threat_type: str
    risk_level: str
    risk_score: int
    findings_digest: str


class BlockchainVerifyRequest(BaseModel):
    report_hash: str
    payload_to_verify: Optional[Dict[str, Any]] = None


class BlockchainVerificationResponse(BaseModel):
    is_verified: bool
    report_hash: str
    reporter_address: str
    threat_type: str
    risk_level: str
    timestamp_utc: str
    block_number: int
    tx_hash: str
    network: str
    gas_used: int
    smart_contract_address: Optional[str] = None
    is_tamper_free: bool
    is_simulated: bool = False
    verification_message: str

