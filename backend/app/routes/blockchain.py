from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.config import settings
from app.models.blockchain_record import BlockchainRecord
from app.schemas.blockchain import (
    BlockchainRecordRequest, BlockchainVerifyRequest, BlockchainVerificationResponse
)
from app.services.blockchain_service import blockchain_service

router = APIRouter(prefix="/blockchain", tags=["Blockchain Threat Verification"])


@router.get("/status")
def get_blockchain_status(db: Session = Depends(get_db)):
    """Returns network connectivity, smart contract address, and ledger report count."""
    total_on_ledger = db.query(BlockchainRecord).count()
    return {
        "network": "Ethereum Sepolia Testnet" if blockchain_service.is_live_sepolia else "WebSentinel Local Cryptographic Ledger (Simulation Mode)",
        "connection_status": blockchain_service.connection_status,
        "status_detail": blockchain_service.status_detail,
        "is_live_sepolia": blockchain_service.is_live_sepolia,
        "is_simulated": not blockchain_service.is_live_sepolia,
        "smart_contract_address": settings.CONTRACT_ADDRESS,
        "contract_bytecode_verified": blockchain_service.contract_bytecode_verified,
        "chain_id": settings.SEPOLIA_CHAIN_ID,
        "total_reports_anchored": total_on_ledger,
        "verification_mechanism": "EVM SHA-256 State Tree Hash Verification",
        "privacy_guarantee": "Zero raw investigation data or PII stored on-chain; strictly canonical SHA-256 digests."
    }


@router.post("/record", response_model=BlockchainVerificationResponse)
def record_to_blockchain(req: BlockchainRecordRequest, db: Session = Depends(get_db)):
    """
    Computes canonical SHA-256 fingerprint and anchors it to the immutable ledger.
    """
    try:
        response = blockchain_service.record_report(db=db, report_data=req)
        return response
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Blockchain anchoring failed: {str(e)}")


@router.post("/verify", response_model=BlockchainVerificationResponse)
def verify_blockchain_report(req: BlockchainVerifyRequest, db: Session = Depends(get_db)):
    """
    Verifies report integrity and checks whether a given fingerprint exists on-chain.
    Detects any payload tampering.
    """
    if not req.report_hash:
        raise HTTPException(status_code=400, detail="Report hash is required")

    try:
        result = blockchain_service.verify_report_integrity(
            db=db,
            report_hash=req.report_hash,
            payload_to_verify=req.payload_to_verify
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Verification lookup failed: {str(e)}")


@router.get("/records", response_model=List[dict])
def list_blockchain_records(limit: int = 20, db: Session = Depends(get_db)):
    """Lists recent blockchain anchored records for explorer view."""
    records = db.query(BlockchainRecord).order_by(BlockchainRecord.verified_at.desc()).limit(limit).all()
    return [
        {
            "id": r.id,
            "report_hash": r.report_hash,
            "scan_id": r.scan_id,
            "reporter_address": r.reporter_address,
            "threat_type": r.threat_type,
            "risk_level": r.risk_level,
            "block_number": r.block_number,
            "tx_hash": r.tx_hash,
            "network": r.network,
            "verified_at": r.verified_at.isoformat()
        }
        for r in records
    ]

