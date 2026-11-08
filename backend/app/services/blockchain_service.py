import json
import hashlib
import logging
from datetime import datetime, timezone
from typing import Dict, Any, Optional, Tuple
from sqlalchemy.orm import Session

from app.config import settings
from app.models.blockchain_record import BlockchainRecord
from app.models.scan_history import ScanRecord
from app.schemas.blockchain import (
    BlockchainRecordRequest, BlockchainVerifyRequest, BlockchainVerificationResponse
)

logger = logging.getLogger("websentinel.blockchain")

DEFAULT_SIMULATED_REPORTER = "0x0000000000000000000000000000000000000000"

# Standard ERC/EVM ABI for ThreatVerification contract
THREAT_VERIFICATION_ABI = [
    {
        "inputs": [],
        "stateMutability": "nonpayable",
        "type": "constructor"
    },
    {
        "anonymous": False,
        "inputs": [
            {"indexed": True, "internalType": "bytes32", "name": "reportHash", "type": "bytes32"},
            {"indexed": True, "internalType": "address", "name": "reporter", "type": "address"},
            {"indexed": False, "internalType": "string", "name": "threatType", "type": "string"},
            {"indexed": False, "internalType": "uint8", "name": "riskLevel", "type": "uint8"},
            {"indexed": False, "internalType": "uint256", "name": "timestamp", "type": "uint256"}
        ],
        "name": "ThreatReportRecorded",
        "type": "event"
    },
    {
        "inputs": [
            {"internalType": "bytes32", "name": "reportHash", "type": "bytes32"},
            {"internalType": "string", "name": "threatType", "type": "string"},
            {"internalType": "uint8", "name": "riskLevel", "type": "uint8"},
            {"internalType": "string", "name": "metadataUri", "type": "string"}
        ],
        "name": "recordThreatReport",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "inputs": [{"internalType": "bytes32", "name": "reportHash", "type": "bytes32"}],
        "name": "verifyThreatReport",
        "outputs": [
            {"internalType": "bool", "name": "exists"},
            {"internalType": "bytes32", "name": "hash"},
            {"internalType": "address", "name": "reporter"},
            {"internalType": "string", "name": "threatType"},
            {"internalType": "uint8", "name": "riskLevel"},
            {"internalType": "uint256", "name": "timestamp"},
            {"internalType": "string", "name": "metadataUri"}
        ],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [],
        "name": "getTotalReports",
        "outputs": [{"internalType": "uint256", "name": ""}],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [{"internalType": "uint256", "name": "index", "type": "uint256"}],
        "name": "getReportHashAtIndex",
        "outputs": [{"internalType": "bytes32", "name": "", "type": "bytes32"}],
        "stateMutability": "view",
        "type": "function"
    }
]


def canonicalize_and_hash(payload: Dict[str, Any]) -> str:
    """
    Produces deterministic SHA-256 fingerprint of canonical JSON:
    - Keys sorted alphabetically
    - Strict UTF-8 serialization
    - Compact formatting without superfluous whitespace
    """
    canonical_str = json.dumps(payload, sort_keys=True, separators=(',', ':'), ensure_ascii=True)
    digest = hashlib.sha256(canonical_str.encode('utf-8')).hexdigest()
    return f"0x{digest}"


class BlockchainService:
    def __init__(self):
        self.w3 = None
        self.contract = None
        self.is_live_sepolia = False
        self.contract_bytecode_verified = False
        self.connection_status = "LOCAL_SIMULATION"
        self.status_detail = "Operating in Local Cryptographic EVM Ledger simulation mode (No Sepolia RPC configured)."
        self.reconnect()

    def verify_contract_bytecode(self, address: str) -> Tuple[bool, str]:
        """
        Verifies that the target address on the connected network contains deployed contract bytecode.
        Detects uninitialized, empty, or externally owned accounts (EOAs).
        """
        if not self.w3 or not self.w3.is_connected():
            return False, "EVM RPC node is not connected."
        try:
            from web3 import Web3
            checksum = Web3.to_checksum_address(address)
            code = self.w3.eth.get_code(checksum)
            if not code or code == b"" or code == b"\x00" or code.hex() in ("", "0x", "0x0"):
                return False, f"Address {checksum} contains no contract bytecode (EOA or undeployed address)."
            return True, f"Contract bytecode verified ({len(code)} bytes deployed)."
        except Exception as e:
            return False, f"Failed to inspect contract bytecode: {str(e)}"

    @staticmethod
    def compute_canonical_hash(payload: Dict[str, Any]) -> str:
        return canonicalize_and_hash(payload)

    def record_threat_fingerprint(
        self,
        scan_id: str,
        target: str,
        threat_type: str,
        risk_level: str,
        risk_score: int,
        findings_digest: str,
        custom_payload: Optional[Dict[str, Any]] = None,
        db: Optional[Session] = None
    ) -> BlockchainVerificationResponse:
        from app.database import SessionLocal
        should_close = False
        if db is None:
            db = SessionLocal()
            should_close = True
        try:
            req = BlockchainRecordRequest(
                scan_id=scan_id,
                target=target,
                threat_type=threat_type,
                risk_level=risk_level,
                risk_score=risk_score,
                findings_digest=findings_digest
            )
            return self.record_report(db=db, report_data=req)
        finally:
            if should_close:
                db.close()

    def verify_report_hash(
        self,
        report_hash: str,
        payload_to_verify: Optional[Dict[str, Any]] = None,
        db: Optional[Session] = None
    ) -> BlockchainVerificationResponse:
        from app.database import SessionLocal
        should_close = False
        if db is None:
            db = SessionLocal()
            should_close = True
        try:
            return self.verify_report_integrity(db=db, report_hash=report_hash, payload_to_verify=payload_to_verify)
        finally:
            if should_close:
                db.close()

    def reconnect(self):
        """Initializes or refreshes Web3 connection to Sepolia testnet with bytecode verification."""
        self.w3 = None
        self.contract = None
        self.is_live_sepolia = False
        self.contract_bytecode_verified = False
        self.connection_status = "LOCAL_SIMULATION"
        self.status_detail = "Operating in Local Cryptographic EVM Ledger simulation mode (No Sepolia RPC configured)."

        if not settings.ETHEREUM_RPC_URL:
            logger.info("No ETHEREUM_RPC_URL configured. Operating in Local Cryptographic Ledger simulation mode.")
            return

        if not settings.CONTRACT_ADDRESS:
            self.connection_status = "INVALID_CONFIGURATION"
            self.status_detail = "Ethereum RPC configured but CONTRACT_ADDRESS is missing."
            logger.warning(self.status_detail)
            return

        try:
            from web3 import Web3
            self.w3 = Web3(Web3.HTTPProvider(settings.ETHEREUM_RPC_URL, request_kwargs={"timeout": 6.0}))
            if not self.w3.is_connected():
                self.connection_status = "RPC_UNREACHABLE"
                self.status_detail = f"Configured Ethereum RPC URL unreachable ({settings.ETHEREUM_RPC_URL[:25]}...)."
                logger.warning(self.status_detail)
                return

            # Check bytecode deployment at target contract address
            is_deployed, detail = self.verify_contract_bytecode(settings.CONTRACT_ADDRESS)
            if is_deployed:
                self.is_live_sepolia = True
                self.contract_bytecode_verified = True
                self.connection_status = "LIVE_SEPOLIA_DEPLOYED"
                self.status_detail = f"Connected to Ethereum Sepolia Testnet. Contract verified at {settings.CONTRACT_ADDRESS}."
                self.contract = self.w3.eth.contract(
                    address=Web3.to_checksum_address(settings.CONTRACT_ADDRESS),
                    abi=THREAT_VERIFICATION_ABI
                )
                logger.info(self.status_detail)
            else:
                self.is_live_sepolia = False
                self.contract_bytecode_verified = False
                self.connection_status = "LIVE_SEPOLIA_UNDEPLOYED"
                self.status_detail = f"Connected to Sepolia RPC, but target address has no deployed bytecode: {detail}"
                logger.warning(self.status_detail)

        except Exception as e:
            self.connection_status = "RPC_UNREACHABLE"
            self.status_detail = f"Web3 initialization error: {str(e)}"
            logger.warning(self.status_detail)

    def record_report(
        self,
        db: Session,
        report_data: BlockchainRecordRequest,
        reporter_address: Optional[str] = None
    ) -> BlockchainVerificationResponse:
        """
        Records canonical threat report fingerprint to the blockchain or local cryptographic ledger.
        NEVER sends raw personal information or sensitive payloads onto the ledger;
        only anchors the cryptographic SHA-256 digest, threat type, risk level, and timestamp.
        """
        timestamp = datetime.now(timezone.utc).isoformat()
        reporter = reporter_address or DEFAULT_SIMULATED_REPORTER

        # If scan_id matches an existing scan record, prioritize its verified canonical hash
        scan_record = None
        if report_data.scan_id:
            scan_record = db.query(ScanRecord).filter(ScanRecord.id == report_data.scan_id).first()

        if scan_record and scan_record.blockchain_hash:
            report_hash = scan_record.blockchain_hash
            canonical_dict = {
                "findings_digest": report_data.findings_digest,
                "risk_level": report_data.risk_level,
                "risk_score": report_data.risk_score,
                "scan_type": report_data.threat_type,
                "target": report_data.target,
                "timestamp_utc": scan_record.created_at.isoformat()
            }
        elif scan_record:
            canonical_dict = {
                "findings_digest": report_data.findings_digest,
                "risk_level": report_data.risk_level,
                "risk_score": report_data.risk_score,
                "scan_type": report_data.threat_type,
                "target": report_data.target,
                "timestamp_utc": scan_record.created_at.isoformat()
            }
            report_hash = canonicalize_and_hash(canonical_dict)
            scan_record.blockchain_hash = report_hash
        else:
            canonical_dict = {
                "findings_digest": report_data.findings_digest,
                "risk_level": report_data.risk_level,
                "risk_score": report_data.risk_score,
                "scan_type": report_data.threat_type,
                "target": report_data.target,
                "timestamp_utc": timestamp
            }
            report_hash = canonicalize_and_hash(canonical_dict)

        # Check if already registered on the ledger
        existing = db.query(BlockchainRecord).filter(BlockchainRecord.report_hash == report_hash).first()
        if existing:
            return BlockchainVerificationResponse(
                is_verified=True,
                report_hash=existing.report_hash,
                reporter_address=existing.reporter_address,
                threat_type=existing.threat_type,
                risk_level=existing.risk_level,
                timestamp_utc=existing.verified_at.isoformat(),
                block_number=existing.block_number,
                tx_hash=existing.tx_hash,
                network=existing.network,
                gas_used=48720,
                smart_contract_address=settings.CONTRACT_ADDRESS,
                is_tamper_free=True,
                is_simulated="Simulation Mode" in existing.network,
                verification_message="Report fingerprint previously anchored and verified on immutable ledger."
            )

        # Handle Live Sepolia vs Local Cryptographic Ledger Simulation
        if self.is_live_sepolia and self.contract_bytecode_verified and settings.WALLET_PRIVATE_KEY and self.contract:
            try:
                from web3 import Web3
                account = self.w3.eth.account.from_key(settings.WALLET_PRIVATE_KEY)
                reporter = account.address
                risk_enum_map = {"LOW": 0, "SUSPICIOUS": 1, "HIGH": 2, "CONFIRMED MALICIOUS": 3}
                risk_int = risk_enum_map.get(report_data.risk_level.upper(), 0)

                nonce = self.w3.eth.get_transaction_count(reporter)
                tx = self.contract.functions.recordThreatReport(
                    bytes.fromhex(report_hash[2:]),
                    report_data.threat_type,
                    risk_int,
                    f"urn:websentinel:{report_data.scan_id}"
                ).build_transaction({
                    'from': reporter,
                    'nonce': nonce,
                    'gas': 120000,
                    'gasPrice': self.w3.eth.gas_price
                })
                signed_tx = self.w3.eth.account.sign_transaction(tx, private_key=settings.WALLET_PRIVATE_KEY)
                tx_hash_bytes = self.w3.eth.send_raw_transaction(signed_tx.rawTransaction)
                tx_receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash_bytes, timeout=15)
                tx_hash = self.w3.to_hex(tx_hash_bytes)
                block_number = tx_receipt.blockNumber
                network_name = "Ethereum Sepolia Testnet"
                is_sim = False
                gas_used = tx_receipt.gasUsed
            except Exception as e:
                logger.warning(f"Sepolia transaction failed: {e}. Falling back to Local Cryptographic Ledger.")
                network_name = "WebSentinel Local Cryptographic Ledger (Simulation Mode)"
                tx_digest = hashlib.sha256(f"{report_hash}:{reporter}:{timestamp}".encode()).hexdigest()
                tx_hash = f"SIM-{tx_digest[:24]}"
                block_number = db.query(BlockchainRecord).count() + 1
                is_sim = True
                gas_used = 48720
        else:
            network_name = "WebSentinel Local Cryptographic Ledger (Simulation Mode)"
            tx_digest = hashlib.sha256(f"{report_hash}:{reporter}:{timestamp}".encode()).hexdigest()
            tx_hash = f"SIM-{tx_digest[:24]}"
            block_number = db.query(BlockchainRecord).count() + 1
            is_sim = True
            gas_used = 48720

        # Persist record
        record = BlockchainRecord(
            report_hash=report_hash,
            scan_id=report_data.scan_id,
            reporter_address=reporter,
            threat_type=report_data.threat_type,
            risk_level=report_data.risk_level,
            block_number=block_number,
            tx_hash=tx_hash,
            network=network_name,
            canonical_payload=json.dumps(canonical_dict, sort_keys=True)
        )
        db.add(record)
        db.commit()
        db.refresh(record)

        if scan_record:
            scan_record.blockchain_hash = report_hash
            scan_record.blockchain_tx = tx_hash
            db.commit()

        msg = (
            "Cryptographic proof anchored to live Ethereum Sepolia Testnet."
            if not is_sim
            else "Cryptographic proof anchored to Local Verifiable EVM Ledger (Simulation Mode). Configure Sepolia credentials in Settings for live on-chain anchoring."
        )

        return BlockchainVerificationResponse(
            is_verified=True,
            report_hash=record.report_hash,
            reporter_address=record.reporter_address,
            threat_type=record.threat_type,
            risk_level=record.risk_level,
            timestamp_utc=record.verified_at.isoformat(),
            block_number=record.block_number,
            tx_hash=record.tx_hash,
            network=record.network,
            gas_used=gas_used,
            smart_contract_address=settings.CONTRACT_ADDRESS,
            is_tamper_free=True,
            is_simulated=is_sim,
            verification_message=msg
        )

    def verify_report_integrity(
        self,
        db: Session,
        report_hash: str,
        payload_to_verify: Optional[Dict[str, Any]] = None
    ) -> BlockchainVerificationResponse:
        """
        Verifies whether a given report hash exists on-chain or in the verifiable ledger.
        If a payload is provided, re-computes its canonical SHA-256 hash to verify data integrity (tamper detection).
        """
        clean_hash = report_hash.strip().lower()
        if not clean_hash.startswith("0x"):
            clean_hash = "0x" + clean_hash

        # Tamper check if raw payload supplied
        is_tamper_free = True
        tamper_msg = "Cryptographic integrity verified. Stored hash matches ledger registration."

        if payload_to_verify:
            computed_hash = canonicalize_and_hash(payload_to_verify)
            if computed_hash.lower() != clean_hash:
                is_tamper_free = False
                tamper_msg = f"TAMPERING DETECTED: Computed hash ({computed_hash[:18]}...) does NOT match claimed report hash ({clean_hash[:18]}...)."

        # Lookup in records
        record = db.query(BlockchainRecord).filter(BlockchainRecord.report_hash == clean_hash).first()
        if not record:
            # Check live on-chain if contract is connected
            if self.is_live_sepolia and self.contract:
                try:
                    exists, _, reporter, threat_type, risk_level, timestamp, _ = self.contract.functions.verifyThreatReport(
                        bytes.fromhex(clean_hash[2:])
                    ).call()
                    if exists:
                        risk_labels = ["LOW", "SUSPICIOUS", "HIGH", "CONFIRMED MALICIOUS"]
                        return BlockchainVerificationResponse(
                            is_verified=True,
                            report_hash=clean_hash,
                            reporter_address=reporter,
                            threat_type=threat_type,
                            risk_level=risk_labels[risk_level] if risk_level < len(risk_labels) else "UNKNOWN",
                            timestamp_utc=datetime.fromtimestamp(timestamp, timezone.utc).isoformat(),
                            block_number=0,
                            tx_hash="On-Chain State Query",
                            network="Ethereum Sepolia Testnet",
                            gas_used=0,
                            smart_contract_address=settings.CONTRACT_ADDRESS,
                            is_tamper_free=is_tamper_free,
                            is_simulated=False,
                            verification_message=tamper_msg
                        )
                except Exception as e:
                    logger.debug(f"On-chain query failed: {e}")

            return BlockchainVerificationResponse(
                is_verified=False,
                report_hash=clean_hash,
                reporter_address="0x0000000000000000000000000000000000000000",
                threat_type="Unknown",
                risk_level="Unknown",
                timestamp_utc="",
                block_number=0,
                tx_hash="",
                network="Ethereum Sepolia Testnet" if self.is_live_sepolia else "WebSentinel Local Cryptographic Ledger (Simulation Mode)",
                gas_used=0,
                smart_contract_address=settings.CONTRACT_ADDRESS,
                is_tamper_free=False,
                is_simulated=not self.is_live_sepolia,
                verification_message="Report hash not found on registered threat ledger. Hash may be unanchored or invalid."
            )

        return BlockchainVerificationResponse(
            is_verified=True,
            report_hash=record.report_hash,
            reporter_address=record.reporter_address,
            threat_type=record.threat_type,
            risk_level=record.risk_level,
            timestamp_utc=record.verified_at.isoformat(),
            block_number=record.block_number,
            tx_hash=record.tx_hash,
            network=record.network,
            gas_used=48720,
            smart_contract_address=settings.CONTRACT_ADDRESS,
            is_tamper_free=is_tamper_free,
            is_simulated="Simulation Mode" in record.network,
            verification_message=tamper_msg
        )


blockchain_service = BlockchainService()


