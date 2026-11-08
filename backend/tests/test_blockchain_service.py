import pytest
import hashlib
import json
import uuid
from app.services.blockchain_service import blockchain_service, canonicalize_and_hash
from app.database import SessionLocal
from app.models.blockchain_record import BlockchainRecord
from app.models.scan_history import ScanRecord


def test_canonical_hash_consistency():
    payload = {
        "findings_digest": "Testing SHA-256 canonical hashing",
        "risk_level": "CONFIRMED_MALICIOUS",
        "risk_score": 95,
        "scan_type": "url",
        "target": "https://evil-phishing.test",
        "timestamp_utc": "2026-11-08T12:00:00"
    }
    expected_hash = "0x" + hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(',', ':')).encode('utf-8')).hexdigest()
    computed_hash = canonicalize_and_hash(payload)
    assert computed_hash == expected_hash


def test_blockchain_anchor_and_duplicate_prevention():
    test_id = f"test-scan-{uuid.uuid4()}"
    target_url = f"https://threat-{test_id}.test"
    db = SessionLocal()
    try:
        # Create a ScanRecord first
        scan_rec = ScanRecord(
            id=test_id,
            target=target_url,
            scan_type="url",
            risk_level="HIGH",
            risk_score=85,
            summary="Test scan record",
            blockchain_hash=None
        )
        db.add(scan_rec)
        db.commit()

        initial_count = db.query(BlockchainRecord).count()

        # First registration must succeed
        res1 = blockchain_service.record_threat_fingerprint(
            scan_id=test_id,
            target=target_url,
            threat_type="url",
            risk_level="HIGH",
            risk_score=85,
            findings_digest="Cryptographic ledger anchor test",
            db=db
        )

        assert res1.is_verified is True
        assert res1.is_simulated is True
        assert res1.tx_hash.startswith("SIM-")
        assert res1.is_tamper_free is True

        count_after_first = db.query(BlockchainRecord).count()
        assert count_after_first == initial_count + 1

        # Second registration of the exact same scan must return previous anchor and NOT insert duplicate row
        res2 = blockchain_service.record_threat_fingerprint(
            scan_id=test_id,
            target=target_url,
            threat_type="url",
            risk_level="HIGH",
            risk_score=85,
            findings_digest="Cryptographic ledger anchor test",
            db=db
        )
        assert res2.is_verified is True
        assert "previously anchored" in res2.verification_message.lower()

        count_after_second = db.query(BlockchainRecord).count()
        assert count_after_second == count_after_first  # Duplicate was rejected, no extra row!
    finally:
        db.close()


def test_tamper_detection():
    test_id = f"tamper-test-{uuid.uuid4()}"
    target_domain = f"https://suspicious-{uuid.uuid4().hex[:6]}.com"
    db = SessionLocal()
    try:
        res = blockchain_service.record_threat_fingerprint(
            scan_id=test_id,
            target=target_domain,
            threat_type="url",
            risk_level="HIGH",
            risk_score=88,
            findings_digest="Original authentic report findings",
            db=db
        )

        # Build payload that matches the record
        record = db.query(BlockchainRecord).filter(BlockchainRecord.report_hash == res.report_hash).first()
        valid_payload = {
            "findings_digest": "Original authentic report findings",
            "risk_level": "HIGH",
            "risk_score": 88,
            "scan_type": "url",
            "target": target_domain,
            "timestamp_utc": record.verified_at.isoformat()
        }

        # Verify with tampered payload -> Tamper Alert Detected!
        tampered_payload = dict(valid_payload)
        tampered_payload["risk_level"] = "LOW"
        tampered_payload["findings_digest"] = "Altered by unauthorized actor"

        verify_tampered = blockchain_service.verify_report_hash(
            res.report_hash,
            payload_to_verify=tampered_payload,
            db=db
        )
        assert verify_tampered.is_verified is True
        assert verify_tampered.is_tamper_free is False
        assert "TAMPER" in verify_tampered.verification_message.upper()
    finally:
        db.close()


def test_verify_contract_bytecode_detection():
    from unittest.mock import MagicMock
    from web3 import Web3

    # 1. When not connected to Sepolia
    blockchain_service.w3 = None
    is_dep, msg = blockchain_service.verify_contract_bytecode("0x1234567890123456789012345678901234567890")
    assert is_dep is False
    assert "not connected" in msg.lower()

    # 2. When connected but target address has no bytecode (EOA or undeployed)
    mock_w3 = MagicMock()
    mock_w3.is_connected.return_value = True
    mock_w3.eth.get_code.return_value = b""
    blockchain_service.w3 = mock_w3

    is_dep, msg = blockchain_service.verify_contract_bytecode("0x1234567890123456789012345678901234567890")
    assert is_dep is False
    assert "no contract bytecode" in msg.lower()

    # 3. When address has real deployed bytecode
    mock_w3.eth.get_code.return_value = b"\x60\x80\x60\x40\x52\x34\x80\x15"
    is_dep, msg = blockchain_service.verify_contract_bytecode("0x1234567890123456789012345678901234567890")
    assert is_dep is True
    assert "verified" in msg.lower()

    # Reset service
    blockchain_service.reconnect()


def test_unanchored_hash_verification():
    db = SessionLocal()
    try:
        random_hash = "0x" + hashlib.sha256(b"non-existent-report-test").hexdigest()
        res = blockchain_service.verify_report_hash(random_hash, db=db)
        assert res.is_verified is False
        assert res.is_tamper_free is False
        assert "not found" in res.verification_message.lower()
    finally:
        db.close()


def test_solidity_contract_abi_alignment():
    import os
    from app.services.blockchain_service import THREAT_VERIFICATION_ABI

    contract_path = os.path.join(os.path.dirname(__file__), "..", "contracts", "ThreatVerification.sol")
    assert os.path.exists(contract_path), "ThreatVerification.sol contract file must exist"

    with open(contract_path, "r", encoding="utf-8") as f:
        content = f.read()

    # Ensure Solidity version and core functions are present
    assert "pragma solidity ^0.8.20;" in content
    assert "contract ThreatVerification" in content
    assert "function recordThreatReport" in content
    assert "function verifyThreatReport" in content
    assert "function getTotalReports" in content
    assert "function getReportHashAtIndex" in content
    assert "event ThreatReportRecorded" in content

    # Check ABI contains all required functions and events
    abi_names = {entry.get("name") for entry in THREAT_VERIFICATION_ABI if "name" in entry}
    expected_names = {
        "recordThreatReport",
        "verifyThreatReport",
        "getTotalReports",
        "getReportHashAtIndex",
        "ThreatReportRecorded"
    }
    assert expected_names.issubset(abi_names), f"Missing ABI entries: {expected_names - abi_names}"


