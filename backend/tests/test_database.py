import uuid
from datetime import datetime, timezone
import pytest
from sqlalchemy.exc import IntegrityError
from app.database import SessionLocal
from app.models.scan_history import ScanRecord
from app.models.threat_ioc import ThreatIOC
from app.models.blockchain_record import BlockchainRecord


def test_scan_record_crud():
    db = SessionLocal()
    scan_id = str(uuid.uuid4())
    try:
        # Create
        record = ScanRecord(
            id=scan_id,
            target="https://database-test.example.com",
            scan_type="url",
            risk_level="SUSPICIOUS",
            risk_score=55,
            summary="Database unit test record",
            evidence_json='[{"rule": "entropy", "score": 55}]',
            recommendations_json='[{"title": "Verify domain ownership"}]',
            raw_data_json='{"status_code": 200}'
        )
        db.add(record)
        db.commit()

        # Read
        fetched = db.query(ScanRecord).filter(ScanRecord.id == scan_id).first()
        assert fetched is not None
        assert fetched.target == "https://database-test.example.com"
        assert fetched.risk_score == 55
        assert fetched.risk_level == "SUSPICIOUS"

        # Update
        fetched.risk_score = 60
        fetched.summary = "Updated summary in test"
        db.commit()

        updated = db.query(ScanRecord).filter(ScanRecord.id == scan_id).first()
        assert updated.risk_score == 60
        assert updated.summary == "Updated summary in test"

        # Delete
        db.delete(updated)
        db.commit()

        deleted = db.query(ScanRecord).filter(ScanRecord.id == scan_id).first()
        assert deleted is None
    finally:
        db.close()


def test_threat_ioc_uniqueness_constraint():
    db = SessionLocal()
    unique_val = f"test-ioc-{uuid.uuid4().hex[:8]}.malicious.test"
    ioc1 = ThreatIOC(
        id=str(uuid.uuid4()),
        ioc_value=unique_val,
        ioc_type="domain",
        threat_category="phishing",
        severity="HIGH",
        source="Test Source",
        confidence=90,
        is_demo=False
    )
    ioc2 = ThreatIOC(
        id=str(uuid.uuid4()),
        ioc_value=unique_val,  # Duplicate ioc_value violates UNIQUE
        ioc_type="domain",
        threat_category="phishing",
        severity="HIGH",
        source="Duplicate Test Source",
        confidence=90,
        is_demo=False
    )
    try:
        db.add(ioc1)
        db.commit()

        # Attempting to insert duplicate should raise IntegrityError
        db.add(ioc2)
        with pytest.raises(IntegrityError):
            db.commit()
        db.rollback()
    finally:
        # Cleanup
        to_clean = db.query(ThreatIOC).filter(ThreatIOC.ioc_value == unique_val).first()
        if to_clean:
            db.delete(to_clean)
            db.commit()
        db.close()


def test_threat_ioc_filtering_and_demo_flag():
    db = SessionLocal()
    demo_val = f"demo-test-{uuid.uuid4().hex[:6]}.test"
    real_val = f"real-test-{uuid.uuid4().hex[:6]}.test"
    try:
        ioc_demo = ThreatIOC(
            id=str(uuid.uuid4()),
            ioc_value=demo_val,
            ioc_type="domain",
            threat_category="brand_impersonation",
            severity="CONFIRMED MALICIOUS",
            source="Demo Preseed",
            confidence=100,
            is_demo=True
        )
        ioc_real = ThreatIOC(
            id=str(uuid.uuid4()),
            ioc_value=real_val,
            ioc_type="ip",
            threat_category="malware_c2",
            severity="HIGH",
            source="Live Threat Feed",
            confidence=88,
            is_demo=False
        )
        db.add_all([ioc_demo, ioc_real])
        db.commit()

        # Query demo IOCs
        demo_results = db.query(ThreatIOC).filter(ThreatIOC.is_demo == True, ThreatIOC.ioc_value == demo_val).all()
        assert len(demo_results) == 1
        assert demo_results[0].is_demo is True

        # Query by ioc_type
        ip_results = db.query(ThreatIOC).filter(ThreatIOC.ioc_type == "ip", ThreatIOC.ioc_value == real_val).all()
        assert len(ip_results) == 1
        assert ip_results[0].is_demo is False
    finally:
        for val in [demo_val, real_val]:
            item = db.query(ThreatIOC).filter(ThreatIOC.ioc_value == val).first()
            if item:
                db.delete(item)
        db.commit()
        db.close()


def test_blockchain_record_integrity():
    db = SessionLocal()
    hash_val = "0x" + uuid.uuid4().hex + uuid.uuid4().hex
    tx_val = "0x" + uuid.uuid4().hex + uuid.uuid4().hex
    try:
        record = BlockchainRecord(
            id=str(uuid.uuid4()),
            report_hash=hash_val,
            scan_id=str(uuid.uuid4()),
            reporter_address="0x1111111111111111111111111111111111111111",
            threat_type="url",
            risk_level="HIGH",
            block_number=1234567,
            tx_hash=tx_val,
            network="Sepolia Testnet",
            canonical_payload='{"test": true}'
        )
        db.add(record)
        db.commit()

        fetched = db.query(BlockchainRecord).filter(BlockchainRecord.report_hash == hash_val).first()
        assert fetched is not None
        assert fetched.tx_hash == tx_val
        assert fetched.block_number == 1234567

        # Uniqueness on report_hash
        dup_record = BlockchainRecord(
            id=str(uuid.uuid4()),
            report_hash=hash_val,  # Duplicate hash
            reporter_address="0x2222222222222222222222222222222222222222",
            threat_type="url",
            risk_level="HIGH",
            block_number=1234568,
            tx_hash="0x" + uuid.uuid4().hex + uuid.uuid4().hex,
            network="Sepolia Testnet",
            canonical_payload='{"test": true}'
        )
        db.add(dup_record)
        with pytest.raises(IntegrityError):
            db.commit()
        db.rollback()
    finally:
        to_clean = db.query(BlockchainRecord).filter(BlockchainRecord.report_hash == hash_val).first()
        if to_clean:
            db.delete(to_clean)
            db.commit()
        db.close()

