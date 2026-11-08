import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, DateTime, Text
from app.database import Base


class BlockchainRecord(Base):
    __tablename__ = "blockchain_records"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    report_hash = Column(String(66), nullable=False, unique=True, index=True) # 0x... sha256
    scan_id = Column(String(36), nullable=True, index=True)
    reporter_address = Column(String(42), nullable=False)
    threat_type = Column(String(32), nullable=False)
    risk_level = Column(String(32), nullable=False)
    block_number = Column(Integer, nullable=False)
    tx_hash = Column(String(66), nullable=False, unique=True)
    network = Column(String(64), nullable=False, default="Sepolia Testnet")
    canonical_payload = Column(Text, nullable=False)
    verified_at = Column(DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))

