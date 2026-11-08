import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, DateTime, Text
from app.database import Base


class ScanRecord(Base):
    __tablename__ = "scan_records"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    target = Column(String(2048), nullable=False, index=True)
    scan_type = Column(String(32), nullable=False, index=True)  # url, ip, message, tls, headers, unified
    risk_level = Column(String(32), nullable=False, index=True)  # LOW, SUSPICIOUS, HIGH, CONFIRMED MALICIOUS
    risk_score = Column(Integer, nullable=False, default=0)       # 0 - 100
    summary = Column(Text, nullable=True)
    evidence_json = Column(Text, nullable=True)                  # Stored as JSON string
    recommendations_json = Column(Text, nullable=True)           # Stored as JSON string
    raw_data_json = Column(Text, nullable=True)                  # Stored as JSON string
    blockchain_hash = Column(String(66), nullable=True, index=True) # 0x... 32-byte sha256
    blockchain_tx = Column(String(66), nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None), index=True)

