import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, DateTime, Text, Boolean
from app.database import Base


class ThreatIOC(Base):
    __tablename__ = "threat_iocs"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    ioc_value = Column(String(1024), nullable=False, unique=True, index=True)
    ioc_type = Column(String(32), nullable=False, index=True)  # domain, ip, url, hash, email
    threat_category = Column(String(64), nullable=False, index=True) # phishing, malware_c2, credential_theft, crypto_scam
    severity = Column(String(32), nullable=False, index=True)  # LOW, SUSPICIOUS, HIGH, CONFIRMED MALICIOUS
    source = Column(String(128), nullable=False)               # WebSentinel Intel, AbuseIPDB, PhishTank, etc.
    description = Column(Text, nullable=True)
    confidence = Column(Integer, default=95)                   # 0-100
    is_demo = Column(Boolean, default=False)                   # Flag for curated seed / demonstration IOCs
    first_seen = Column(DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))
    last_seen = Column(DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))
    is_active = Column(Boolean, default=True)

