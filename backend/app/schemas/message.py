from typing import List, Optional
from pydantic import BaseModel
from app.schemas.common import RiskLevel, EvidenceItem, RecommendedAction


class MessageScanRequest(BaseModel):
    content: str
    message_type: str = "auto"  # auto, email, sms, chat
    sender_metadata: Optional[str] = None


class ExtractedUrlItem(BaseModel):
    url: str
    domain: str
    is_suspicious: bool
    risk_indicator: Optional[str] = None


class SuspiciousEntity(BaseModel):
    entity: str
    entity_type: str  # Brand, Financial Institution, Phone Number, Crypto Address
    context: str


class MessageScanResponse(BaseModel):
    id: str
    message_type: str
    risk_level: RiskLevel
    risk_score: int = 0  # 0-100 threat severity score
    confidence_score: int  # 0-100 AI/heuristic confidence
    attack_category: str
    extracted_urls: List[ExtractedUrlItem] = []
    suspicious_entities: List[SuspiciousEntity] = []
    manipulation_techniques: List[str] = []
    explanation: str
    evidence: List[EvidenceItem] = []
    recommended_actions: List[RecommendedAction] = []
    source: str  # "gemini_ai" or "heuristic_engine"
    ai_disclaimer: str = "AI-generated conclusions are probabilistic assessments and are maintained distinct from verified deterministic threat intelligence."
    canonical_hash: str
    timestamp: str

