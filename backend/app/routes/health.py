from fastapi import APIRouter
from app.config import settings

router = APIRouter(prefix="/health", tags=["Health & System"])


@router.get("/")
def health_check():
    return {
        "status": "healthy",
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "environment": settings.ENVIRONMENT,
        "integrations": {
            "gemini_ai": bool(settings.GEMINI_API_KEY),
            "google_safe_browsing": bool(settings.GOOGLE_SAFE_BROWSING_API_KEY),
            "virustotal": bool(settings.VIRUSTOTAL_API_KEY),
            "sepolia_blockchain": bool(settings.ETHEREUM_RPC_URL and settings.CONTRACT_ADDRESS)
        }
    }

