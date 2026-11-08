import re
from fastapi import APIRouter, HTTPException, Header, status
from pydantic import BaseModel
from typing import Optional
from app.config import settings

router = APIRouter(prefix="/settings", tags=["Configuration & Integrations"])


class SettingsUpdateRequest(BaseModel):
    admin_key: Optional[str] = None
    gemini_api_key: Optional[str] = None
    google_safe_browsing_api_key: Optional[str] = None
    virustotal_api_key: Optional[str] = None
    ethereum_rpc_url: Optional[str] = None
    contract_address: Optional[str] = None


def _mask_database_url(url: str) -> str:
    """Masks database passwords to prevent sensitive credential exposure."""
    if not url:
        return ""
    if "@" in url:
        try:
            # Mask user:password@host...
            parts = url.split("@", 1)
            scheme_user = parts[0].rsplit(":", 1)[0]
            return f"{scheme_user}:***@{parts[1]}"
        except Exception:
            return "configured (credentials hidden)"
    # Clean file path for sqlite
    if url.startswith("sqlite:///"):
        return "sqlite:///./sentinelx.db"
    return url


def _mask_rpc_url(rpc_url: Optional[str]) -> Optional[str]:
    """Masks secret API tokens inside RPC URLs (e.g. Infura / Alchemy keys)."""
    if not rpc_url:
        return None
    if "/v3/" in rpc_url:
        base, token = rpc_url.rsplit("/v3/", 1)
        if len(token) > 6:
            return f"{base}/v3/{token[:3]}***{token[-3:]}"
    return rpc_url


@router.get("/")
def get_current_settings():
    """Returns configuration status without revealing sensitive secrets."""
    masked_db = _mask_database_url(settings.DATABASE_URL)
    masked_rpc = _mask_rpc_url(settings.ETHEREUM_RPC_URL)

    return {
        "app_name": settings.APP_NAME,
        "environment": settings.ENVIRONMENT,
        "database_url": masked_db,
        "gemini_api_key_configured": bool(settings.GEMINI_API_KEY),
        "gemini_api_key_masked": f"...{settings.GEMINI_API_KEY[-4:]}" if settings.GEMINI_API_KEY else None,
        "google_safe_browsing_configured": bool(settings.GOOGLE_SAFE_BROWSING_API_KEY),
        "virustotal_configured": bool(settings.VIRUSTOTAL_API_KEY),
        "ethereum_rpc_url": masked_rpc or "Not configured (Local Cryptographic EVM Ledger Active)",
        "contract_address": settings.CONTRACT_ADDRESS or None,
        "is_simulated_ledger": not bool(settings.ETHEREUM_RPC_URL and settings.CONTRACT_ADDRESS),
        "sepolia_chain_id": settings.SEPOLIA_CHAIN_ID,
        "max_redirect_hops": settings.MAX_REDIRECT_HOPS,
        "timeout_seconds": settings.REQUEST_TIMEOUT_SECONDS,
        "admin_auth_required": bool(settings.ADMIN_API_KEY)
    }


@router.post("/update")
def update_settings(
    req: SettingsUpdateRequest,
    x_admin_key: Optional[str] = Header(None, alias="X-Admin-Key"),
    authorization: Optional[str] = Header(None)
):
    """
    Dynamically updates API keys and blockchain RPC configuration.
    Requires admin authentication if ADMIN_API_KEY is configured in the environment.
    """
    # Enforce admin authorization check
    if settings.ADMIN_API_KEY:
        token = req.admin_key or x_admin_key
        if not token and authorization:
            if authorization.lower().startswith("bearer "):
                token = authorization[7:].strip()
            else:
                token = authorization.strip()
        if not token or token != settings.ADMIN_API_KEY:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Admin authorization required to modify system configuration."
            )

    # Input validations
    if req.contract_address is not None and req.contract_address.strip():
        clean_addr = req.contract_address.strip()
        if not re.match(r"^0x[a-fA-F0-9]{40}$", clean_addr):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid contract address: must be a 42-character 0x-prefixed hex string."
            )

    if req.ethereum_rpc_url is not None and req.ethereum_rpc_url.strip():
        clean_rpc = req.ethereum_rpc_url.strip()
        if not (clean_rpc.startswith("http://") or clean_rpc.startswith("https://") or
                clean_rpc.startswith("ws://") or clean_rpc.startswith("wss://")):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid Ethereum RPC URL: must start with http://, https://, ws://, or wss://"
            )

    if req.gemini_api_key is not None:
        settings.GEMINI_API_KEY = req.gemini_api_key.strip() if req.gemini_api_key.strip() else None
    if req.google_safe_browsing_api_key is not None:
        settings.GOOGLE_SAFE_BROWSING_API_KEY = req.google_safe_browsing_api_key.strip() if req.google_safe_browsing_api_key.strip() else None
    if req.virustotal_api_key is not None:
        settings.VIRUSTOTAL_API_KEY = req.virustotal_api_key.strip() if req.virustotal_api_key.strip() else None
    if req.ethereum_rpc_url is not None:
        settings.ETHEREUM_RPC_URL = req.ethereum_rpc_url.strip() if req.ethereum_rpc_url.strip() else None
    if req.contract_address is not None:
        settings.CONTRACT_ADDRESS = req.contract_address.strip() if req.contract_address.strip() else None

    # Reconnect blockchain service with new RPC/contract credentials
    from app.services.blockchain_service import blockchain_service
    blockchain_service.reconnect()

    return {
        "message": "Settings updated successfully",
        "gemini_configured": bool(settings.GEMINI_API_KEY),
        "safe_browsing_configured": bool(settings.GOOGLE_SAFE_BROWSING_API_KEY),
        "virustotal_configured": bool(settings.VIRUSTOTAL_API_KEY),
        "sepolia_rpc_configured": bool(settings.ETHEREUM_RPC_URL),
        "is_live_sepolia": blockchain_service.is_live_sepolia
    }

