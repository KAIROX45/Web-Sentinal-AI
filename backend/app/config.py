import os
from typing import List, Optional
from pydantic_settings import BaseSettings, SettingsConfigDict

_BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_DEFAULT_DB_PATH = os.path.join(_BACKEND_DIR, "sentinelx.db").replace("\\", "/")


class Settings(BaseSettings):
    APP_NAME: str = "WebSentinel AI"
    APP_VERSION: str = "1.0.0"
    ENVIRONMENT: str = "development"
    DEBUG: bool = True

    # Security administration
    ADMIN_API_KEY: Optional[str] = os.getenv("ADMIN_API_KEY", None)

    # Database: Use absolute path to backend sentinelx.db to avoid path fragmentation
    DATABASE_URL: str = os.getenv("DATABASE_URL", f"sqlite:///{_DEFAULT_DB_PATH}")

    # API Keys (optional; platform runs robust local cybersecurity heuristic engines if unset)
    GEMINI_API_KEY: Optional[str] = os.getenv("GEMINI_API_KEY", None)
    GOOGLE_SAFE_BROWSING_API_KEY: Optional[str] = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", None)
    VIRUSTOTAL_API_KEY: Optional[str] = os.getenv("VIRUSTOTAL_API_KEY", None)

    # Blockchain (Sepolia Testnet / Local Ledger)
    ETHEREUM_RPC_URL: Optional[str] = os.getenv("ETHEREUM_RPC_URL", None)
    CONTRACT_ADDRESS: Optional[str] = os.getenv("CONTRACT_ADDRESS", None)
    WALLET_PRIVATE_KEY: Optional[str] = os.getenv("WALLET_PRIVATE_KEY", None)
    SEPOLIA_CHAIN_ID: int = 11155111

    # Security & Scanning limits
    REQUEST_TIMEOUT_SECONDS: float = 6.0
    MAX_REDIRECT_HOPS: int = 5
    MAX_CONTENT_LENGTH_BYTES: int = 1048576  # 1 MB
    RATE_LIMIT_PER_MINUTE: int = 60
    USER_AGENT: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) WebSentinel-ThreatScanner/1.0"

    # CORS
    CORS_ORIGINS: List[str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
        "https://web-sentinal-ai.vercel.app"
    ]

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )


settings = Settings()

