import time
import uuid
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.config import settings
from app.database import engine, Base, SessionLocal
from app.models import ScanRecord, ThreatIOC, BlockchainRecord
from app.services.threat_intelligence import seed_ioc_database
from app.services.rate_limiter import rate_limiter
from app.routes import (
    health_router,
    url_router,
    tls_router,
    headers_router,
    message_router,
    ip_router,
    threats_router,
    reports_router,
    blockchain_router,
    unified_router,
    settings_router
)

# Configure structured logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("websentinel.api")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: initialize database tables and seed curated threat intelligence
    logger.info("Initializing WebSentinel AI Database Schema...")
    Base.metadata.create_all(bind=engine)
    
    # Safe migration for new columns on SQLite
    with engine.connect() as conn:
        try:
            from sqlalchemy import text
            conn.execute(text("ALTER TABLE threat_iocs ADD COLUMN is_demo BOOLEAN DEFAULT 0"))
            conn.commit()
        except Exception:
            pass

    db = SessionLocal()
    try:
        seed_ioc_database(db)
    finally:
        db.close()
    
    logger.info("WebSentinel AI Cyber Threat Intelligence Engine ready.")
    yield
    logger.info("Shutting down WebSentinel AI backend...")


app = FastAPI(
    title=settings.APP_NAME,
    description="Enterprise AI-Powered Web Threat Detection & Cybersecurity Intelligence Platform",
    version=settings.APP_VERSION,
    lifespan=lifespan
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# In-memory sliding window rate limiting middleware
@app.middleware("http")
async def rate_limiting_middleware(request: Request, call_next):
    # Exempt OPTIONS preflight requests, health checks, documentation, and static paths
    if request.method == "OPTIONS":
        return await call_next(request)

    path = request.url.path
    if path in ("/health", "/api/health", "/docs", "/openapi.json", "/redoc") or path.startswith("/static"):
        return await call_next(request)

    client_ip = request.client.host if request.client else "127.0.0.1"
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        client_ip = forwarded_for.split(",")[0].strip()

    allowed, retry_after = await rate_limiter.acquire(client_ip)
    if not allowed:
        return JSONResponse(
            status_code=429,
            content={
                "error": "Too Many Requests",
                "detail": f"Rate limit exceeded: maximum {settings.RATE_LIMIT_PER_MINUTE} requests per minute.",
                "retry_after_seconds": retry_after
            },
            headers={"Retry-After": str(retry_after)}
        )

    return await call_next(request)


# Response time header middleware
@app.middleware("http")
async def add_process_time_header(request: Request, call_next):
    start_time = time.time()
    response = await call_next(request)
    process_time = (time.time() - start_time) * 1000
    response.headers["X-Process-Time-Ms"] = f"{process_time:.2f}"
    return response


# Centralized sanitized exception handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    error_id = str(uuid.uuid4())[:8]
    logger.error(f"Unhandled exception [{error_id}] during {request.method} {request.url.path}: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal Server Error",
            "detail": "An unexpected internal server error occurred. Please try again later.",
            "error_id": error_id,
            "path": request.url.path
        }
    )


# Register modular routers
app.include_router(health_router, prefix="/api")
app.include_router(url_router, prefix="/api")
app.include_router(tls_router, prefix="/api")
app.include_router(headers_router, prefix="/api")
app.include_router(message_router, prefix="/api")
app.include_router(ip_router, prefix="/api")
app.include_router(threats_router, prefix="/api")
app.include_router(reports_router, prefix="/api")
app.include_router(blockchain_router, prefix="/api")
app.include_router(unified_router, prefix="/api")
app.include_router(settings_router, prefix="/api")


@app.get("/")
def root():
    return {
        "platform": settings.APP_NAME,
        "tagline": "Detect. Investigate. Understand. Verify.",
        "version": settings.APP_VERSION,
        "status": "operational",
        "docs_url": "/docs",
        "api_prefix": "/api"
    }

