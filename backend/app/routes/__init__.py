from app.routes.health import router as health_router
from app.routes.url import router as url_router
from app.routes.tls import router as tls_router
from app.routes.headers import router as headers_router
from app.routes.message import router as message_router
from app.routes.ip import router as ip_router
from app.routes.threats import router as threats_router
from app.routes.reports import router as reports_router
from app.routes.blockchain import router as blockchain_router
from app.routes.unified import router as unified_router
from app.routes.settings import router as settings_router

__all__ = [
    "health_router",
    "url_router",
    "tls_router",
    "headers_router",
    "message_router",
    "ip_router",
    "threats_router",
    "reports_router",
    "blockchain_router",
    "unified_router",
    "settings_router"
]

