import asyncio
import logging
from contextlib import asynccontextmanager
from pathlib import Path

log = logging.getLogger(__name__)

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from app.api import connectors, scans, findings, assets, auth, users, saml, targets, logs, tags
from app.api import claims
from app.api import edges
from app.api import hygiene
from app.api import monitoring
from app.api import notifications
from app.api import scan_templates
from app.api import settings as settings_api
from app.api import system
from app.core.config import require_configured_secret_key, settings
from app.core.database import get_db


@asynccontextmanager
async def lifespan(app: FastAPI):
    require_configured_secret_key()

    db = next(get_db())
    try:
        from app.services.connector_config import load_overrides_from_db
        from app.api.connectors import REGISTRY
        load_overrides_from_db(db, REGISTRY)
    finally:
        db.close()

    from app.core.logging import setup_db_logging
    setup_db_logging()
    log.info("Constellus backend started — logging active")

    from app.services import scheduler
    scheduler.start()

    task = asyncio.create_task(_log_cleanup_loop())
    yield
    task.cancel()
    scheduler.shutdown()


async def _log_cleanup_loop() -> None:
    """Purge logs older than the configured retention period. Runs every hour."""
    while True:
        try:
            await asyncio.sleep(3600)
            _purge_old_logs()
        except asyncio.CancelledError:
            break
        except Exception:
            pass


def _purge_old_logs() -> None:
    from datetime import datetime, timedelta, timezone
    from app.core.database import SessionLocal
    from app.models.system_log import SystemLog
    from app.services.app_settings import get_int

    db = SessionLocal()
    try:
        days = get_int(db, "log_retention_days") or 15
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        deleted = db.query(SystemLog).filter(SystemLog.created_at < cutoff).delete()
        if deleted:
            db.commit()
            log.info("Log retention: purged %d entries older than %d days", deleted, days)
    except Exception as exc:
        log.warning("Log retention cleanup failed: %s", exc)
    finally:
        db.close()


app = FastAPI(
    title="Constellus",
    description="External Attack Surface Management",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router, prefix="/api/auth", tags=["auth"])
app.include_router(connectors.router, prefix="/api/connectors", tags=["connectors"])
app.include_router(scans.router, prefix="/api/scans", tags=["scans"])
app.include_router(scan_templates.router, prefix="/api/scan-templates", tags=["scan-templates"])
app.include_router(findings.router, prefix="/api/findings", tags=["findings"])
app.include_router(assets.router, prefix="/api/assets", tags=["assets"])
app.include_router(users.router, prefix="/api/users", tags=["users"])
app.include_router(saml.router, prefix="/api/auth/saml", tags=["saml"])
app.include_router(targets.router, prefix="/api/targets", tags=["targets"])
app.include_router(logs.router, prefix="/api/logs", tags=["logs"])
app.include_router(settings_api.router, prefix="/api/settings", tags=["settings"])
app.include_router(tags.router, prefix="/api/tags", tags=["tags"])
app.include_router(system.router, prefix="/api/system", tags=["system"])
app.include_router(monitoring.router, prefix="/api/monitoring", tags=["monitoring"])
app.include_router(notifications.router, prefix="/api/notifications", tags=["notifications"])
app.include_router(edges.router, prefix="/api/edges", tags=["edges"])
app.include_router(claims.router, prefix="/api/claims", tags=["claims"])
app.include_router(hygiene.router, prefix="/api/hygiene", tags=["hygiene"])


@app.get("/api/health")
def health():
    return {"status": "ok"}


# Serve the compiled frontend. Must come after all API routes.
_static_dir = Path(__file__).parent.parent / "static"
if _static_dir.exists():
    app.mount("/assets", StaticFiles(directory=str(_static_dir / "assets")), name="assets")

    @app.get("/{full_path:path}")
    def spa_fallback(full_path: str):
        index = _static_dir / "index.html"
        return FileResponse(str(index))
