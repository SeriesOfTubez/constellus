from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from app.api import connectors, scans, findings, assets, auth, users, saml
from app.api import system
from app.core.config import settings
from app.core.database import get_db


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Load DB-stored connector config into the in-process secrets override layer
    db = next(get_db())
    try:
        from app.services.connector_config import load_overrides_from_db
        from app.api.connectors import REGISTRY
        load_overrides_from_db(db, REGISTRY)
    finally:
        db.close()
    yield


app = FastAPI(
    title="Sextant",
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
app.include_router(findings.router, prefix="/api/findings", tags=["findings"])
app.include_router(assets.router, prefix="/api/assets", tags=["assets"])
app.include_router(users.router, prefix="/api/users", tags=["users"])
app.include_router(saml.router, prefix="/api/auth/saml", tags=["saml"])
app.include_router(system.router, prefix="/api/system", tags=["system"])


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
