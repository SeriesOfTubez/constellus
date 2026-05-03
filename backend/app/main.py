from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api import connectors, scans, findings, assets, auth
from app.core.config import settings

app = FastAPI(
    title="Sextant",
    description="External Attack Surface Management",
    version="0.1.0",
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


@app.get("/api/health")
def health():
    return {"status": "ok"}
