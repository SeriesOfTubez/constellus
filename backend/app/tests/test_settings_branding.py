"""The curated org accent set (planning#337).

An org-chosen accent must never read as a severity colour, so the accent is not a
free picker: it is a small allowlist of colours that all sit at the same OKLCH
lightness and chroma, with hues well clear of the severity hues. The floor is 40
degrees; lime is the one named exception (planning#367).

This file is the guard that three things agree: the backend allowlist
(`app.api.settings.ACCENT_PALETTE`), the frontend swatches
(`frontend/src/lib/branding.ts`) and the identity default
(`app_settings.DEFAULTS["org.brand_accent"]`). It also measures the palette
against the severity tokens in `frontend/src/index.css`.

Run with pytest via `backend/scripts/test.sh` (it needs the throwaway test DB).
"""
import math
import re
import uuid
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api import settings as settings_api
from app.api.deps import get_current_user
from app.api.settings import ACCENT_PALETTE
from app.core.database import SessionLocal, get_db
from app.models.app_settings import AppSetting
from app.models.user import UserRole
from app.services import app_settings as svc
from app.tests._users import user_with

ROOT = Path(__file__).resolve().parents[3]
BRANDING_TS = ROOT / "frontend" / "src" / "lib" / "branding.ts"
INDEX_CSS = ROOT / "frontend" / "src" / "index.css"

# Hue distance from every severity hue, in degrees. Lime was judged by eye beside Medium
# and Clean in a mockup and accepted at 37 (Jason, 2026-11-12, planning#367). It is keyed
# by value, so a changed lime loses the exception and a new accent is held to 40.
HUE_FLOOR = 40
HUE_FLOOR_EXCEPTIONS = {"#aeca82": 35}


def _lin(c: float) -> float:
    c /= 255
    return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4


def oklch(hex_colour: str) -> tuple[float, float, float]:
    h = hex_colour.lstrip("#")
    r, g, b = (_lin(int(h[i:i + 2], 16)) for i in (0, 2, 4))
    l = (0.4122214708 * r + 0.5363325363 * g + 0.0514459929 * b) ** (1 / 3)
    m = (0.2119034982 * r + 0.6806995451 * g + 0.1073969566 * b) ** (1 / 3)
    s = (0.0883024619 * r + 0.2817188376 * g + 0.6299787005 * b) ** (1 / 3)
    L = 0.2104542553 * l + 0.7936177850 * m - 0.0040720468 * s
    a = 1.9779984951 * l - 2.4285922050 * m + 0.4505937099 * s
    bb = 0.0259040371 * l + 0.7827717662 * m - 0.8086757660 * s
    return L, math.hypot(a, bb), math.degrees(math.atan2(bb, a)) % 360


def _client(with_admin: bool = True) -> TestClient:
    app = FastAPI()
    app.include_router(settings_api.router, prefix="/api/settings")

    def _db():
        db = SessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = _db
    if with_admin:
        user = user_with(
            UserRole.ADMIN.value,
            id=uuid.uuid4(),
            email="branding-test-admin@example.invalid",
            full_name="Branding test admin",
            is_active=True,
        )
        app.dependency_overrides[get_current_user] = lambda: user
    return TestClient(app)


def _delete_accent_row() -> None:
    db = SessionLocal()
    try:
        db.query(AppSetting).filter_by(key="org.brand_accent").delete()
        db.commit()
    finally:
        db.close()


def _stored_accent() -> str | None:
    db = SessionLocal()
    try:
        row = db.get(AppSetting, "org.brand_accent")
        return row.value if row else None
    finally:
        db.close()


@pytest.fixture(autouse=True)
def clean_accent_row():
    _delete_accent_row()
    yield
    _delete_accent_row()


def test_rejects_an_accent_outside_the_curated_set():
    # An old swatch, 39 degrees from Clean.
    r = _client().put("/api/settings/", json={"org_brand_accent": "#06b6d4"})
    assert r.status_code == 422
    assert "org_brand_accent" in str(r.json()["detail"])
    assert _stored_accent() is None


def test_rejects_an_accent_that_left_the_curated_set():
    # Orchid, Magenta, the old Pink and the considered-then-dropped Silver.
    for gone in ("#d2acee", "#dba9e6", "#e1a7df", "#b1c0c8"):
        r = _client().put("/api/settings/", json={"org_brand_accent": gone})
        assert r.status_code == 422, gone
    assert _stored_accent() is None


def test_a_stored_accent_that_left_the_curated_set_reads_as_the_default():
    db = SessionLocal()
    try:
        svc.set_value(db, "org.brand_accent", "#d2acee")
    finally:
        db.close()
    assert _stored_accent() == "#d2acee"

    pub = _client(with_admin=False).get("/api/settings/branding")
    assert pub.status_code == 200
    assert pub.json()["org_brand_accent"] == "#66d0df"
    full = _client().get("/api/settings/")
    assert full.status_code == 200
    assert full.json()["org_brand_accent"] == "#66d0df"


def test_accepts_every_curated_accent():
    assert len(ACCENT_PALETTE) == 4
    for hx in sorted(ACCENT_PALETTE):
        r = _client().put("/api/settings/", json={"org_brand_accent": hx})
        assert r.status_code == 200, hx
        pub = _client(with_admin=False).get("/api/settings/branding")
        assert pub.json()["org_brand_accent"] == hx


def test_accepts_a_curated_accent_case_insensitively():
    r = _client().put("/api/settings/", json={"org_brand_accent": "#C7AFF5"})
    assert r.status_code == 200
    assert r.json()["org_brand_accent"] == "#c7aff5"

    pub = _client(with_admin=False).get("/api/settings/branding")
    assert pub.status_code == 200
    assert pub.json()["org_brand_accent"] == "#c7aff5"
    assert _stored_accent() == "#c7aff5"


def test_default_accent_is_the_identity_cyan():
    pub = _client(with_admin=False).get("/api/settings/branding")
    assert pub.status_code == 200
    assert pub.json()["org_brand_accent"] == "#66d0df"
    assert svc.DEFAULTS["org.brand_accent"] == "#66d0df"
    assert "#66d0df" in ACCENT_PALETTE


def test_palette_matches_the_frontend():
    if not BRANDING_TS.exists():
        pytest.skip(f"frontend source not checked out: {BRANDING_TS}")
    src = BRANDING_TS.read_text()

    # skip past the `{ name: string; value: string }[]` type annotation to the array literal
    block = re.search(r"ACCENT_PALETTE[^=]*=\s*\[[^\]]*\]", src, re.DOTALL)
    assert block, "ACCENT_PALETTE block not found in branding.ts"
    found = re.findall(r"#[0-9a-f]{6}", block.group(0))
    assert len(found) == len(ACCENT_PALETTE)
    assert set(found) == ACCENT_PALETTE

    default = re.search(
        r"BRANDING_DEFAULTS[^}]*?org_brand_accent:\s*\"(#[0-9a-f]{6})\"", src, re.DOTALL
    )
    assert default, "org_brand_accent default not found in BRANDING_DEFAULTS"
    assert default.group(1) == svc.DEFAULTS["org.brand_accent"]


def test_every_curated_accent_clears_the_severity_hues():
    if not INDEX_CSS.exists():
        pytest.skip(f"frontend source not checked out: {INDEX_CSS}")
    css = INDEX_CSS.read_text()
    sev = re.findall(r"--sev-(critical|high|medium|low|clean):\s*(#[0-9a-f]{6})", css)
    assert len(sev) == 5, sev
    sev_hues = {name: oklch(hx)[2] for name, hx in sev}

    assert set(HUE_FLOOR_EXCEPTIONS) <= ACCENT_PALETTE, "an exception names no curated accent"
    for hx in sorted(ACCENT_PALETTE):
        L, C, H = oklch(hx)
        assert 0.78 <= L <= 0.82, f"{hx} lightness {L:.3f}"
        assert 0.09 <= C <= 0.11, f"{hx} chroma {C:.3f}"
        dists = {}
        for name, sh in sev_hues.items():
            d = abs(H - sh) % 360
            dists[name] = min(d, 360 - d)
        nearest = min(dists, key=lambda k: dists[k])
        floor = HUE_FLOOR_EXCEPTIONS.get(hx, HUE_FLOOR)
        assert dists[nearest] >= floor, (
            f"{hx} (hue {H:.1f}) is only {dists[nearest]:.1f} degrees from {nearest}"
        )
        if hx in HUE_FLOOR_EXCEPTIONS:
            assert dists[nearest] < HUE_FLOOR, f"{hx} clears {HUE_FLOOR} and needs no exception"
