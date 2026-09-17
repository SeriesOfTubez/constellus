"""Local mirror of constellus-binaries' `cloud-ranges` dataset (planning#179).

The dataset is published as a manifest (sha256 + generated_at + record_count)
plus a gzipped NDJSON file of provider CIDR prefixes, refreshed daily by
`app.services.scheduler`. `tenancy_enricher` reads this mirror via `lookup`
and `dataset_state`; nothing in a scan path calls out to it, and nothing in
this module calls out to anything but the two published release assets
below.
"""

import gzip
import hashlib
import ipaddress
import json
import logging
import os
import tempfile
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import httpx
from sqlalchemy import insert, text
from sqlalchemy.orm import Session

from app.connectors.http import connector_get
from app.models.cloud_range import CloudRange, CloudRangeMeta

log = logging.getLogger(__name__)

_BASE = "https://github.com/SeriesOfTubez/constellus-binaries/releases/download/cloud-ranges-latest"
MANIFEST_URL = f"{_BASE}/manifest.json"
DATASET_URL = f"{_BASE}/cloud-ranges.ndjson.gz"

# `generated_at` means "last verified current" and the upstream workflow runs
# daily, so this is three consecutive missed runs — a broken mirror, not a
# quiet week. SCHEMA.md asks a consumer to say so loudly rather than silently
# trusting month-old ranges in an authorisation decision.
STALE_AFTER = timedelta(days=3)

_SERVICE_CLASSES = {"compute", "edge", "storage", "managed", "unknown"}
_REQUIRED_LINE_KEYS = ("prefix", "ip_version", "provider", "service_class", "source")

_INSERT_CHUNK_SIZE = 5000


@dataclass
class RefreshResult:
    ok: bool
    changed: bool
    record_count: int
    dataset_sha256: str | None
    reason: str | None = None


@dataclass
class CloudRangeMatch:
    prefix: str
    provider: str
    service_raw: str | None
    service_class: str
    region: str | None
    source: str


@dataclass
class DatasetState:
    dataset_sha256: str
    generated_at: datetime
    record_count: int
    stale: bool


def refresh(db: Session) -> RefreshResult:
    """Refresh the local mirror from the published manifest/dataset.

    Fails soft — this runs from APScheduler and must never raise into the
    scheduler. On any unexpected error, logs it and returns ok=False rather
    than propagating.
    """
    try:
        return _refresh(db)
    except Exception:
        log.exception("cloud_ranges: refresh failed")
        db.rollback()
        return RefreshResult(ok=False, changed=False, record_count=0, dataset_sha256=None, reason="exception")


def _refresh(db: Session) -> RefreshResult:
    # follow_redirects: a GitHub release asset 302s to a signed
    # release-assets.githubusercontent.com URL. Both URLs here are fixed
    # constants, never derived from asset data, so following is safe —
    # see connector_get's own note on why it is off by default.
    manifest_resp = connector_get(MANIFEST_URL, timeout=30, follow_redirects=True)
    manifest_resp.raise_for_status()
    manifest = manifest_resp.json()
    if not isinstance(manifest, dict) or not all(
        k in manifest for k in ("dataset_sha256", "generated_at", "record_count")
    ):
        log.error("cloud_ranges: manifest missing required keys: %r", manifest)
        return RefreshResult(ok=False, changed=False, record_count=0, dataset_sha256=None, reason="bad_manifest")

    new_sha256 = manifest["dataset_sha256"]
    generated_at = _parse_datetime(manifest["generated_at"])
    record_count = manifest["record_count"]

    existing_meta = db.get(CloudRangeMeta, True)

    if existing_meta is not None and existing_meta.dataset_sha256 == new_sha256:
        # Digest unchanged — do not download. Keeps "did the ranges change"
        # and "is the mirror alive" separate questions: the manifest (and
        # therefore generated_at/refreshed_at) is refreshed even on an
        # unchanged day, so staleness detection still works.
        existing_meta.generated_at = generated_at
        existing_meta.refreshed_at = datetime.now(timezone.utc)
        existing_meta.manifest = manifest
        db.commit()
        return RefreshResult(ok=True, changed=False, record_count=existing_meta.record_count, dataset_sha256=new_sha256)

    fd, tmp_path = tempfile.mkstemp(suffix=".ndjson.gz")
    os.close(fd)
    try:
        # Stream to a temp file rather than buffering in memory — the
        # cpe_cve_sync.py:102 precedent for a large downloaded asset.
        rows, computed_sha256 = _download_and_parse(tmp_path)

        if computed_sha256 != new_sha256:
            log.error(
                "cloud_ranges: digest mismatch — manifest says %s, computed %s",
                new_sha256, computed_sha256,
            )
            return RefreshResult(ok=False, changed=False, record_count=0, dataset_sha256=None, reason="digest_mismatch")

        if rows is None:
            # _download_and_parse already logged the specific reason.
            return RefreshResult(ok=False, changed=False, record_count=0, dataset_sha256=None, reason="bad_dataset")

        if len(rows) != record_count:
            log.error(
                "cloud_ranges: parsed %d rows but manifest declares record_count=%d",
                len(rows), record_count,
            )
            return RefreshResult(ok=False, changed=False, record_count=0, dataset_sha256=None, reason="record_count_mismatch")

        try:
            db.execute(text("DELETE FROM cloud_ranges"))
            for start in range(0, len(rows), _INSERT_CHUNK_SIZE):
                chunk = rows[start:start + _INSERT_CHUNK_SIZE]
                db.execute(insert(CloudRange), chunk)

            now = datetime.now(timezone.utc)
            if existing_meta is None:
                db.add(CloudRangeMeta(
                    id=True,
                    dataset_sha256=new_sha256,
                    generated_at=generated_at,
                    record_count=record_count,
                    refreshed_at=now,
                    manifest=manifest,
                ))
            else:
                existing_meta.dataset_sha256 = new_sha256
                existing_meta.generated_at = generated_at
                existing_meta.record_count = record_count
                existing_meta.refreshed_at = now
                existing_meta.manifest = manifest

            db.commit()
        except Exception:
            db.rollback()
            raise

        log.info("cloud_ranges: refreshed — %d rows loaded (sha256=%s)", len(rows), new_sha256)
        return RefreshResult(ok=True, changed=True, record_count=len(rows), dataset_sha256=new_sha256)
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


def _download_dataset_to_file(tmp_path: str) -> None:
    """Stream `DATASET_URL` to `tmp_path`. Split out from `_download_and_parse`
    so tests can monkeypatch this one raw-assignment-style (cloud_ranges is in
    conftest.py's _GUARDED_MODULES) without touching the global `httpx` module."""
    with httpx.stream("GET", DATASET_URL, timeout=300, follow_redirects=True) as r:
        r.raise_for_status()
        with open(tmp_path, "wb") as f:
            for chunk in r.iter_bytes(1 << 20):
                f.write(chunk)


def _download_and_parse(tmp_path: str) -> tuple[list[dict] | None, str]:
    """Download the gzipped dataset to `tmp_path`, then parse it.

    Returns (rows_as_dicts, computed_sha256_of_uncompressed_bytes) — the
    digest is computed over the raw uncompressed NDJSON bytes exactly as
    published, before any line splitting/stripping, so it matches whatever
    the upstream build hashed. `rows` is None if a line failed validation
    (a bad line aborts the whole load, same posture as the upstream build).
    """
    _download_dataset_to_file(tmp_path)

    with gzip.open(tmp_path, "rb") as f:
        raw = f.read()
    computed_sha256 = hashlib.sha256(raw).hexdigest()

    rows: list[dict] = []
    for line_no, line in enumerate(raw.decode("utf-8").splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            log.error("cloud_ranges: line %d is not valid JSON — aborting load", line_no)
            return None, computed_sha256

        if not isinstance(obj, dict) or not all(k in obj for k in _REQUIRED_LINE_KEYS):
            log.error("cloud_ranges: line %d missing required keys — aborting load: %r", line_no, obj)
            return None, computed_sha256

        if obj["service_class"] not in _SERVICE_CLASSES:
            log.error(
                "cloud_ranges: line %d has out-of-vocabulary service_class %r — aborting load",
                line_no, obj["service_class"],
            )
            return None, computed_sha256

        rows.append({
            "prefix": obj["prefix"],
            "ip_version": obj["ip_version"],
            "provider": obj["provider"],
            "service_raw": obj.get("service_raw"),
            "service_class": obj["service_class"],
            "region": obj.get("region"),
            "source": obj["source"],
        })

    return rows, computed_sha256


def lookup(db: Session, ip: str) -> CloudRangeMatch | None:
    """The most specific `cloud_ranges` prefix containing `ip`, or None.

    Specificity rule (SCHEMA.md, verbatim): longest matching prefix first,
    and among equal-length matches prefer any service_class other than
    'unknown'. This is the single most misreadable line in this module —
    the ORDER BY below implements exactly that sentence.
    """
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return None

    row = db.execute(
        text(
            "SELECT prefix::text, provider, service_raw, service_class, region, source "
            "FROM cloud_ranges "
            "WHERE prefix >>= CAST(:ip AS inet) "
            "ORDER BY masklen(prefix) DESC, "
            "         (service_class = 'unknown') ASC "
            "LIMIT 1"
        ),
        {"ip": ip},
    ).first()

    if row is None:
        return None
    return CloudRangeMatch(
        prefix=row[0], provider=row[1], service_raw=row[2],
        service_class=row[3], region=row[4], source=row[5],
    )


def dataset_state(db: Session) -> DatasetState | None:
    meta = db.get(CloudRangeMeta, True)
    if meta is None:
        return None
    stale = datetime.now(timezone.utc) - meta.generated_at > STALE_AFTER
    return DatasetState(
        dataset_sha256=meta.dataset_sha256,
        generated_at=meta.generated_at,
        record_count=meta.record_count,
        stale=stale,
    )


def _parse_datetime(value: str) -> datetime:
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt
