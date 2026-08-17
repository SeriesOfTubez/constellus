"""
APScheduler integration for scheduled scan templates.

A single BackgroundScheduler lives in this process. On app startup we load
every enabled ScanTemplate with a non-empty schedule_cron and register a
cron job. Template create/update/delete refreshes the corresponding job.

When a job fires, the trigger function creates a ScanRun linked to the
template and hands it to scan_executor.launch (which creates its own DB
session and runs the scan inside a thread).

Multi-worker note: uvicorn defaults to a single worker per container, which
matches this in-process scheduler. A multi-worker deployment would need
either a shared scheduler (with a job store like SQLAlchemyJobStore) or
worker-local jobs gated by a Postgres advisory lock — neither is wired up
here.
"""

import logging
import threading
import uuid
from datetime import datetime, timedelta, timezone

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger

from app.core.database import SessionLocal
from app.models.scan import ScanKind, ScanRun, ScanStatus
from app.models.scan_template import ScanTemplate
from app.services import ct_refresher

log = logging.getLogger(__name__)

_scheduler: BackgroundScheduler | None = None
_lock = threading.Lock()

# Stable UUID for the seeded "Default monitoring" template. Using a fixed UUID
# makes seeding idempotent (`if not exists, create`) and survives restarts
# without recreating a deleted template — user removing it is a real choice.
DEFAULT_MONITORING_TEMPLATE_ID = uuid.UUID("00000000-0000-0000-0000-000000000001")


# ── Public API ────────────────────────────────────────────────────────────────

def start() -> None:
    """Initialize the scheduler and load all enabled templates."""
    global _scheduler
    with _lock:
        if _scheduler is not None:
            return
        _scheduler = BackgroundScheduler(timezone="UTC")
        _scheduler.start()
        log.info("APScheduler started")

    _seed_default_template()
    _seed_default_connectors()
    _load_existing_templates()
    _register_ct_refresher()
    _register_epss_refresher()
    _register_cpe_index_refresher()


def _seed_default_connectors() -> None:
    """Idempotently enable connectors that should be on out-of-the-box.

    Currently just Certspotter — it works with no configuration (free
    rate-limited tier) and is core to passive subdomain discovery. If a
    user disables it via the UI, that choice persists; we only insert a
    row if none exists for the connector.
    """
    from app.models.connector_config import ConnectorConfig
    db = SessionLocal()
    try:
        for connector_id in ("certspotter",):
            existing = db.query(ConnectorConfig).filter(
                ConnectorConfig.connector_id == connector_id
            ).first()
            if existing is not None:
                continue
            db.add(ConnectorConfig(connector_id=connector_id, enabled=True))
            log.info("Seeded default-enabled connector %s", connector_id)
        db.commit()
    finally:
        db.close()


def _register_ct_refresher() -> None:
    """Register the Certificate Transparency cache refresher as a recurring
    interval job. Keeps the cache warm without blocking scan runs."""
    if _scheduler is None:
        return
    _scheduler.add_job(
        ct_refresher.tick,
        trigger=IntervalTrigger(seconds=ct_refresher.TICK_INTERVAL_SECONDS),
        id="ct_refresher",
        name="Certificate Transparency cache refresher",
        replace_existing=True,
        coalesce=True,
        max_instances=1,
    )
    log.info("Scheduled ct_refresher (every %ds)", ct_refresher.TICK_INTERVAL_SECONDS)


def _register_epss_refresher() -> None:
    """Sample EPSS scores for all active CVEs every 12h, then prune expired rows.

    FIRST.org publishes once per day; 12h polling catches same-day score
    changes quickly while the PK in epss_history deduplicates to one row
    per (cve_id, calendar day) automatically.

    Retention rides on the same tick rather than a separate job — pruning is
    idempotent, so running it twice a day is harmless, and it replaces the
    TimescaleDB retention policy removed from migration 0033.
    """
    if _scheduler is None:
        return
    _scheduler.add_job(
        _run_epss_refresh,
        trigger=IntervalTrigger(hours=12),
        id="epss_refresher",
        name="EPSS history 12h refresh",
        replace_existing=True,
        coalesce=True,
        max_instances=1,
    )
    log.info("Scheduled epss_refresher (every 12h)")


def _run_epss_refresh() -> None:
    from app.services import epss_history_service

    db = SessionLocal()
    try:
        count = epss_history_service.refresh_all_active(db)
        log.info("EPSS history refresh complete — %d rows upserted", count)
    except Exception:
        log.error("EPSS history refresh failed", exc_info=True)
    # Retention runs even when the refresh failed — an upstream FIRST.org
    # outage must not let the table grow unbounded. Its own session because a
    # failed refresh may have left this one needing a rollback.
    try:
        db.rollback()
        epss_history_service.prune_expired(db)
    except Exception:
        log.error("EPSS history retention failed", exc_info=True)
    finally:
        db.close()


def _register_cpe_index_refresher() -> None:
    """Refresh the local CPE→CVE version-range index daily (native version→CVE
    matching, #66 B0). First run fires ~60s after startup so a fresh deploy
    seeds from the VulnCheck backup without blocking boot; thereafter the seed is
    skipped (idempotent) and only the cheap VulnCheck lastMod delta runs.
    """
    if _scheduler is None:
        return
    _scheduler.add_job(
        _run_cpe_index_refresh,
        trigger=IntervalTrigger(hours=24),
        id="cpe_index_refresher",
        name="CPE→CVE index daily refresh",
        replace_existing=True,
        coalesce=True,
        max_instances=1,
        next_run_time=datetime.now(timezone.utc) + timedelta(seconds=60),
    )
    log.info("Scheduled cpe_index_refresher (every 24h; first run ~60s after start)")


def _run_cpe_index_refresh() -> None:
    from app.services import cpe_cve_sync

    db = SessionLocal()
    try:
        stats = cpe_cve_sync.refresh(db)
        log.info("CPE index refresh complete — %s", stats)
    except Exception:
        log.error("CPE index refresh failed", exc_info=True)
    finally:
        db.close()


def shutdown() -> None:
    global _scheduler
    with _lock:
        if _scheduler is None:
            return
        _scheduler.shutdown(wait=False)
        _scheduler = None
        log.info("APScheduler stopped")


def upsert_template_job(template: ScanTemplate) -> None:
    """Add or update the cron job for a template. No-op if the template is
    disabled, has no schedule_cron, or the scheduler isn't running."""
    if _scheduler is None:
        return
    job_id = str(template.id)
    if not template.enabled or not template.schedule_cron:
        remove_template_job(template.id)
        return

    try:
        trigger = CronTrigger.from_crontab(template.schedule_cron, timezone="UTC")
    except ValueError:
        log.warning(
            "Template %s has invalid schedule_cron %r — skipping",
            template.id, template.schedule_cron,
        )
        return

    _scheduler.add_job(
        _run_template,
        trigger=trigger,
        id=job_id,
        args=[template.id],
        name=template.name or f"template:{template.id}",
        replace_existing=True,
        misfire_grace_time=300,
        coalesce=True,
        max_instances=1,
    )
    log.info("Scheduled template %s (%s) with cron %r", template.id, template.name, template.schedule_cron)


def remove_template_job(template_id: uuid.UUID) -> None:
    if _scheduler is None:
        return
    try:
        _scheduler.remove_job(str(template_id))
    except Exception:
        pass


def list_jobs() -> list[dict]:
    if _scheduler is None:
        return []
    return [
        {
            "id": j.id,
            "name": j.name,
            "next_run_time": j.next_run_time.isoformat() if j.next_run_time else None,
        }
        for j in _scheduler.get_jobs()
    ]


# ── Internal ──────────────────────────────────────────────────────────────────

def _seed_default_template() -> None:
    """Idempotently create the default global monitoring template on first run.

    Runs all three phases (discovery → enrichment → scanning) daily at 02:00
    UTC against every target in the system. Batched at 50 targets/chunk with
    no inter-batch delay — tune per deployment by editing the row directly if
    needed. If a user deletes this template, it stays deleted (we check the
    fixed seed UUID, not by name).
    """
    db = SessionLocal()
    try:
        if db.get(ScanTemplate, DEFAULT_MONITORING_TEMPLATE_ID):
            return

        tmpl = ScanTemplate(
            id=DEFAULT_MONITORING_TEMPLATE_ID,
            name="Default monitoring",
            scope={},
            options={
                "cert_transparency": True,
                "subfinder": True,
                "dnsrecon": False,
                "bruteforce": False,
            },
            schedule_cron="0 2 * * *",
            enabled=True,
            dynamic_scope=True,
            target_tag_filter=[],
            batch_size=50,
            batch_delay_seconds=0,
        )
        db.add(tmpl)
        db.commit()
        log.info("Seeded default monitoring template (id=%s)", DEFAULT_MONITORING_TEMPLATE_ID)
    finally:
        db.close()


def _load_existing_templates() -> None:
    db = SessionLocal()
    try:
        templates = (
            db.query(ScanTemplate)
            .filter(ScanTemplate.enabled == True)  # noqa: E712
            .filter(ScanTemplate.schedule_cron.isnot(None))
            .all()
        )
        for tmpl in templates:
            upsert_template_job(tmpl)
        log.info("Loaded %d scheduled templates", len(templates))
    finally:
        db.close()


def _run_template(template_id: uuid.UUID) -> None:
    """Fired by APScheduler. Creates a ScanRun from the template and launches it."""
    from app.api.connectors import REGISTRY
    from app.services import scan_executor

    db = SessionLocal()
    try:
        tmpl = db.get(ScanTemplate, template_id)
        if not tmpl or not tmpl.enabled:
            log.info("Template %s gone or disabled — skipping scheduled run", template_id)
            return

        run = ScanRun(
            id=uuid.uuid4(),
            name=f"{tmpl.name} (scheduled)",
            status=ScanStatus.PENDING,
            kind=ScanKind.MONITORING,
            scope=tmpl.scope,
            options=tmpl.options or {},
            template_id=tmpl.id,
            created_at=datetime.now(timezone.utc),
        )
        db.add(run)
        db.commit()
        run_id = run.id
        scope = run.scope
    finally:
        db.close()

    # scan_executor.launch creates its own session
    log.info("Launching scheduled run %s for template %s", run_id, template_id)
    scan_executor.launch(run_id, scope, REGISTRY)
