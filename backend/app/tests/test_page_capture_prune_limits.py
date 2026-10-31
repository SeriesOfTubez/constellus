"""Image pruning and the proxy limits file (planning#280 S5b-2b slice b, planning#317).

Run through backend/scripts/test.sh. Directories are tmp_path.
"""

import ast
import json
import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from sqlalchemy.exc import IntegrityError

from app.core.database import SessionLocal
from app.models.app_settings import AppSetting
from app.models.observer import Observer
from app.models.page_capture import PageCapture
from app.services import app_settings
from app.services import page_capture as pc
from app.tests.test_page_capture_service import WEBP, _candidate, env, w  # noqa: F401 (fixtures)

_KEYS = (pc.IMAGE_KEEP_COUNT_KEY, pc.PROXY_CONNECT_TIMEOUT_KEY, pc.PROXY_IDLE_TIMEOUT_KEY,
         pc.PROXY_MAX_CONNECTIONS_KEY)


@pytest.fixture
def settings_restore():
    with SessionLocal() as s:
        snaps = {k: (s.get(AppSetting, k).value if s.get(AppSetting, k) else None) for k in _KEYS}
    yield
    with SessionLocal() as s:
        for k, v in snaps.items():
            row = s.get(AppSetting, k)
            if v is None and row is not None:
                s.delete(row)
            elif v is not None:
                app_settings.set_value(s, k, v)
        s.commit()


@pytest.fixture
def cfg(env, tmp_path, monkeypatch):  # noqa: F811
    d = tmp_path / "config"
    d.mkdir()
    monkeypatch.setenv("CAPTURE_CONFIG_DIR", str(d))
    return d


def _done(w, domain, age, with_file=True, env=None):  # noqa: F811
    """A done row finished `age` minutes ago holding an image (file written under env['images'])."""
    c = _candidate(w, value=domain)
    obs = w.db.query(Observer).filter(Observer.name == "page_capture").one()
    t = datetime.now(timezone.utc) - timedelta(minutes=age)
    row = PageCapture(
        candidate_id=c.id, domain=domain, observer_id=obs.id, requested_url=f"https://{domain}/",
        status="done", finished_at=t, user_agent_mode="stock", image_max_bytes=2097152,
    )
    w.db.add(row)
    w.db.flush()
    row.image_path = f"{row.id}.webp"
    row.image_bytes = len(WEBP)
    row.image_sha256 = "0" * 64
    row.image_quality = 80
    w.db.commit()
    if with_file:
        (env["images"] / f"{row.id}.webp").write_bytes(WEBP)
    return row


def _get(w, row):
    w.db.expire_all()
    return w.db.get(PageCapture, row.id)


def _set(key, value):
    with SessionLocal() as s:
        app_settings.set_value(s, key, str(value))
        s.commit()


def _world(w, env, n_a=5, n_b=4):  # noqa: F811
    da, db_ = f"a-{os.urandom(4).hex()}.fabrikam.com", f"b-{os.urandom(4).hex()}.fabrikam.com"
    a = [_done(w, da, age, env=env) for age in range(n_a)]  # a[0] newest
    b = [_done(w, db_, age, env=env) for age in range(n_b)]
    return a, b


# ── pruning ──────────────────────────────────────────────────────────────────


def test_prune_keeps_latest_n_per_domain_and_never_deletes_rows(w, env, settings_restore):
    a, b = _world(w, env)
    _set(pc.IMAGE_KEEP_COUNT_KEY, 3)
    total = w.db.query(PageCapture).filter(PageCapture.candidate_id.in_(w.cap_candidates)).count()
    now = datetime.now(timezone.utc)
    assert pc.prune_images(w.db, now=now) == 3  # 2 from a, 1 from b
    w.db.commit()
    for r in a[:3] + b[:3]:
        assert _get(w, r).image_path is not None and (env["images"] / f"{r.id}.webp").exists()
        assert _get(w, r).image_pruned_at is None
    for r in a[3:] + b[3:]:
        got = _get(w, r)
        assert got.image_path is None and got.image_pruned_at == now
        assert got.image_bytes == len(WEBP) and got.image_sha256 == "0" * 64 and got.image_quality == 80
        assert not (env["images"] / f"{r.id}.webp").exists()
    assert w.db.query(PageCapture).filter(PageCapture.candidate_id.in_(w.cap_candidates)).count() == total
    assert pc.prune_images(w.db) == 0  # idempotent


def test_prune_keep_one_and_keep_above_row_count(w, env, settings_restore):
    a, b = _world(w, env)
    _set(pc.IMAGE_KEEP_COUNT_KEY, 50)
    assert pc.prune_images(w.db) == 0
    assert all((env["images"] / f"{r.id}.webp").exists() for r in a + b)
    _set(pc.IMAGE_KEEP_COUNT_KEY, 1)
    assert pc.prune_images(w.db) == (len(a) - 1) + (len(b) - 1)
    assert (env["images"] / f"{a[0].id}.webp").exists() and (env["images"] / f"{b[0].id}.webp").exists()
    assert not (env["images"] / f"{a[1].id}.webp").exists()


def test_prune_default_keep_count_is_three(w, env, settings_restore):
    a, _ = _world(w, env, n_a=4, n_b=1)
    with SessionLocal() as s:
        row = s.get(AppSetting, pc.IMAGE_KEEP_COUNT_KEY)
        if row is not None:
            s.delete(row)
            s.commit()
    assert pc.prune_images(w.db) == 1
    assert _get(w, a[3]).image_pruned_at is not None


def test_prune_missing_file_is_still_recorded(w, env, settings_restore):
    a, _ = _world(w, env, n_a=3, n_b=1)
    _set(pc.IMAGE_KEEP_COUNT_KEY, 1)
    (env["images"] / f"{a[2].id}.webp").unlink()
    assert pc.prune_images(w.db) == 2
    assert _get(w, a[2]).image_path is None and _get(w, a[2]).image_pruned_at is not None


def test_prune_name_mismatch_nulls_without_unlinking(w, env, settings_restore):
    a, _ = _world(w, env, n_a=2, n_b=1)
    _set(pc.IMAGE_KEEP_COUNT_KEY, 1)
    planted = env["images"] / "planted.webp"
    planted.write_bytes(WEBP)
    own = env["images"] / f"{a[1].id}.webp"
    a[1].image_path = "planted.webp"
    w.db.commit()
    assert pc.prune_images(w.db) == 1
    assert planted.exists() and own.exists()  # neither file touched
    got = _get(w, a[1])
    assert got.image_path is None and got.image_pruned_at is not None


def test_prune_symlink_is_removed_and_its_target_survives(w, env, settings_restore, tmp_path):
    a, _ = _world(w, env, n_a=2, n_b=1)
    _set(pc.IMAGE_KEEP_COUNT_KEY, 1)
    outside = tmp_path / "outside.webp"
    outside.write_bytes(WEBP)
    link = env["images"] / f"{a[1].id}.webp"
    link.unlink()
    link.symlink_to(outside)
    assert pc.prune_images(w.db) == 1
    assert not os.path.lexists(link) and outside.read_bytes() == WEBP
    assert _get(w, a[1]).image_pruned_at is not None


def test_prune_refuses_a_symlinked_images_dir(w, env, settings_restore, tmp_path, monkeypatch):
    a, _ = _world(w, env, n_a=3, n_b=1)
    _set(pc.IMAGE_KEEP_COUNT_KEY, 1)
    link = tmp_path / "imglink"
    link.symlink_to(env["images"])
    monkeypatch.setenv("CAPTURE_IMAGES_DIR", str(link))
    assert pc.prune_images(w.db) == 0
    assert all((env["images"] / f"{r.id}.webp").exists() for r in a)
    assert all(_get(w, r).image_path is not None for r in a)


def test_prune_other_oserror_leaves_the_row_for_retry(w, env, settings_restore):
    a, _ = _world(w, env, n_a=3, n_b=1)
    _set(pc.IMAGE_KEEP_COUNT_KEY, 1)
    victim = env["images"] / f"{a[1].id}.webp"
    victim.unlink()
    victim.mkdir()  # unlink of a directory is an OSError that is not ENOENT
    assert pc.prune_images(w.db) == 1  # only a[2]
    assert _get(w, a[1]).image_path == f"{a[1].id}.webp" and _get(w, a[1]).image_pruned_at is None
    assert _get(w, a[2]).image_pruned_at is not None
    victim.rmdir()
    assert pc.prune_images(w.db) == 1  # retried and recorded
    assert _get(w, a[1]).image_pruned_at is not None


def test_prune_batch_is_honoured(w, env, settings_restore, monkeypatch):
    a, b = _world(w, env)
    _set(pc.IMAGE_KEEP_COUNT_KEY, 1)
    monkeypatch.setattr(pc, "PRUNE_BATCH", 2)
    assert pc.prune_images(w.db) == 2
    assert pc.prune_images(w.db) == 2
    assert (len(a) - 1) + (len(b) - 1) == 7
    assert pc.prune_images(w.db) == 2
    assert pc.prune_images(w.db) == 1
    assert pc.prune_images(w.db) == 0


def test_prune_does_not_commit(w, env, settings_restore):
    a, _ = _world(w, env, n_a=2, n_b=1)
    _set(pc.IMAGE_KEEP_COUNT_KEY, 1)
    assert pc.prune_images(w.db) == 1
    w.db.rollback()
    assert _get(w, a[1]).image_path is not None  # the row change rolled back (the file is gone: self-heals)
    assert pc.prune_images(w.db) == 1  # FileNotFoundError path records it


def test_check_constraint_rejects_pruned_at_with_an_image_path(w, env):
    a = _done(w, f"c-{os.urandom(4).hex()}.fabrikam.com", 0, env=env)
    a.image_pruned_at = datetime.now(timezone.utc)
    with pytest.raises(IntegrityError):
        w.db.commit()
    w.db.rollback()
    a = _get(w, a)
    a.image_path = None
    a.image_pruned_at = datetime.now(timezone.utc)
    w.db.commit()  # the legal shape is accepted
    a.image_omitted_reason = "too_large"
    with pytest.raises(IntegrityError):
        w.db.commit()
    w.db.rollback()


# ── limits file ──────────────────────────────────────────────────────────────

CANON = b'{"connect_timeout_s":10,"idle_timeout_s":30,"max_connections":256,"version":1}\n'


def test_write_limits_on_a_missing_file(w, cfg, settings_restore):
    for k in _KEYS:
        with SessionLocal() as s:
            row = s.get(AppSetting, k)
            if row is not None:
                s.delete(row)
                s.commit()
    assert pc.write_proxy_limits(w.db) is True
    assert (cfg / "proxy_limits.json").read_bytes() == CANON
    assert not (cfg / ".proxy_limits.json.tmp").exists()


def test_write_limits_is_a_noop_when_equal(w, cfg, settings_restore):
    assert pc.write_proxy_limits(w.db) is True  # a write did happen
    st = os.stat(cfg / "proxy_limits.json")
    assert pc.write_proxy_limits(w.db) is False
    st2 = os.stat(cfg / "proxy_limits.json")
    assert (st.st_ino, st.st_mtime_ns) == (st2.st_ino, st2.st_mtime_ns)


def test_write_limits_rewrites_after_a_setting_change(w, cfg, settings_restore):
    pc.write_proxy_limits(w.db)
    _set(pc.PROXY_IDLE_TIMEOUT_KEY, 99)
    assert pc.write_proxy_limits(w.db) is True
    assert json.loads((cfg / "proxy_limits.json").read_bytes())["idle_timeout_s"] == 99
    (cfg / "proxy_limits.json").write_bytes(b"garbage")  # drift heals too
    assert pc.write_proxy_limits(w.db) is True
    assert json.loads((cfg / "proxy_limits.json").read_bytes())["idle_timeout_s"] == 99


def test_write_limits_replaces_a_symlink_without_touching_its_target(w, cfg, settings_restore, tmp_path):
    victim = tmp_path / "victim.txt"
    victim.write_bytes(b"precious")
    (cfg / "proxy_limits.json").symlink_to(victim)
    assert pc.write_proxy_limits(w.db) is True
    assert not (cfg / "proxy_limits.json").is_symlink()
    assert (cfg / "proxy_limits.json").read_bytes().endswith(b"\n")
    assert victim.read_bytes() == b"precious"


def test_write_limits_does_not_follow_a_planted_tmp_symlink(w, cfg, settings_restore, tmp_path):
    victim = tmp_path / "victim.txt"
    victim.write_bytes(b"precious")
    (cfg / ".proxy_limits.json.tmp").symlink_to(victim)
    assert not (cfg / "proxy_limits.json").exists()  # precondition: a write is due
    with pytest.raises(OSError):
        pc.write_proxy_limits(w.db)
    assert victim.read_bytes() == b"precious"
    assert not (cfg / "proxy_limits.json").exists()


def test_write_limits_refuses_a_symlinked_config_dir(w, cfg, settings_restore, tmp_path, monkeypatch):
    link = tmp_path / "cfglink"
    link.symlink_to(cfg)
    monkeypatch.setenv("CAPTURE_CONFIG_DIR", str(link))
    assert pc.write_proxy_limits(w.db) is False
    assert list(cfg.iterdir()) == []


def test_write_limits_missing_dir_returns_false(w, cfg, settings_restore, monkeypatch):
    monkeypatch.setenv("CAPTURE_CONFIG_DIR", str(cfg / "nope"))
    assert pc.write_proxy_limits(w.db) is False


def test_out_of_range_stored_settings_fall_back_to_defaults(w, cfg, settings_restore):
    _set(pc.PROXY_CONNECT_TIMEOUT_KEY, 0)
    _set(pc.PROXY_IDLE_TIMEOUT_KEY, 601)
    _set(pc.PROXY_MAX_CONNECTIONS_KEY, 5000)
    _set(pc.IMAGE_KEEP_COUNT_KEY, 51)
    assert pc.proxy_limits_bytes(w.db) == CANON
    assert pc.image_keep_count(w.db) == pc.DEFAULT_IMAGE_KEEP_COUNT


def test_tick_writes_limits_even_when_the_spool_dirs_are_missing(w, cfg, settings_restore, tmp_path, monkeypatch):
    monkeypatch.setenv("CAPTURE_SPOOL_DIR", str(tmp_path / "no-spool"))
    assert not (cfg / "proxy_limits.json").exists()
    pc.tick()
    assert (cfg / "proxy_limits.json").read_bytes().endswith(b"\n")
    assert json.loads((cfg / "proxy_limits.json").read_bytes())["version"] == 1


def test_tick_prunes_after_the_sweep(w, cfg, env, settings_restore):
    a, _ = _world(w, env, n_a=4, n_b=1)
    _set(pc.IMAGE_KEEP_COUNT_KEY, 2)
    pc.tick()
    assert _get(w, a[2]).image_pruned_at is not None and _get(w, a[1]).image_pruned_at is None
    assert not (env["images"] / f"{a[3].id}.webp").exists()


def test_tick_survives_a_prune_failure_and_still_sweeps(w, cfg, env, settings_restore, monkeypatch):
    calls = []

    def boom(db, now=None):
        calls.append(1)
        raise RuntimeError("x")

    monkeypatch.setattr(pc, "prune_images", boom)
    pc.tick()
    assert calls == [1]


# ── drift against the proxy ──────────────────────────────────────────────────


def _proxy_constants() -> dict:
    root = Path(__file__).resolve().parents[3]
    tree = ast.parse((root / "capture-proxy" / "proxy.py").read_text())
    out = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            try:
                out[node.targets[0].id] = ast.literal_eval(node.value)
            except ValueError:
                pass
    return out


def test_proxy_constants_match_the_backend():
    proxy = _proxy_constants()
    expected = {
        "CONNECT_TIMEOUT_S": pc.PROXY_CONNECT_TIMEOUT_DEFAULT,
        "IDLE_TIMEOUT_S": pc.PROXY_IDLE_TIMEOUT_DEFAULT,
        "MAX_CONNECTIONS": pc.PROXY_MAX_CONNECTIONS_DEFAULT,
        "CONNECT_TIMEOUT_BOUNDS": (pc.PROXY_CONNECT_TIMEOUT_MIN, pc.PROXY_CONNECT_TIMEOUT_MAX),
        "IDLE_TIMEOUT_BOUNDS": (pc.PROXY_IDLE_TIMEOUT_MIN, pc.PROXY_IDLE_TIMEOUT_MAX),
        "MAX_CONNECTIONS_BOUNDS": (pc.PROXY_MAX_CONNECTIONS_MIN, pc.PROXY_MAX_CONNECTIONS_MAX),
        "LIMITS_FILE_VERSION": pc.PROXY_LIMITS_VERSION,
        "LIMITS_FILE_MAX_BYTES": pc.PROXY_LIMITS_MAX_BYTES,
        "LIMITS_FILE_NAME": pc.PROXY_LIMITS_FILE,
    }
    missing = [k for k in expected if k not in proxy]
    assert not missing, f"capture-proxy/proxy.py does not define {missing}"
    assert {k: proxy[k] for k in expected} == expected


# ── drift: job contract v3 literals across proxy, browser and backend ───────


def _literal_constants(path: Path) -> dict:
    """Module-level NAME = <literal> or NAME = frozenset(<literal>) (ast only)."""
    out = {}
    for node in ast.parse(path.read_text()).body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            value = node.value
            wrap = None
            if (
                isinstance(value, ast.Call)
                and isinstance(value.func, ast.Name)
                and value.func.id == "frozenset"
                and len(value.args) == 1
                and not value.keywords
            ):
                wrap, value = frozenset, value.args[0]
            try:
                lit = ast.literal_eval(value)
            except ValueError:
                continue
            out[node.targets[0].id] = wrap(lit) if wrap else lit
    return out


def test_archive_hosts_and_modes_match_across_proxy_browser_and_backend():
    root = Path(__file__).resolve().parents[3]
    proxy = _literal_constants(root / "capture-proxy" / "proxy.py")
    spool = _literal_constants(root / "capture-browser" / "capture" / "spool.py")
    for name, src in (("proxy", proxy), ("browser spool", spool)):
        missing = [k for k in ("ARCHIVE_HOSTS", "MODES") if k not in src]
        assert not missing, f"{name} does not define {missing} as ast-readable literals"
    assert spool["ARCHIVE_HOSTS"] == proxy["ARCHIVE_HOSTS"] == frozenset({"web.archive.org"})
    assert tuple(spool["MODES"]) == tuple(proxy["MODES"]) == pc.CAPTURE_MODES == ("live", "archive")


def test_wayback_host_and_snapshot_url_satisfy_the_browser_and_proxy_rules():
    from datetime import datetime, timezone
    from urllib.parse import urlsplit

    from app.services import wayback

    root = Path(__file__).resolve().parents[3]
    proxy = _literal_constants(root / "capture-proxy" / "proxy.py")
    spool = _literal_constants(root / "capture-browser" / "capture" / "spool.py")
    assert wayback.ARCHIVE_HOST in proxy["ARCHIVE_HOSTS"]
    assert wayback.ARCHIVE_HOST in spool["ARCHIVE_HOSTS"]
    # The browser's `archive_request_allowed` cannot be imported by the backend venv, so its
    # rule is restated as data. Its path pattern is `_ARCHIVE_PATH_RE = re.compile(...)`, a
    # call that `_literal_constants` does not read, so the pattern is hard-coded here: keep it
    # equal to capture-browser/capture/spool.py (checked below by source text).
    path_re = r"/web/[0-9]+"
    assert f're.compile(r"{path_re}")' in (root / "capture-browser" / "capture" / "spool.py").read_text()
    snap = wayback.Snapshot("20261020123456", datetime(2026, 10, 20, 12, 34, 56, tzinfo=timezone.utc))
    parts = urlsplit(wayback.snapshot_url(snap, "fabrikam.com"))
    assert parts.scheme == "https"
    assert parts.hostname in spool["ARCHIVE_HOSTS"]
    assert parts.port is None
    assert re.match(path_re, parts.path)
    assert "@" not in parts.netloc


def test_job_version_matches_the_browser_spool():
    root = Path(__file__).resolve().parents[3]
    spool = _literal_constants(root / "capture-browser" / "capture" / "spool.py")
    assert spool["JOB_VERSION"] == pc.JOB_VERSION == 3


def test_proxy_credential_ttl_matches_the_backend():
    root = Path(__file__).resolve().parents[3]
    proxy = _literal_constants(root / "capture-proxy" / "proxy.py")
    assert proxy["MAX_CREDENTIAL_TTL_S"] == pc.QUEUE_TIMEOUT_MAX + pc.CREDENTIAL_RUN_MARGIN_S


# ── limits sink selection (planning#324 slice 2) ─────────────────────────────


def test_configmap_sink_delegates_and_writes_no_file(w, cfg, settings_restore, monkeypatch):
    monkeypatch.setenv("CAPTURE_LIMITS_SINK", "configmap")
    calls = []
    monkeypatch.setattr(pc.capture_limits_configmap, "write_configmap_limits", lambda want: calls.append(want) or True)
    assert pc.write_proxy_limits(w.db) is True
    assert calls == [pc.proxy_limits_bytes(w.db)]
    assert list(cfg.iterdir()) == []


def test_unknown_sink_writes_nothing_and_logs(w, cfg, settings_restore, monkeypatch, caplog):
    monkeypatch.setenv("CAPTURE_LIMITS_SINK", "bogus")
    calls = []
    monkeypatch.setattr(pc.capture_limits_configmap, "write_configmap_limits", lambda want: calls.append(want) or True)
    assert pc.write_proxy_limits(w.db) is False
    assert list(cfg.iterdir()) == [] and calls == []
    assert "not a known sink" in caplog.text


def test_unset_sink_writes_the_file(w, cfg, settings_restore, monkeypatch):
    monkeypatch.delenv("CAPTURE_LIMITS_SINK", raising=False)
    assert pc.write_proxy_limits(w.db) is True
    assert (cfg / "proxy_limits.json").read_bytes() == CANON


def test_file_sink_writes_the_file(w, cfg, settings_restore, monkeypatch):
    monkeypatch.setenv("CAPTURE_LIMITS_SINK", "file")
    assert pc.write_proxy_limits(w.db) is True
    assert (cfg / "proxy_limits.json").read_bytes() == CANON


def test_tick_survives_a_configmap_sink_failure_and_continues(w, cfg, settings_restore, tmp_path, monkeypatch, caplog):
    from app.services.capture_limits_configmap import ConfigMapSinkError

    monkeypatch.setenv("CAPTURE_SPOOL_DIR", str(tmp_path / "no-spool"))
    monkeypatch.setenv("CAPTURE_LIMITS_SINK", "configmap")

    def boom(want):
        raise ConfigMapSinkError("x")

    monkeypatch.setattr(pc.capture_limits_configmap, "write_configmap_limits", boom)
    swept = []
    monkeypatch.setattr(pc, "sweep_timeouts", lambda db, now=None: swept.append(1) or 0)
    pc.tick()
    assert "writing the proxy limits failed" in caplog.text
    assert swept == [1]
