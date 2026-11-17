"""planning#360 part A: CVE-level dates in `cve_records`, the VulnCheck fetchers
that capture them, the fetch/mirror split, and the first-confirmed stamp on
findings. Wire shapes follow live VulnCheck / NVD2 responses. No network (the
HTTP seam `connector_get` is replaced) and no network addresses at all.
Synthetic CVE ids (CVE-2099-*) and hosts only.

Run with:  backend/scripts/test.sh app/tests/test_cve_records.py
"""

import uuid
from datetime import date, datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from sqlalchemy.exc import IntegrityError

from app.core.database import SessionLocal
from app.models.asset_canonical import AssetCanonical
from app.models.cve_record import CVE_PUBLISHED_SOURCES, CveRecord
from app.models.finding_canonical import FindingCanonical
from app.services import cve_enrichment, cve_records
from app.services import shared_infra_verifier as siv
from app.services import vulncheck_enrichment as vc

T0 = datetime(2030, 1, 1, 12, 0, tzinfo=timezone.utc)
T1 = T0 + timedelta(days=1)
CVE_A = "CVE-2099-0001"
CVE_B = "CVE-2099-0002"
CVE_C = "CVE-2099-0003"
ALL_CVES = [CVE_A, CVE_B, CVE_C, "CVE-2099-0004"]
HOST = "cve-records.fabrikam.com"


class _Resp:
    def __init__(self, payload, status=200):
        self._p, self.status_code = payload, status

    def json(self):
        return self._p


@pytest.fixture
def db():
    s = SessionLocal()
    _purge(s)
    vc._cache.clear()
    yield s
    s.rollback()
    _purge(s)
    vc._cache.clear()
    s.close()


def _purge(s):
    s.rollback()
    s.query(CveRecord).filter(CveRecord.cve_id.in_(ALL_CVES)).delete(synchronize_session=False)
    asset_ids = [r[0] for r in s.query(AssetCanonical.id).filter(AssetCanonical.value == HOST)]
    if asset_ids:
        s.query(FindingCanonical).filter(FindingCanonical.asset_canonical_id.in_(asset_ids)).delete(
            synchronize_session=False
        )
        s.query(AssetCanonical).filter(AssetCanonical.id.in_(asset_ids)).delete(synchronize_session=False)
    s.commit()


def _routes(monkeypatch, kev=None, nvd=None, cvelist=None):
    """Replace connector_get: one handler per VulnCheck index, keyed by CVE id.
    A value of an int means that HTTP status with an empty body; a missing CVE is
    `data: []`. Returns the call log."""
    calls: list[tuple[str, str]] = []
    tables = {vc._KEV_URL: kev or {}, vc._NVD2_URL: nvd or {}, vc._CVELIST_URL: cvelist or {}}

    def fake(url, headers=None, params=None, timeout=None, **kw):
        cve = params["cve"]
        calls.append((url, cve))
        entry = tables[url].get(cve)
        if isinstance(entry, int):
            return _Resp({}, status=entry)
        return _Resp({"data": [entry] if entry else []})

    monkeypatch.setattr(vc, "connector_get", fake)
    return calls


def _nvd_rec(published="2021-12-10T10:15:09.143"):
    rec = {
        "id": CVE_A,
        "descriptions": [{"lang": "en", "value": "A flaw in the widget. More text follows."}],
        "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "vectorString": "CVSS:3.1/AV:N", "version": "3.1"}}]},
        "weaknesses": [{"description": [{"lang": "en", "value": "CWE-20"}]}],
        "references": [{"url": "https://example.test/advisory", "tags": ["Vendor Advisory"]}],
    }
    if published is not None:
        rec["published"] = published
    return rec


def _kev_rec(date_added="2021-12-10T00:00:00Z"):
    rec = {
        "cve": [CVE_A],
        "vulnerabilityName": "Fabrikam widget flaw",
        "shortDescription": "Widget flaw.",
        "required_action": "Apply updates.",
        "knownRansomwareCampaignUse": "Known",
        "reported_exploited_by_vulncheck_canaries": False,
        "vulncheck_xdb": [{"xdb_url": "https://example.test/xdb/1", "exploit_type": "initial-access", "date_added": "2022-01-01T00:00:00Z"}],
        "vulncheck_reported_exploitation": [],
    }
    if date_added is not None:
        rec["date_added"] = date_added
    return rec


H = {"Accept": "application/json"}


# ── fetchers ───────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("published", ["2021-12-10T10:15:09.143", "2021-12-10T10:15:09.143Z", "2021-12-10T12:15:09.143+02:00"])
def test_nvd2_published_is_aware_utc(monkeypatch, published):
    calls = _routes(monkeypatch, nvd={CVE_A: _nvd_rec(published)})
    out = vc._fetch_nvd2(CVE_A, H)
    assert calls, "the NVD2 fetcher was reached"
    assert out["published_at"] == datetime(2021, 12, 10, 10, 15, 9, 143000, tzinfo=timezone.utc)
    assert out["published_at"].utcoffset() == timedelta(0)
    assert out["cvss_score"] == 9.8  # the existing fields are unchanged


@pytest.mark.parametrize("published", [None, "", "not a date", 20211210, "0001-01-01T00:00:00Z"])
def test_nvd2_published_missing_or_garbage_is_none(monkeypatch, published):
    rec = _nvd_rec(None)
    if published is not None:
        rec["published"] = published
    calls = _routes(monkeypatch, nvd={CVE_A: rec})
    out = vc._fetch_nvd2(CVE_A, H)
    assert calls, "the NVD2 fetcher was reached"
    assert out is not None and out["published_at"] is None
    assert out["cvss_score"] == 9.8


def test_kev_date_added_is_a_date(monkeypatch):
    calls = _routes(monkeypatch, kev={CVE_A: _kev_rec()})
    out = vc._fetch_kev_signals(CVE_A, H)
    assert calls
    assert out["vulncheck_kev"] is True
    assert out["vulncheck_kev_date_added"] == date(2021, 12, 10)
    assert out["exploit_count"] == 1


@pytest.mark.parametrize("raw", ["0001-01-01T00:00:00Z", None, "garbage", 5])
def test_kev_date_added_zero_missing_or_garbage_is_none(monkeypatch, raw):
    rec = _kev_rec(None)
    if raw is not None:
        rec["date_added"] = raw
    calls = _routes(monkeypatch, kev={CVE_A: rec})
    out = vc._fetch_kev_signals(CVE_A, H)
    assert calls and out["vulncheck_kev"] is True, "the record branch was reached"
    assert out["vulncheck_kev_date_added"] is None


def test_kev_absent_from_index_has_no_date(monkeypatch):
    calls = _routes(monkeypatch, kev={})
    out = vc._fetch_kev_signals(CVE_A, H)
    assert calls
    assert out["vulncheck_kev"] is False
    assert out["vulncheck_kev_date_added"] is None


def test_lookup_merges_published_at_into_the_signal(monkeypatch):
    _routes(monkeypatch, kev={CVE_A: _kev_rec()}, nvd={CVE_A: _nvd_rec()})
    sig = vc._lookup_cve(CVE_A, H)
    assert sig["published_at"] == datetime(2021, 12, 10, 10, 15, 9, 143000, tzinfo=timezone.utc)
    assert sig["vulncheck_kev_date_added"] == date(2021, 12, 10)
    assert "intel" in sig and "published_at" not in sig["intel"]


def test_lookup_fresh_bypasses_cache_default_uses_it(monkeypatch):
    calls = _routes(monkeypatch, kev={CVE_A: _kev_rec()}, nvd={CVE_A: _nvd_rec()})
    vc._cache.clear()
    vc._lookup_cve(CVE_A, H)
    n_first = len(calls)
    assert n_first == 3  # kev + nvd2 + cvelist: the populate call really fetched

    vc._lookup_cve(CVE_A, H)
    assert len(calls) == n_first, "default call is served from the cache"

    vc._lookup_cve(CVE_A, H, fresh=True)
    assert len(calls) == 2 * n_first, "fresh=True fetches again despite a populated cache"

    vc._lookup_cve(CVE_A, H)
    assert len(calls) == 2 * n_first, "the fresh result was written back to the cache"


# ── cve_records writer ─────────────────────────────────────────────────────────

def _row(db, cve):
    db.expire_all()
    return db.get(CveRecord, cve)


def test_upsert_inserts_and_keeps_stored_dates_against_none(db):
    pub = datetime(2021, 12, 10, 10, 15, tzinfo=timezone.utc)
    cve_records.upsert_from_signals(
        db, {CVE_A.lower(): {"published_at": pub, "vulncheck_kev_date_added": date(2022, 1, 5)}}, T0
    )
    db.commit()
    row = _row(db, CVE_A)
    assert row is not None, "the row exists before the keep-assertions run"
    assert (row.published_at, row.published_source, row.vulncheck_kev_date_added) == (pub, "vulncheck_nvd2", date(2022, 1, 5))
    assert row.refreshed_at == T0 and row.refresh_failed is False

    cve_records.upsert_from_signals(db, {CVE_A: {"published_at": None, "vulncheck_kev_date_added": None}}, T1)
    db.commit()
    row = _row(db, CVE_A)
    assert row.published_at == pub and row.published_source == "vulncheck_nvd2"
    assert row.vulncheck_kev_date_added == date(2022, 1, 5)
    assert row.refreshed_at == T1, "the attempt time still moves"

    newer = datetime(2021, 12, 11, tzinfo=timezone.utc)
    cve_records.upsert_from_signals(db, {CVE_A: {"published_at": newer, "vulncheck_kev_date_added": date(2022, 2, 1)}}, T1)
    db.commit()
    row = _row(db, CVE_A)
    assert row.published_at == newer and row.vulncheck_kev_date_added == date(2022, 2, 1)


def test_mark_failed_then_success_clears_the_flag(db):
    pub = datetime(2021, 12, 10, tzinfo=timezone.utc)
    cve_records.mark_failed(db, [CVE_B.lower()], T0)  # a CVE with no row yet
    db.commit()
    row = _row(db, CVE_B)
    assert row is not None and row.refresh_failed is True and row.published_at is None

    cve_records.upsert_from_signals(db, {CVE_B: {"published_at": pub}}, T0)
    db.commit()
    assert _row(db, CVE_B).refresh_failed is False

    cve_records.mark_failed(db, [CVE_B], T1)
    db.commit()
    row = _row(db, CVE_B)
    assert row.refresh_failed is True and row.refreshed_at == T1
    assert row.published_at == pub and row.published_source == "vulncheck_nvd2", "dates untouched by a failure"

    cve_records.upsert_from_signals(db, {CVE_B: {"published_at": None}}, T1)
    db.commit()
    assert _row(db, CVE_B).refresh_failed is False


# ── migration CHECKs ───────────────────────────────────────────────────────────

def _raw_insert(db, **cols):
    db.execute(CveRecord.__table__.insert().values(**cols))
    db.flush()


def test_check_sources_vocabulary_matches_model():
    assert CVE_PUBLISHED_SOURCES == ("vulncheck_nvd2",)


def test_check_accepts_a_valid_row(db):
    _raw_insert(db, cve_id=CVE_C, published_at=T0, published_source="vulncheck_nvd2")
    db.rollback()


@pytest.mark.parametrize(
    "cols",
    [
        {"cve_id": "cve-2099-0003"},
        {"cve_id": CVE_C, "published_at": T0},
        {"cve_id": CVE_C, "published_source": "vulncheck_nvd2"},
        {"cve_id": CVE_C, "published_at": T0, "published_source": "somewhere_else"},
    ],
)
def test_checks_reject_bad_rows(db, cols):
    with pytest.raises(IntegrityError):
        _raw_insert(db, **cols)
    db.rollback()
    assert db.query(CveRecord).filter(CveRecord.cve_id.in_([CVE_C, "cve-2099-0003"])).count() == 0


# ── VulnCheck enrich_scan_findings end to end ──────────────────────────────────

def _make_findings(db, cves):
    now = datetime.now(timezone.utc)
    asset = AssetCanonical(
        id=uuid.uuid4(), asset_type="domain", value=HOST, first_seen_at=now, last_seen_at=now, ignored=False, tags=[]
    )
    db.add(asset)
    db.flush()
    ids = {}
    for cve in cves:
        f = FindingCanonical(
            id=uuid.uuid4(), asset_canonical_id=asset.id, finding_type="cve", source="test", fingerprint=f"fp-{cve}",
            severity="high", title=f"{cve} exposed (via Shodan)", state="open", category="vulnerability",
            cve_id=cve, first_seen_at=now, last_seen_at=now, detail={}, tags=[],
        )
        db.add(f)
        ids[cve] = f.id
    db.commit()
    return ids


def test_vulncheck_enrich_writes_records_and_still_mirrors(db, monkeypatch):
    ids = _make_findings(db, [CVE_A, CVE_B])
    monkeypatch.setattr(vc.connector_instances, "enabled_config", lambda d, t: {"api_key": "k"})
    # CVE_A is fully known; CVE_B's KEV lookup fails with a 503 (transient).
    calls = _routes(monkeypatch, kev={CVE_A: _kev_rec(), CVE_B: 503}, nvd={CVE_A: _nvd_rec()})

    mirrored = vc.enrich_scan_findings(db, uuid.uuid4(), set(ids.values()))
    assert calls, "the fetchers were reached"
    assert mirrored == {ids[CVE_A]}

    db.expire_all()
    a = db.get(FindingCanonical, ids[CVE_A])
    assert a.vulncheck_kev is True and a.exploit_count == 1 and a.ransomware_use is True
    assert a.title == "A flaw in the widget."
    assert a.cvss_score == 9.8
    b = db.get(FindingCanonical, ids[CVE_B])
    assert b.vulncheck_kev is None or b.vulncheck_kev is False
    assert b.title.endswith("(via Shodan)"), "the failed CVE's finding is untouched"

    rec_a = db.get(CveRecord, CVE_A)
    assert rec_a.published_at == datetime(2021, 12, 10, 10, 15, 9, 143000, tzinfo=timezone.utc)
    assert rec_a.published_source == "vulncheck_nvd2"
    assert rec_a.vulncheck_kev_date_added == date(2021, 12, 10)
    assert rec_a.refresh_failed is False and rec_a.refreshed_at is not None
    rec_b = db.get(CveRecord, CVE_B)
    assert rec_b.refresh_failed is True and rec_b.published_at is None and rec_b.refreshed_at is not None


def test_vulncheck_enrich_all_failed_still_records_the_failure(db, monkeypatch):
    ids = _make_findings(db, [CVE_A])
    monkeypatch.setattr(vc.connector_instances, "enabled_config", lambda d, t: {"api_key": "k"})
    calls = _routes(monkeypatch, kev={CVE_A: 500})
    assert vc.enrich_scan_findings(db, uuid.uuid4(), set(ids.values())) == set()
    assert calls
    db.expire_all()
    assert db.get(CveRecord, CVE_A).refresh_failed is True


# ── mirror_signals / CISA KEV ──────────────────────────────────────────────────

def test_mirror_signals_flushes_without_committing(db):
    ids = _make_findings(db, [CVE_A])
    sig = {
        "vulncheck_kev": True, "has_exploit": True, "exploit_count": 2, "exploit_types": ["infoleak"],
        "ransomware_use": False, "canary_detected": False, "intel": {"description": "Widget flaw. Details."},
    }
    out = vc.mirror_signals(db, {CVE_A: sig})
    assert out == {ids[CVE_A]}
    assert db.get(FindingCanonical, ids[CVE_A]).exploit_count == 2
    db.rollback()  # not committed: the change must vanish
    db.expire_all()
    assert db.get(FindingCanonical, ids[CVE_A]).exploit_count in (None, 0)


def test_mirror_cisa_kev_sets_kev_and_date_and_returns_ids(db):
    ids = _make_findings(db, [CVE_A, CVE_B])
    out = cve_enrichment.mirror_cisa_kev(db, [CVE_A, CVE_B], {CVE_A: "2021-12-10", "CVE-2099-9999": "2020-01-01"})
    assert out == {ids[CVE_A]}
    db.commit()
    db.expire_all()
    a = db.get(FindingCanonical, ids[CVE_A])
    assert a.kev is True and a.kev_date_added == date(2021, 12, 10)
    assert not db.get(FindingCanonical, ids[CVE_B]).kev


def test_mirror_cisa_kev_bad_date_sets_kev_without_date(db):
    ids = _make_findings(db, [CVE_A])
    out = cve_enrichment.mirror_cisa_kev(db, [CVE_A], {CVE_A: "not-a-date"})
    assert out == {ids[CVE_A]}
    assert db.get(FindingCanonical, ids[CVE_A]).kev is True
    assert db.get(FindingCanonical, ids[CVE_A]).kev_date_added is None


def test_cisa_enrich_scan_findings_still_sets_kev(db, monkeypatch):
    from app.services import epss_history_service

    ids = _make_findings(db, [CVE_A, CVE_B])
    reached = {"kev": 0}

    def fake_kev():
        reached["kev"] += 1
        return {CVE_A: "2021-12-10"}

    monkeypatch.setattr(cve_enrichment, "_get_kev_dict", fake_kev)
    monkeypatch.setattr(cve_enrichment, "_fetch_epss_bulk", lambda cves: {})
    monkeypatch.setattr(epss_history_service, "cves_without_history", lambda d, c: [])
    monkeypatch.setattr(epss_history_service, "upsert_current", lambda d, c: None)
    monkeypatch.setattr(cve_enrichment.connector_instances, "enabled_config", lambda d, t: {"api_key": "k"})

    out = cve_enrichment.enrich_scan_findings(db, uuid.uuid4(), set(ids.values()))
    assert reached["kev"] == 1
    assert out == {ids[CVE_A]}
    db.expire_all()
    a = db.get(FindingCanonical, ids[CVE_A])
    assert a.kev is True and a.kev_date_added == date(2021, 12, 10)
    assert not db.get(FindingCanonical, ids[CVE_B]).kev


# ── ownership_confirmed_at ─────────────────────────────────────────────────────

def _finding_ns():
    return SimpleNamespace(
        id=uuid.uuid4(), verification=None, verification_evidence=None, verified_at=None, ownership_confirmed_at=None,
        cve_id=None, title="", description="", finding_type="cve",
    )


def test_first_confirmed_ours_stamps_and_later_applies_never_move_it():
    f = _finding_ns()
    siv._apply_verdict(f, "confirmed_ours", {}, {}, T0)
    assert f.verification == "confirmed_ours" and f.ownership_confirmed_at == T0

    siv._apply_verdict(f, "confirmed_ours", {}, {}, T1)  # forced re-verify
    assert f.verified_at == T1, "the re-verify really was applied"
    assert f.ownership_confirmed_at == T0

    siv._apply_verdict(f, "rejected_shared_infra", {}, {}, T1)
    assert f.verification == "rejected_shared_infra"
    assert f.ownership_confirmed_at == T0, "a later change of verdict does not clear it"

    siv._apply_verdict(f, "confirmed_ours", {}, {}, T1 + timedelta(days=1))
    assert f.ownership_confirmed_at == T0, "re-confirming after a reversal keeps the first date"


@pytest.mark.parametrize("verdict", ["unverified", "rejected_shared_infra", "ownership_unverifiable"])
def test_other_verdicts_never_stamp(verdict):
    f = _finding_ns()
    siv._apply_verdict(f, verdict, {}, {}, T0)
    assert f.verification == verdict and f.verified_at == T0, "the verdict was applied"
    assert f.ownership_confirmed_at is None


def test_stamp_findings_for_ip_stamps_via_the_real_path_and_force_keeps_it():
    f = _finding_ns()

    class _Q:
        def filter(self, *a, **k):
            return self

        def all(self):
            return [f]

    class _S:
        def query(self, *a, **k):
            return _Q()

    cls = {"verdict": "confirmed_ours", "evidence": {}, "matrices": {}}
    asset = SimpleNamespace(id=uuid.uuid4())
    assert siv.stamp_findings_for_ip(_S(), asset, cls) == {f.id}
    first = f.ownership_confirmed_at
    assert first is not None
    assert siv.stamp_findings_for_ip(_S(), asset, cls, force=True) == {f.id}
    assert f.ownership_confirmed_at == first
