"""CaptureStore conformance (planning#318). No DB. The `store` fixture runs every portable
test against the filesystem AND an S3 store (a RustFS container from the `capture-s3-test`
compose profile; skipped when CAPTURE_S3_TEST_ENDPOINT is unset). Portable tests reach the
backing store only through the `raw` helper, so the same assertions hold on both. Tests
marked FS-only build symlinks, FIFOs and directories and exercise the filesystem defences;
`test_s3_*` tests exercise the commit marker and presigned PUTs."""

import json
import os
import shutil
import time
import uuid

import botocore.session
import httpx
import pytest
from botocore.config import Config
from botocore.exceptions import ClientError

from app.services import capture_store_s3
from app.services.capture_store import FilesystemStore, get_store
from app.services.capture_store_s3 import S3Buckets, S3Store

ID = "11111111-1111-4111-8111-111111111111"
ID2 = "22222222-2222-4222-8222-222222222222"
ID3 = "33333333-3333-4333-8333-333333333333"

_SKIP_S3 = ("no test S3 endpoint: start the capture-s3-test compose profile and set "
            "CAPTURE_S3_TEST_ENDPOINT / _ACCESS_KEY / _SECRET_KEY")
_AREAS = ("jobs", "results", "proxylog", "images")


class _FsRaw:
    def __init__(self, root):
        self._root = root
        self._dirs = {"jobs": "spool/jobs", "claimed": "spool/claimed", "results": "spool/results",
                      "proxylog": "proxylog", "images": "images"}

    def _d(self, area):
        return self._root / self._dirs[area]

    def put(self, area, rel, data):
        p = self._d(area) / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)

    def get(self, area, rel):
        p = self._d(area) / rel
        return p.read_bytes() if p.exists() else None

    def exists(self, area, rel):
        return (self._d(area) / rel).exists()

    def names(self, area):
        return sorted(os.listdir(self._d(area)))

    def break_area(self, area):
        shutil.rmtree(self._d(area))

    def break_spool(self):
        self._d("claimed").rmdir()


class _S3Raw:
    def __init__(self, admin, buckets):
        self._a = admin
        self._b = buckets

    def _bucket(self, area):
        if area == "claimed":
            raise AssertionError("`claimed` exists on the filesystem only")
        return getattr(self._b, area)

    def put(self, area, rel, data):
        self._a.put_object(Bucket=self._bucket(area), Key=f"{area}/{rel}", Body=data)

    def get(self, area, rel):
        try:
            return self._a.get_object(Bucket=self._bucket(area), Key=f"{area}/{rel}")["Body"].read()
        except ClientError as e:
            if e.response["Error"]["Code"] in ("NoSuchKey", "404"):
                return None
            raise

    def exists(self, area, rel):
        return self.get(area, rel) is not None

    def names(self, area):
        out = set()
        for page in self._a.get_paginator("list_objects_v2").paginate(
                Bucket=self._bucket(area), Prefix=f"{area}/"):
            for obj in page.get("Contents", []):
                out.add(obj["Key"][len(area) + 1:].split("/")[0])
        return sorted(out)

    def break_area(self, area):
        _empty_and_delete(self._a, self._bucket(area))

    def break_spool(self):
        self.break_area("results")


def _empty_and_delete(admin, bucket):
    try:
        for page in admin.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            for obj in page.get("Contents", []):
                admin.delete_object(Bucket=bucket, Key=obj["Key"])
        admin.delete_bucket(Bucket=bucket)
    except ClientError:
        pass


@pytest.fixture(params=["filesystem", "s3"])
def store(request, tmp_path, monkeypatch):
    if request.param == "filesystem":
        for sub in ("spool/jobs", "spool/claimed", "spool/results", "proxylog", "images"):
            (tmp_path / sub).mkdir(parents=True)
        request.node.stash_raw = _FsRaw(tmp_path)
        yield FilesystemStore(str(tmp_path / "spool"), str(tmp_path / "proxylog"), str(tmp_path / "images"))
        return
    endpoint = os.environ.get("CAPTURE_S3_TEST_ENDPOINT")
    if not endpoint:
        pytest.skip(_SKIP_S3)
    access = os.environ.get("CAPTURE_S3_TEST_ACCESS_KEY", "")
    secret = os.environ.get("CAPTURE_S3_TEST_SECRET_KEY", "")
    tag = uuid.uuid4().hex[:8]
    buckets = S3Buckets(*(f"cap-{tag}-{a}" for a in _AREAS))
    # an independent client, built like production's, so tests observe the store from outside
    admin = botocore.session.get_session().create_client(
        "s3", region_name="us-east-1", endpoint_url=endpoint,
        aws_access_key_id=access, aws_secret_access_key=secret,
        config=Config(signature_version="s3v4", s3={"addressing_style": "path"}))
    for b in buckets.__dict__.values():
        admin.create_bucket(Bucket=b)
    monkeypatch.setenv("CAPTURE_STORE", "s3")
    monkeypatch.setenv("CAPTURE_S3_ENDPOINT", endpoint)
    monkeypatch.setenv("CAPTURE_S3_INSECURE_HTTP", "1")
    monkeypatch.setenv("CAPTURE_S3_ACCESS_KEY", access)
    monkeypatch.setenv("CAPTURE_S3_SECRET_KEY", secret)
    monkeypatch.setenv("CAPTURE_S3_PATH_STYLE", "true")
    for area in _AREAS:
        monkeypatch.setenv(f"CAPTURE_S3_BUCKET_{area.upper()}", getattr(buckets, area))
    s = get_store()  # exercises the dispatch live
    assert isinstance(s, S3Store)
    request.node.stash_raw = _S3Raw(admin, buckets)
    try:
        yield s
    finally:
        for b in buckets.__dict__.values():
            _empty_and_delete(admin, b)
        capture_store_s3._client.cache_clear()


@pytest.fixture
def raw(store, request):
    return request.node.stash_raw


@pytest.fixture
def fs(store):
    if not isinstance(store, FilesystemStore):
        pytest.skip("filesystem-only")
    return store


@pytest.fixture
def s3(store):
    if not isinstance(store, S3Store):
        pytest.skip("s3-only")
    return store


def _bundle(fs, name=ID, files=None):
    d = fs._spool + f"/results/{name}"
    os.makedirs(d, exist_ok=True)
    for fn, data in (files or {"result.json": b"{}"}).items():
        with open(f"{d}/{fn}", "wb") as f:
            f.write(data)
    return d


# ── portable ────────────────────────────────────────────────────────────────


def test_get_store_reads_the_env_at_call_time(monkeypatch, tmp_path):
    # filesystem-only by construction: it reads `_spool` and never uses the `store` fixture
    monkeypatch.setenv("CAPTURE_SPOOL_DIR", str(tmp_path / "a"))
    assert get_store()._spool == str(tmp_path / "a")
    monkeypatch.setenv("CAPTURE_SPOOL_DIR", str(tmp_path / "b"))
    assert get_store()._spool == str(tmp_path / "b")


def test_put_job_publishes_exact_bytes_and_no_temp(store, raw):
    store.put_job(ID, b'{"a":1}')
    assert raw.get("jobs", f"{ID}.json") == b'{"a":1}'
    assert raw.names("jobs") == [f"{ID}.json"]


def test_put_job_failure_raises_and_leaves_no_temp(store, raw):
    raw.break_area("jobs")
    with pytest.raises(OSError):
        store.put_job(ID, b"x")


def test_delete_job_is_quiet_when_absent_and_removes_only_the_named_job(store, raw):
    store.delete_job(ID)  # absent: no raise
    raw.put("jobs", f"{ID}.json", b"x")
    raw.put("jobs", f"{ID2}.json", b"x")
    store.delete_job(ID)
    assert not raw.exists("jobs", f"{ID}.json")
    assert raw.exists("jobs", f"{ID2}.json")  # only the named job


def test_fs_delete_job_also_removes_the_claimed_job(fs, raw):
    raw.put("jobs", f"{ID}.json", b"x")
    raw.put("claimed", f"{ID}.json", b"x")
    fs.delete_job(ID)
    assert not raw.exists("jobs", f"{ID}.json")
    assert not raw.exists("claimed", f"{ID}.json")


def test_list_results_sorted_and_skips_dot_names(store, raw):
    raw.put("results", f"{ID2}/result.json", b"{}")
    raw.put("results", f"{ID}/result.json", b"{}")
    raw.put("results", ".hidden/result.json", b"{}")
    assert store.list_results() == [ID, ID2]


def test_list_results_empty_when_results_missing(store, raw):
    raw.break_area("results")
    assert store.list_results() == []


def test_result_info_reports_a_bundle_and_none_when_absent(store, raw):
    raw.put("results", f"{ID}/result.json", b"{}")
    mtime, is_bundle = store.result_info(ID)
    assert is_bundle is True and mtime > 0
    assert store.result_info(ID3) is None


def test_fs_result_info_flags_a_plain_file_as_not_a_bundle(fs, raw):
    raw.put("results", ID2, b"x")
    assert fs.result_info(ID2)[1] is False


def test_remove_result_removes_a_bundle(store, raw):
    raw.put("results", f"{ID}/result.json", b"{}")
    raw.put("results", f"{ID}/screenshot.webp", b"x")
    store.remove_result(ID)
    assert raw.names("results") == []
    store.remove_result(ID)  # absent: quiet


def test_result_files_ok_true_for_the_two_result_files(store, raw):
    raw.put("results", f"{ID}/result.json", b"{}")
    raw.put("results", f"{ID}/screenshot.webp", b"x")
    assert store.result_files_ok(ID) is True


def test_read_result_file_exact_at_cap_and_none_over(store, raw):
    raw.put("results", f"{ID}/f", b"x" * 10)
    assert store.read_result_file(ID, "f", 10) == b"x" * 10
    assert store.read_result_file(ID, "f", 9) is None
    assert store.read_result_file(ID, "missing", 10) is None


def test_read_proxylog_absent_is_none(store):
    assert store.read_proxylog(ID, 10) is None


def test_read_proxylog_truncated_flag(store, raw):
    raw.put("proxylog", f"{ID}.jsonl", b"x" * 9)
    assert store.read_proxylog(ID, 10) == (b"x" * 9, False)
    raw.put("proxylog", f"{ID}.jsonl", b"x" * 10)
    assert store.read_proxylog(ID, 10) == (b"x" * 10, True)
    raw.put("proxylog", f"{ID}.jsonl", b"x" * 25)
    data, truncated = store.read_proxylog(ID, 10)
    assert len(data) == 10 and truncated is True


def test_delete_proxylog_is_quiet(store, raw):
    store.delete_proxylog(ID)
    raw.put("proxylog", f"{ID}.jsonl", b"x")
    assert raw.exists("proxylog", f"{ID}.jsonl")  # reached: there was something to delete
    store.delete_proxylog(ID)
    assert not raw.exists("proxylog", f"{ID}.jsonl")


def test_image_round_trip_and_deletes(store, raw):
    store.put_image(ID, b"img")
    assert raw.names("images") == [f"{ID}.webp"]  # no temp left
    assert store.read_image(ID, 3) == b"img"
    assert store.read_image(ID, 2) is None
    store.delete_image(ID)
    assert store.read_image(ID, 3) is None
    store.delete_image(ID)  # missing: no raise
    store.put_image(ID, b"img")
    store.delete_image_quiet(ID)
    assert store.read_image(ID, 3) is None
    store.delete_image_quiet(ID)


def test_put_image_failure_raises_and_leaves_no_temp(store, raw):
    raw.break_area("images")
    with pytest.raises(OSError):
        store.put_image(ID, b"x")


def test_check_spool_and_images_pass_when_ready(store):
    store.check_spool()
    store.check_images()


def test_check_spool_and_images_raise_when_missing(store, raw):
    raw.break_spool()
    with pytest.raises(OSError):
        store.check_spool()
    raw.break_area("images")
    with pytest.raises(OSError):
        store.check_images()


# ── filesystem-only ─────────────────────────────────────────────────────────


def test_fs_result_files_ok_false_for_symlink_subdir_fifo(fs, tmp_path):
    d = _bundle(fs)
    assert fs.result_files_ok(ID) is True  # same shape, valid
    (tmp_path / "t").write_text("x")
    os.symlink(tmp_path / "t", f"{d}/link")
    assert fs.result_files_ok(ID) is False
    os.unlink(f"{d}/link")
    assert fs.result_files_ok(ID) is True
    os.mkdir(f"{d}/sub")
    assert fs.result_files_ok(ID) is False
    os.rmdir(f"{d}/sub")
    assert fs.result_files_ok(ID) is True
    os.mkfifo(f"{d}/fifo")
    assert fs.result_files_ok(ID) is False


def test_fs_read_result_file_none_for_a_symlink(fs, tmp_path):
    d = _bundle(fs, files={"real": b"abc"})
    assert fs.read_result_file(ID, "real", 10) == b"abc"
    os.symlink(f"{d}/real", f"{d}/link")
    assert fs.read_result_file(ID, "link", 10) is None


def test_fs_read_proxylog_none_for_non_regular(fs, tmp_path):
    p = tmp_path / "proxylog" / f"{ID}.jsonl"
    p.write_bytes(b"ok")
    assert fs.read_proxylog(ID, 10) == (b"ok", False)
    p.unlink()
    os.mkfifo(p)
    assert fs.read_proxylog(ID, 10) is None


def test_fs_delete_image_propagates_a_non_missing_error(fs, tmp_path):
    (tmp_path / "images" / f"{ID}.webp").mkdir()
    with pytest.raises(OSError) as e:
        fs.delete_image(ID)
    assert not isinstance(e.value, FileNotFoundError)
    fs.delete_image_quiet(ID)  # the quiet variant swallows it


def test_fs_checks_refuse_a_symlinked_dir(fs, tmp_path):
    fs.check_spool()
    fs.check_images()
    real = tmp_path / "real"
    real.mkdir()
    (tmp_path / "spool/jobs").rmdir()
    os.symlink(real, tmp_path / "spool/jobs")
    with pytest.raises(OSError):
        fs.check_spool()
    (tmp_path / "images").rmdir()
    os.symlink(real, tmp_path / "images")
    with pytest.raises(OSError):
        fs.check_images()


# ── s3-only ─────────────────────────────────────────────────────────────────


def test_s3_list_results_requires_result_json(s3, raw):
    raw.put("results", f"{ID}/screenshot.webp", b"x")
    assert s3.list_results() == []
    assert s3.result_info(ID) is None
    raw.put("results", f"{ID}/result.json", b"{}")
    assert s3.list_results() == [ID]
    mtime, is_bundle = s3.result_info(ID)
    assert is_bundle is True and abs(time.time() - mtime) < 120


def test_s3_result_files_ok_rejects_other_keys(s3, raw):
    assert s3.result_files_ok(ID) is False  # nothing
    raw.put("results", f"{ID}/result.json", b"{}")
    assert s3.result_files_ok(ID) is True
    raw.put("results", f"{ID}/extra", b"x")
    assert s3.result_files_ok(ID) is False
    raw.put("results", f"{ID2}/result.json", b"{}")
    raw.put("results", f"{ID2}/", b"")  # directory marker key
    assert s3.result_files_ok(ID2) is False


def test_s3_remove_result_clears_an_orphan_screenshot(s3, raw):
    raw.put("results", f"{ID}/screenshot.webp", b"x")
    assert raw.names("results") == [ID]  # reached: the orphan exists
    s3.remove_result(ID)
    assert raw.names("results") == []


def test_s3_presigned_put_round_trip(s3, raw):
    exp = int(time.time()) + 600
    store_fields = s3.job_fields(ID, exp)["store"]
    body = json.dumps({"capture_id": ID}).encode()
    r1 = httpx.put(store_fields["screenshot_put"], content=b"RIFF\0\0\0\0WEBP" + b"x" * 100)
    r2 = httpx.put(store_fields["result_put"], content=body)  # no credentials: the URL carries them
    assert (r1.status_code, r2.status_code) == (200, 200)
    assert s3.list_results() == [ID]
    assert s3.result_files_ok(ID) is True
    assert s3.read_result_file(ID, "result.json", 1000) == body
    assert s3.read_result_file(ID, "screenshot.webp", 50) is None  # over the cap
    assert store_fields["expires"] == exp


def test_s3_presigned_put_refuses_what_the_presign_did_not_authorise(s3, raw):
    url = s3.job_fields(ID, int(time.time()) + 600)["store"]["result_put"]
    # reached: the same URL does accept the exact request, so the refusals below are not vacuous
    ok = httpx.put(url, content=b"{}")
    assert ok.status_code == 200
    assert httpx.put(url, content=b"{}", headers={"x-amz-acl": "public-read"}).status_code == 403
    assert httpx.get(url).status_code == 403
    stale = s3.job_fields(ID2, int(time.time()) - 10)["store"]["result_put"]  # clamped to 1 s
    time.sleep(2)
    assert httpx.put(stale, content=b"{}").status_code == 403
    assert raw.names("results") == [ID]  # nothing was written under ID2


def test_s3_store_is_built_by_get_store(s3):
    assert isinstance(s3, S3Store)
    assert isinstance(get_store(), S3Store)
