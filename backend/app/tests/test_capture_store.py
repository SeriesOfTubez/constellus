"""CaptureStore conformance (planning#318). No DB. The `store` fixture is parameterised so
a later backend can be added to `params`; tests marked FS-only build symlinks, FIFOs and
directories and so exercise the filesystem defences only."""

import os

import pytest

from app.services.capture_store import FilesystemStore, get_store

ID = "11111111-1111-4111-8111-111111111111"
ID2 = "22222222-2222-4222-8222-222222222222"


@pytest.fixture(params=["filesystem"])
def store(request, tmp_path):
    for sub in ("spool/jobs", "spool/claimed", "spool/results", "proxylog", "images"):
        (tmp_path / sub).mkdir(parents=True)
    return FilesystemStore(str(tmp_path / "spool"), str(tmp_path / "proxylog"), str(tmp_path / "images"))


@pytest.fixture
def fs(store):
    if not isinstance(store, FilesystemStore):
        pytest.skip("filesystem-only")
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
    monkeypatch.setenv("CAPTURE_SPOOL_DIR", str(tmp_path / "a"))
    assert get_store()._spool == str(tmp_path / "a")
    monkeypatch.setenv("CAPTURE_SPOOL_DIR", str(tmp_path / "b"))
    assert get_store()._spool == str(tmp_path / "b")


def test_put_job_publishes_exact_bytes_and_no_temp(store, tmp_path):
    store.put_job(ID, b'{"a":1}')
    assert (tmp_path / "spool/jobs" / f"{ID}.json").read_bytes() == b'{"a":1}'
    assert [p.name for p in (tmp_path / "spool/jobs").iterdir()] == [f"{ID}.json"]


def test_put_job_failure_raises_and_leaves_no_temp(store, tmp_path):
    (tmp_path / "spool/jobs").rmdir()
    with pytest.raises(OSError):
        store.put_job(ID, b"x")
    assert not (tmp_path / "spool/jobs").exists()


def test_delete_job_removes_queued_and_claimed_and_is_quiet_when_absent(store, tmp_path):
    store.delete_job(ID)  # absent: no raise
    (tmp_path / "spool/jobs" / f"{ID}.json").write_text("x")
    (tmp_path / "spool/claimed" / f"{ID}.json").write_text("x")
    (tmp_path / "spool/jobs" / f"{ID2}.json").write_text("x")
    store.delete_job(ID)
    assert not (tmp_path / "spool/jobs" / f"{ID}.json").exists()
    assert not (tmp_path / "spool/claimed" / f"{ID}.json").exists()
    assert (tmp_path / "spool/jobs" / f"{ID2}.json").exists()  # only the named job


def test_list_results_sorted_and_skips_dot_names(store, tmp_path):
    for n in (ID2, ID, ".hidden"):
        (tmp_path / "spool/results" / n).mkdir()
    assert store.list_results() == [ID, ID2]


def test_list_results_empty_when_results_missing(store, tmp_path):
    (tmp_path / "spool/results").rmdir()
    assert store.list_results() == []


def test_result_info_flags_bundle_vs_file_and_none_when_absent(store, tmp_path):
    (tmp_path / "spool/results" / ID).mkdir()
    (tmp_path / "spool/results" / ID2).write_text("x")
    mtime, is_bundle = store.result_info(ID)
    assert is_bundle is True and mtime > 0
    assert store.result_info(ID2)[1] is False
    assert store.result_info("33333333-3333-4333-8333-333333333333") is None


def test_remove_result_removes_a_bundle(store, tmp_path):
    (tmp_path / "spool/results" / ID).mkdir()
    (tmp_path / "spool/results" / ID / "result.json").write_text("{}")
    store.remove_result(ID)
    assert not (tmp_path / "spool/results" / ID).exists()
    store.remove_result(ID)  # absent: quiet


def test_result_files_ok_true_for_regular_files(fs):
    _bundle(fs, files={"result.json": b"{}", "screenshot.webp": b"x"})
    assert fs.result_files_ok(ID) is True


def test_read_result_file_exact_at_cap_and_none_over(store, tmp_path):
    d = tmp_path / "spool/results" / ID
    d.mkdir()
    (d / "f").write_bytes(b"x" * 10)
    assert store.read_result_file(ID, "f", 10) == b"x" * 10
    assert store.read_result_file(ID, "f", 9) is None
    assert store.read_result_file(ID, "missing", 10) is None


def test_read_proxylog_absent_is_none(store):
    assert store.read_proxylog(ID, 10) is None


def test_read_proxylog_truncated_flag(store, tmp_path):
    p = tmp_path / "proxylog" / f"{ID}.jsonl"
    p.write_bytes(b"x" * 9)
    assert store.read_proxylog(ID, 10) == (b"x" * 9, False)
    p.write_bytes(b"x" * 10)
    assert store.read_proxylog(ID, 10) == (b"x" * 10, True)
    p.write_bytes(b"x" * 25)
    data, truncated = store.read_proxylog(ID, 10)
    assert len(data) == 10 and truncated is True


def test_delete_proxylog_is_quiet(store, tmp_path):
    store.delete_proxylog(ID)
    p = tmp_path / "proxylog" / f"{ID}.jsonl"
    p.write_text("x")
    store.delete_proxylog(ID)
    assert not p.exists()


def test_image_round_trip_and_deletes(store, tmp_path):
    store.put_image(ID, b"img")
    assert [p.name for p in (tmp_path / "images").iterdir()] == [f"{ID}.webp"]  # no temp left
    assert store.read_image(ID, 3) == b"img"
    assert store.read_image(ID, 2) is None
    store.delete_image(ID)
    assert store.read_image(ID, 3) is None
    store.delete_image(ID)  # missing: no raise
    store.put_image(ID, b"img")
    store.delete_image_quiet(ID)
    assert store.read_image(ID, 3) is None
    store.delete_image_quiet(ID)


def test_put_image_failure_raises_and_leaves_no_temp(store, tmp_path):
    (tmp_path / "images").rmdir()
    with pytest.raises(OSError):
        store.put_image(ID, b"x")


def test_check_spool_and_images_pass_when_ready(store):
    store.check_spool()
    store.check_images()


def test_check_spool_and_images_raise_when_missing(store, tmp_path):
    (tmp_path / "spool/claimed").rmdir()
    with pytest.raises(OSError):
        store.check_spool()
    (tmp_path / "images").rmdir()
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
