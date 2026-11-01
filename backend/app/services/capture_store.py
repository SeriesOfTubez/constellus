"""The store behind page capture's spool contract (docs/architecture/capture-spool.md).

A backend implements `CaptureStore`. The filesystem one keeps the defences that
only make sense on a filesystem (lstat, no symlinks, O_NOFOLLOW / O_NONBLOCK,
an fstat re-check, regular files only). CONTENT checks (JSON parse, magic
bytes, sha256, field validation) stay in page_capture.py so every backend gets
them. Callers pass capture ids / names, never paths: file names are built only
here, only from a capture id. planning#318. The S3 backend lives in
capture_store_s3.py."""

import logging
import os
import shutil
import stat
from typing import Protocol

log = logging.getLogger(__name__)


class StoreConfigError(OSError):
    """CAPTURE_STORE names an unknown backend, or the chosen backend's env is incomplete.
    An OSError so every caller's existing fail-closed path (spool_unavailable, skipped
    ingest/prune) applies. Never a fallback to another backend."""


def spool_dir() -> str:
    return os.environ.get("CAPTURE_SPOOL_DIR", "/spool")


def proxylog_dir() -> str:
    return os.environ.get("CAPTURE_PROXYLOG_DIR", "/proxylog")


def images_dir() -> str:
    return os.environ.get("CAPTURE_IMAGES_DIR", "/captures")


def _unlink_quiet(path: str) -> None:
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass
    except OSError:
        log.warning("page_capture: could not remove %s", path)


def _remove_entry(path: str) -> None:
    """Remove a spool entry without following symlinks (rmtree refuses a
    symlinked top, and unlinks symlinks inside rather than entering them)."""
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return
    try:
        if stat.S_ISDIR(st.st_mode):
            shutil.rmtree(path)
        else:
            os.unlink(path)
    except OSError:
        log.warning("page_capture: could not remove %s", path)


def _open_regular(path: str) -> int:
    """Open a spool file for reading, safely against a swap after the caller's
    lstat: O_NOFOLLOW refuses a symlink, O_NONBLOCK keeps a FIFO from blocking
    the scheduler thread on open, and the fstat re-checks the opened object is
    a regular file. Raises OSError otherwise."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        raise OSError(f"not a regular file: {path}")
    return fd


class CaptureStore(Protocol):
    # spool: jobs/ claimed/ results/
    def check_spool(self) -> None: ...
    def put_job(self, capture_id: str, payload: bytes) -> None: ...
    def delete_job(self, capture_id: str) -> None: ...
    # extra job keys the worker needs to reach this store (S3: presigned PUTs); {} on the filesystem
    def job_fields(self, capture_id: str, expires_at: int) -> dict: ...
    def sweep_claims(self) -> int: ...
    def list_results(self) -> list[str]: ...
    def result_info(self, name: str) -> tuple[float, bool] | None: ...
    def remove_result(self, name: str) -> None: ...
    def result_files_ok(self, name: str) -> bool: ...
    def read_result_file(self, name: str, filename: str, cap: int) -> bytes | None: ...
    # proxy log (written by capture-proxy, one per capture)
    def read_proxylog(self, capture_id: str, cap: int) -> tuple[bytes, bool] | None: ...
    def delete_proxylog(self, capture_id: str) -> None: ...
    # images (backend-owned, served only through the backend)
    def check_images(self) -> None: ...
    def put_image(self, capture_id: str, data: bytes) -> None: ...
    def read_image(self, capture_id: str, cap: int) -> bytes | None: ...
    def delete_image(self, capture_id: str) -> None: ...
    def delete_image_quiet(self, capture_id: str) -> None: ...


def _read_regular_capped(path: str, cap: int) -> bytes | None:
    """lstat, require a regular file within `cap`, open without following
    symlinks, read cap+1. None for missing / not regular / over cap / OSError."""
    try:
        st = os.lstat(path)
        if not stat.S_ISREG(st.st_mode) or st.st_size > cap:
            return None
        fd = _open_regular(path)
    except OSError:
        return None
    with os.fdopen(fd, "rb") as f:
        data = f.read(cap + 1)
    if len(data) > cap:
        return None
    return data


def _check_real_dir(path: str) -> None:
    if not stat.S_ISDIR(os.lstat(path).st_mode):
        raise NotADirectoryError(path)


class FilesystemStore:
    def __init__(self, spool: str, proxylog: str, images: str):
        self._spool = spool
        self._proxylog = proxylog
        self._images = images

    # spool
    def check_spool(self) -> None:
        """The backend does not create the spool: the images pre-create jobs/,
        claimed/ and results/ with the shared-group mode. A missing directory,
        or one that is not a real directory (a symlink is refused), raises
        OSError."""
        for sub in ("jobs", "claimed", "results"):
            _check_real_dir(os.path.join(self._spool, sub))

    def put_job(self, capture_id: str, payload: bytes) -> None:
        jobs = os.path.join(self._spool, "jobs")
        tmp = os.path.join(jobs, f".{capture_id}.tmp")
        try:
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o640)
            with os.fdopen(fd, "wb") as f:
                f.write(payload)
            os.rename(tmp, os.path.join(jobs, f"{capture_id}.json"))
        except OSError:
            _unlink_quiet(tmp)
            raise

    def delete_job(self, capture_id: str) -> None:
        _unlink_quiet(os.path.join(self._spool, "jobs", f"{capture_id}.json"))
        _unlink_quiet(os.path.join(self._spool, "claimed", f"{capture_id}.json"))

    def job_fields(self, capture_id: str, expires_at: int) -> dict:
        return {}

    def sweep_claims(self) -> int:
        return 0  # the filesystem claims by atomic rename: there are no markers

    def list_results(self) -> list[str]:
        try:
            names = sorted(os.listdir(os.path.join(self._spool, "results")))
        except FileNotFoundError:
            return []
        return [n for n in names if not n.startswith(".")]

    def result_info(self, name: str) -> tuple[float, bool] | None:
        try:
            st = os.lstat(os.path.join(self._spool, "results", name))
        except OSError:
            return None
        return st.st_mtime, stat.S_ISDIR(st.st_mode)

    def remove_result(self, name: str) -> None:
        _remove_entry(os.path.join(self._spool, "results", name))

    def result_files_ok(self, name: str) -> bool:
        path = os.path.join(self._spool, "results", name)
        try:
            entries = os.listdir(path)
        except OSError:
            return False
        for entry in entries:
            try:
                mode = os.lstat(os.path.join(path, entry)).st_mode
            except OSError:
                return False
            if not stat.S_ISREG(mode):
                return False
        return True

    def read_result_file(self, name: str, filename: str, cap: int) -> bytes | None:
        return _read_regular_capped(os.path.join(self._spool, "results", name, filename), cap)

    # proxy log
    def read_proxylog(self, capture_id: str, cap: int) -> tuple[bytes, bool] | None:
        path = os.path.join(self._proxylog, f"{capture_id}.jsonl")
        try:
            st = os.lstat(path)
        except FileNotFoundError:
            return None
        if not stat.S_ISREG(st.st_mode):
            log.warning("page_capture: ignoring non-regular proxy log for %s", capture_id)
            return None
        try:
            fd = _open_regular(path)
        except OSError:
            return None
        with os.fdopen(fd, "rb") as f:
            data = f.read(cap)
        return data, st.st_size >= cap

    def delete_proxylog(self, capture_id: str) -> None:
        _unlink_quiet(os.path.join(self._proxylog, f"{capture_id}.jsonl"))

    # images
    def check_images(self) -> None:
        _check_real_dir(self._images)

    def put_image(self, capture_id: str, data: bytes) -> None:
        tmp = os.path.join(self._images, f".{capture_id}.tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW | os.O_CLOEXEC, 0o640)
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(data)
            os.rename(tmp, os.path.join(self._images, f"{capture_id}.webp"))
        except OSError:
            _unlink_quiet(tmp)
            raise

    def read_image(self, capture_id: str, cap: int) -> bytes | None:
        return _read_regular_capped(os.path.join(self._images, f"{capture_id}.webp"), cap)

    def delete_image(self, capture_id: str) -> None:
        try:
            os.unlink(os.path.join(self._images, f"{capture_id}.webp"))
        except FileNotFoundError:
            pass

    def delete_image_quiet(self, capture_id: str) -> None:
        _unlink_quiet(os.path.join(self._images, f"{capture_id}.webp"))


def get_store() -> CaptureStore:
    """Built at CALL time so a test's per-test env applies. CAPTURE_STORE selects the
    backend (default filesystem); an unknown value raises StoreConfigError, never falls back."""
    kind = os.environ.get("CAPTURE_STORE", "filesystem")
    if kind == "filesystem":
        return FilesystemStore(spool_dir(), proxylog_dir(), images_dir())
    if kind == "s3":
        from app.services.capture_store_s3 import s3_store_from_env  # botocore stays out of this module
        return s3_store_from_env()
    raise StoreConfigError(f"CAPTURE_STORE={kind!r} is not a known capture store (filesystem|s3)")
