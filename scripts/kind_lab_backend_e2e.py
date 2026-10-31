"""Host-side end-to-end check of the REAL backend in the kind lab (planning#327). TEST ONLY.

Queues one capture of the seeded candidate through the real API
(POST /api/organizations/candidates/{id}/captures, so `authorise_candidate_browse`
runs exactly as in production), waits for the backend's own ingest to finish it,
then checks the store: the job object and the proxy log are gone, nothing is left
under results/{id}/, and the screenshot is in the images bucket.

Run through `scripts/kind-lab.sh backend-e2e`, which seeds the lab, logs in, and
provides: the candidate id (argv), KIND_LAB_BACKEND (base URL), KIND_LAB_AUTH_FILE
(a 0600 file holding the Authorization header line), KIND_LAB_ENDPOINT (the
port-forwarded RustFS) and RUSTFS_ACCESS_KEY / RUSTFS_SECRET_KEY. Prints one line
per check plus shapes and counts only: never a token, a key, a presigned URL, the
error text, the page title or any page content.

Exit status is 0 only if every check passes.
"""

import argparse
import http.client
import json
import os
import sys
import time
from urllib.parse import urlsplit

import botocore.session
from botocore.config import Config
from botocore.exceptions import ClientError

JOBS, RESULTS, PROXYLOG, IMAGES = "lab-jobs", "lab-results", "lab-proxylog", "lab-images"
POLL_S = 5
MISSING = ("404", "NoSuchKey", "NotFound")


def read_auth_header(path):
    with open(path, encoding="utf-8") as fh:
        name, _, value = fh.read().strip().partition(":")
    return name.strip(), value.strip()


def api(base, auth, method, path):
    """Returns (status, parsed JSON or None). Never raises on an HTTP error status.
    http.client, not urllib: it speaks http(s) only, so a URL can never be a file."""
    parts = urlsplit(base)
    if parts.scheme != "http" or not parts.hostname:
        raise SystemExit("KIND_LAB_BACKEND must be an http:// URL")
    conn = http.client.HTTPConnection(parts.hostname, parts.port or 80, timeout=30)
    headers = {auth[0]: auth[1]}
    body = None
    if method == "POST":
        headers["Content-Type"] = "application/json"
        body = b"{}"
    try:
        conn.request(method, path, body=body, headers=headers)
        resp = conn.getresponse()
        raw = resp.read()
        try:
            return resp.status, json.loads(raw or b"null")
        except ValueError:
            return resp.status, None
    finally:
        conn.close()


def s3_client(endpoint, access, secret):
    return botocore.session.get_session().create_client(
        "s3", region_name="us-east-1", endpoint_url=endpoint,
        aws_access_key_id=access, aws_secret_access_key=secret,
        config=Config(signature_version="s3v4", s3={"addressing_style": "path"}),
    )


def head_size(c, bucket, key):
    """Object size, or None when absent."""
    try:
        return c.head_object(Bucket=bucket, Key=key)["ContentLength"]
    except ClientError as e:
        if e.response.get("Error", {}).get("Code", "") in MISSING:
            return None
        raise


def list_keys(c, bucket, prefix):
    resp = c.list_objects_v2(Bucket=bucket, Prefix=prefix)
    return [o["Key"] for o in resp.get("Contents", [])]


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("candidate_id")
    ap.add_argument("--timeout", type=int, default=300)
    args = ap.parse_args()

    base = os.environ["KIND_LAB_BACKEND"].rstrip("/")
    auth = read_auth_header(os.environ["KIND_LAB_AUTH_FILE"])
    cid = args.candidate_id
    caps_path = f"/api/organizations/candidates/{cid}/captures"

    t0 = time.monotonic()
    status, body = api(base, auth, "POST", caps_path)
    if status == 202 and isinstance(body, dict):
        cap_id = body["id"]
        print("queued a capture through the API")
    elif status == 409 and isinstance(body, dict) and (body.get("detail") or {}).get("rule") == "capture:already_queued":
        # The hourly capture_sweep may have queued one first: follow the newest queued one.
        lst_status, rows = api(base, auth, "GET", caps_path)
        queued = [r for r in (rows or []) if r.get("status") == "queued"] if lst_status == 200 else []
        if not queued:
            print("FAIL  409 already_queued but no queued capture is listed")
            return 1
        cap_id = queued[0]["id"]  # the list is newest first
        print("a capture was already queued (the sweep got there first); following it")
    else:
        detail = body.get("detail") if isinstance(body, dict) else None
        rule = detail.get("rule") if isinstance(detail, dict) else detail
        print(f"FAIL  the API refused the capture: HTTP {status}, rule {rule}")
        return 1

    row = None
    deadline = t0 + args.timeout
    while time.monotonic() < deadline:
        lst_status, rows = api(base, auth, "GET", caps_path)
        row = next((r for r in (rows or []) if r.get("id") == cap_id), None) if lst_status == 200 else None
        if row and row.get("status") in ("done", "failed"):
            break
        time.sleep(POLL_S)
    secs = time.monotonic() - t0

    failures = 0

    def check(ok, desc):
        nonlocal failures
        print(f"{'PASS' if ok else 'FAIL'}  {desc}")
        failures += 0 if ok else 1

    if row is None or row.get("status") not in ("done", "failed"):
        check(False, f"capture reached done/failed within {args.timeout} s (last status: {row.get('status') if row else 'not listed'})")
        return 1
    print(f"seconds POST->{row['status']}: {secs:.1f}")
    print(f"status={row['status']} http_status={row.get('http_status')} request_count={row.get('request_count')}")
    if row["status"] == "failed":
        print(f"failure_reason={row.get('failure_reason')}")
    check(row["status"] == "done", "capture status is done")
    check(row.get("http_status") == 200, "http_status is 200")
    check(row.get("has_image") is True, "capture has an image")
    check((row.get("request_count") or 0) >= 1, "request_count >= 1")

    c = s3_client(os.environ["KIND_LAB_ENDPOINT"], os.environ["RUSTFS_ACCESS_KEY"], os.environ["RUSTFS_SECRET_KEY"])
    check(head_size(c, JOBS, f"jobs/{cap_id}.json") is None, "jobs/{id}.json is absent")
    check(not list_keys(c, RESULTS, f"results/{cap_id}/"), "nothing is left under results/{id}/")
    check(head_size(c, PROXYLOG, f"proxylog/{cap_id}.jsonl") is None, "proxylog/{id}.jsonl is absent")
    size = head_size(c, IMAGES, f"images/{cap_id}.webp")
    check(size is not None, "images/{id}.webp is present")
    print(f"image_bytes={size}")

    print("RESULT:", "PASS" if failures == 0 else f"FAIL ({failures})")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
