"""Host-side end-to-end check for the kind lab (planning#324). TEST ONLY.

Plays the backend: creates the lab buckets, presigns two PUTs (result.json and
screenshot.webp) for the host the WORKER uses (http://rustfs:9000), derives the
proxy credential, and puts N jobs into the jobs bucket. Then it waits for each
result.json, and checks the screenshot (WebP magic), that the worker's claim
deleted the job object, and that the proxy wrote a log whose records all carry
the capture id. With --count N it reports, per capture, the seconds from enqueue
to result.json, plus the browser pod's restart count: the measure of the
kubelet's restart back-off between one-page-per-container captures.

Run through `scripts/kind-lab.sh e2e [url] [--count N]`, which provides the
port-forward and the credentials (RUSTFS_ACCESS_KEY, RUSTFS_SECRET_KEY,
CAPTURE_PROXY_KEY) in the environment, and KIND_LAB_ENDPOINT. Prints shapes and
counts only, never a key, a presigned URL or page content.

Exit status is 0 only if every capture passes every check.
"""

import argparse
import hashlib
import hmac
import json
import os
import subprocess
import sys
import time
import uuid
from urllib.parse import urlsplit

import botocore.session
from botocore.config import Config
from botocore.exceptions import ClientError

PUBLIC = "http://rustfs:9000"  # what the worker and the proxy use
# The live backend's ingest discards and deletes any result it does not know, so this
# host-driven check uses its OWN results bucket, which the backend never scans.
RESULTS = "lab-e2e-results"
JOBS, PROXYLOG = "lab-jobs", "lab-proxylog"
RESULT_TIMEOUT_S = 150
BASE_TTL_S = 900


def client(endpoint, access, secret):
    return botocore.session.get_session().create_client(
        "s3",
        region_name="us-east-1",
        endpoint_url=endpoint,
        aws_access_key_id=access,
        aws_secret_access_key=secret,
        config=Config(signature_version="s3v4", s3={"addressing_style": "path"}),
    )


def code(e):
    return e.response.get("Error", {}).get("Code", "")


def get_body(c, bucket, key):
    try:
        return c.get_object(Bucket=bucket, Key=key)["Body"].read()
    except ClientError as e:
        if code(e) in ("NoSuchKey", "404", "NotFound"):
            return None
        raise


def exists(c, bucket, key):
    try:
        c.head_object(Bucket=bucket, Key=key)
        return True
    except ClientError as e:
        if code(e) in ("404", "NoSuchKey", "NotFound"):
            return False
        raise


def restart_count():
    ctx = os.environ.get("KIND_LAB_CONTEXT", "kind-constellus-lab")
    try:
        out = subprocess.run(
            ["kubectl", "--context", ctx, "-n", "constellus", "get", "pod",
             "-l", "app.kubernetes.io/name=capture-browser",
             "-o", "jsonpath={.items[0].status.containerStatuses[0].restartCount}"],
            check=True, capture_output=True, text=True, timeout=30,
        ).stdout
        return out.strip() or "?"
    except (subprocess.SubprocessError, OSError):
        return "?"


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("url", nargs="?", default="http://example.com/")
    ap.add_argument("--count", type=int, default=1)
    args = ap.parse_args()
    if args.count < 1:
        ap.error("--count must be >= 1")

    endpoint = os.environ["KIND_LAB_ENDPOINT"]
    access, secret = os.environ["RUSTFS_ACCESS_KEY"], os.environ["RUSTFS_SECRET_KEY"]
    key = os.environ["CAPTURE_PROXY_KEY"].encode()
    c = client(endpoint, access, secret)
    signer = client(PUBLIC, access, secret)  # presigning is offline

    for b in (JOBS, RESULTS, PROXYLOG):
        try:
            c.create_bucket(Bucket=b)
        except ClientError as e:
            if code(e) not in ("BucketAlreadyOwnedByYou", "BucketAlreadyExists"):
                raise

    exp = int(time.time()) + BASE_TTL_S + RESULT_TIMEOUT_S * args.count

    def presign(k):
        return signer.generate_presigned_url(
            "put_object", Params={"Bucket": RESULTS, "Key": k}, ExpiresIn=exp - int(time.time()), HttpMethod="PUT"
        )

    caps = []
    for _ in range(args.count):
        cid = str(uuid.uuid4())
        token = hmac.new(key, f"v3|{cid}|live|{exp}".encode("ascii"), hashlib.sha256).hexdigest()
        job = {
            "v": 3, "capture_id": cid, "url": args.url, "mode": "live",
            "proxy_token": token, "proxy_expires": exp,
            "viewport": {"width": 1280, "height": 800},
            "max_image_bytes": 2097152, "webp_qualities": [80, 60, 40],
            "user_agent_mode": "stock",
            "store": {
                "result_put": presign(f"results/{cid}/result.json"),
                "screenshot_put": presign(f"results/{cid}/screenshot.webp"),
                "expires": exp,
            },
        }
        c.put_object(Bucket=JOBS, Key=f"jobs/{cid}.json", Body=json.dumps(job).encode(), ContentType="application/json")
        caps.append({"id": cid, "t0": time.monotonic()})
    print(f"queued {len(caps)} job(s) for host {urlsplit(args.url).hostname}")

    failures = 0
    deadline = time.monotonic() + RESULT_TIMEOUT_S * args.count
    for cap in caps:
        cid = cap["id"]
        raw = None
        while time.monotonic() < deadline:
            raw = get_body(c, RESULTS, f"results/{cid}/result.json")
            if raw is not None:
                cap["secs"] = time.monotonic() - cap["t0"]
                break
            time.sleep(1)
        problems = []
        if raw is None:
            print(f"capture {cid[:8]}: NO result.json within the timeout")
            failures += 1
            continue
        res = json.loads(raw)
        if res.get("status") is None or res.get("error"):
            problems.append("status missing or error set")
        shot = get_body(c, RESULTS, f"results/{cid}/screenshot.webp")
        if not (shot and shot[:4] == b"RIFF" and shot[8:12] == b"WEBP"):
            problems.append("screenshot is not WebP")
        if exists(c, JOBS, f"jobs/{cid}.json"):
            problems.append("job object still present (claim did not delete it)")
        cap["res"], cap["problems"], cap["shot"] = res, problems, shot

    time.sleep(4)  # the proxy flushes its log object about once a second
    for cap in caps:
        if "res" not in cap:
            continue
        cid, res, problems = cap["id"], cap["res"], cap["problems"]
        raw = get_body(c, PROXYLOG, f"proxylog/{cid}.jsonl")
        recs = [json.loads(line) for line in (raw or b"").splitlines() if line.strip()]
        if not recs:
            problems.append("no proxy log")
        elif any(r.get("capture_id") != cid for r in recs):
            problems.append("proxy log has a record with another capture_id")
        decisions = sorted({r.get("decision") for r in recs})
        hosts = sorted({r.get("host") for r in recs})
        final_host = urlsplit(res.get("final_url") or "").hostname
        print(
            f"capture {cid[:8]}: status={res.get('status')} error={res.get('error')} "
            f"final_host={final_host} requests={len(res.get('requests') or [])} "
            f"screenshot_bytes={len(cap['shot'] or b'')} proxy_records={len(recs)} "
            f"decisions={decisions} hosts={hosts} seconds={cap['secs']:.1f} "
            f"{'FAIL: ' + '; '.join(problems) if problems else 'OK'}"
        )
        failures += bool(problems)

    secs = [round(c_["secs"], 1) for c_ in caps if "secs" in c_]
    print(f"seconds enqueue->result: {secs}")
    print(f"capture-browser restart count: {restart_count()}")
    print("RESULT:", "PASS" if failures == 0 else f"FAIL ({failures})")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
