"""Host-side end-to-end check for the kind lab (planning#324). TEST ONLY.

Plays the backend: creates the lab buckets, presigns two PUTs (result.json and
screenshot.webp) for the host the WORKER uses (http://rustfs:9000), derives the
proxy credential, and puts N jobs into the jobs bucket. Then it waits for each
result.json, and checks the screenshot (WebP magic), that the worker's claim
deleted the job object, and that the proxy wrote a log whose records all carry
the capture id. With --count N it reports, per capture, the seconds from enqueue
to result.json, plus the browser pod's restart count: the measure of the
kubelet's restart back-off between one-page-per-container captures.

Every job also carries `store.claim_put`: a presigned conditional PUT (If-None-Match: *)
of claims/<cid> in the results bucket, which the worker requires. The check asserts that
claims/<cid> exists for every capture. With --workers N (N >= 2) it also reads the
capture-browser pods' logs and asserts each capture has EXACTLY ONE "capture-worker:
<cid>: claimed" line across them and that every pod claimed at least one capture
(planning#323: the claim race really ran). The kubelet keeps one container log per
container instance, and the supervisor respawns the worker INSIDE the container, so a
pod's current log holds every capture; the check records each container's restartCount
before queueing and FAILS if it changed (the log method would then be unreliable).

Run through `scripts/kind-lab.sh e2e [url] [--count N] [--workers N]`, which provides the
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


def kubectl(*args):
    ctx = os.environ.get("KIND_LAB_CONTEXT", "kind-constellus-lab")
    return subprocess.run(
        ["kubectl", "--context", ctx, "-n", "constellus", *args],
        check=True, capture_output=True, text=True, timeout=60,
    ).stdout


def browser_pods():
    """{pod name: restartCount} for the live capture-browser pods."""
    out = kubectl(
        "get", "pods", "-l", "app.kubernetes.io/name=capture-browser", "-o",
        "go-template={{range .items}}{{if not .metadata.deletionTimestamp}}"
        "{{.metadata.name}} {{(index .status.containerStatuses 0).restartCount}}\n{{end}}{{end}}",
    )
    return {n: int(r) for n, r in (line.split() for line in out.splitlines() if line.strip())}


def claimed_lines(pod):
    """cid -> number of 'claimed' lines in the pod's capture-browser container log."""
    log = kubectl("logs", pod, "-c", "capture-browser", "--limit-bytes=50000000")
    counts = {}
    for line in log.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[0] == "capture-worker:" and parts[2] == "claimed" and parts[1].endswith(":"):
            counts[parts[1][:-1]] = counts.get(parts[1][:-1], 0) + 1
    return counts


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


def check_claim_race(workers, pods_before, cids):
    """Every cid claimed exactly once across the pods; every pod claimed at least one."""
    problems = []
    pods_after = browser_pods()
    if set(pods_after) != set(pods_before):
        problems.append(f"pod set changed during the run: {sorted(pods_before)} -> {sorted(pods_after)}")
    for pod, n in pods_before.items():
        if pods_after.get(pod) != n:
            problems.append(f"{pod} restarted its container during the run; its log no longer holds every capture")
    per_pod = {pod: claimed_lines(pod) for pod in pods_before}
    for cid in cids:
        n = sum(counts.get(cid, 0) for counts in per_pod.values())
        if n != 1:
            problems.append(f"{cid[:8]}: {n} 'claimed' lines across the pods (want exactly 1)")
    mine = {pod: sum(1 for cid in cids if counts.get(cid)) for pod, counts in per_pod.items()}
    for pod, n in mine.items():
        if n < 1:
            problems.append(f"{pod} claimed no capture: the race was not exercised")
    print(f"claimed per pod: {sorted(mine.values())} of {len(cids)} captures across {len(per_pod)} pods")
    for p in problems:
        print(f"claim race FAIL: {p}")
    return 1 if problems else 0


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("url", nargs="?", default="http://example.com/")
    ap.add_argument("--count", type=int, default=1)
    ap.add_argument("--workers", type=int, default=1, help="expected capture-browser pods; >= 2 adds the claim-race checks")
    args = ap.parse_args()
    if args.count < 1:
        ap.error("--count must be >= 1")
    if args.workers < 1:
        ap.error("--workers must be >= 1")
    if args.workers > 1 and args.count < 6:
        ap.error("--workers >= 2 needs --count >= 6 (or the race may not be exercised)")
    pods_before = browser_pods() if args.workers > 1 else {}
    if args.workers > 1 and len(pods_before) != args.workers:
        print(f"RESULT: FAIL (expected {args.workers} capture-browser pods, found {len(pods_before)})")
        return 1

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
                "claim_put": signer.generate_presigned_url(
                    "put_object", Params={"Bucket": RESULTS, "Key": f"claims/{cid}", "IfNoneMatch": "*"},
                    ExpiresIn=exp - int(time.time()), HttpMethod="PUT",
                ),
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
        if not exists(c, RESULTS, f"claims/{cid}"):
            problems.append("claims/<cid> marker missing (the claim path was not used)")
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

    if args.workers > 1:
        failures += check_claim_race(args.workers, pods_before, [c_["id"] for c_ in caps])

    secs = [round(c_["secs"], 1) for c_ in caps if "secs" in c_]
    print(f"seconds enqueue->result: {secs}")
    print(f"capture-browser restart count: {restart_count()}")
    print("RESULT:", "PASS" if failures == 0 else f"FAIL ({failures})")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
