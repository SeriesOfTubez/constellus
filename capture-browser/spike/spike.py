"""Egress spike runner (planning#280 S5b-1). Runs INSIDE the capture-browser container.

    python /spike/spike.py browser --capture-id ID     # page-side checks -> JSON on stdout
    python /spike/spike.py net                         # raw-socket checks -> JSON on stdout

`browser` uses capture.run's launch_browser/new_context, i.e. the real launch
configuration, with no flags of its own. Only the spike document itself (and the
service-worker stub) is fulfilled locally via page.route; every other request goes
to the network, i.e. to the proxy. Evaluation happens on the host (evaluate.py).
"""

from __future__ import annotations

import argparse
import json
import secrets
import socket
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
SPIKE_HOSTS = ("http://spike.invalid/**", "https://spike.invalid/**")


def browser_mode(capture_id: str) -> dict:
    from playwright.sync_api import sync_playwright

    from capture.run import launch_browser, new_context, require_env

    proxy_url, token = require_env()
    rand = secrets.token_hex(4)
    html = (HERE / "spike.html").read_text().replace("__RAND__", rand)
    out: dict = {"rand": rand, "main": None, "sw": None, "requests": [], "responses": []}

    def fulfil(route):
        url = route.request.url
        if url.split("?")[0].endswith("/sw.js"):
            route.fulfill(status=200, content_type="text/javascript", body="// spike sw stub\n")
        else:
            route.fulfill(status=200, content_type="text/html", body=html)

    with sync_playwright() as p:
        browser = launch_browser(p, capture_id, proxy_url, token)
        try:
            ctx = new_context(browser)
            for pat in SPIKE_HOSTS:
                ctx.route(pat, fulfil)
            seen: list = []
            ctx.on("request", lambda r: seen.append(r))

            def on_resp(r):
                out["responses"].append({
                    "url": r.url, "status": r.status,
                    "proxy_reason": r.headers.get("x-capture-proxy-reason"),
                })
            ctx.on("response", on_resp)

            for key, url in (("main", "http://spike.invalid/"), ("sw", "https://spike.invalid/?mode=sw")):
                page = ctx.new_page()
                page.goto(url, wait_until="load", timeout=30_000)
                page.wait_for_function("window.__spike && window.__spike.done", timeout=30_000)
                time.sleep(1)  # let trailing requests (prefetch, subresources) surface
                out[key] = page.evaluate("window.__spike")  # a variable the spike page itself set
                page.close()
            out["requests"] = [
                {"url": r.url, "resource_type": r.resource_type, "failure": r.failure}
                for r in seen
            ]
        finally:
            browser.close()
    return out


def _tcp(host: str, port: int, timeout: float) -> str:
    t0 = time.time()
    try:
        s = socket.create_connection((host, port), timeout)
        s.close()
        return "connected"
    except OSError as e:
        return f"failed:{type(e).__name__}:{round(time.time() - t0, 1)}s"


def net_mode() -> dict:
    res: dict = {}
    res["tcp_proxy_sanity"] = _tcp("capture-proxy", 3128, 5)
    res["tcp_1.1.1.1:443"] = _tcp("1.1.1.1", 443, 5)
    res["tcp_8.8.8.8:53"] = _tcp("8.8.8.8", 53, 5)
    query = bytes.fromhex("abcd01000001000000000000") + b"\x07example\x03com\x00\x00\x01\x00\x01"
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3)
    try:
        s.sendto(query, ("1.1.1.1", 53))
        data = s.recv(512)
        res["udp_1.1.1.1:53"] = f"reply:{len(data)}B"
    except OSError as e:
        res["udp_1.1.1.1:53"] = f"noreply:{type(e).__name__}"
    finally:
        s.close()
    for name in ("capture-proxy", "example.com"):
        try:
            res[f"dns_{name}"] = "resolved:" + socket.getaddrinfo(name, 443)[0][4][0]
        except OSError as e:
            res[f"dns_{name}"] = f"failed:{type(e).__name__}"
    # Check 15: CONNECT without credentials.
    try:
        s = socket.create_connection(("capture-proxy", 3128), 5)
        s.sendall(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
        s.settimeout(5)
        res["bare_connect_status"] = s.recv(256).split(b"\r\n")[0].decode("latin1")
        s.close()
    except OSError as e:
        res["bare_connect_status"] = f"error:{type(e).__name__}"
    return res


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["browser", "net"])
    ap.add_argument("--capture-id")
    a = ap.parse_args()
    out = browser_mode(a.capture_id) if a.mode == "browser" else net_mode()
    print("SPIKE_JSON=" + json.dumps(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
