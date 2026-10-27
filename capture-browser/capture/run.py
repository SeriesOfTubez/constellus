"""capture-browser runner (planning#280 S5b-1).

Loads ONE URL in a fresh headless Chromium whose only network path is the
capture-proxy, and writes `result.json`. There is deliberately nothing here
beyond one top-level navigation: no crawling, no link following, no form
submission, no DOM extraction beyond `document.title`.

`launch_browser` / `new_context` are the single source of truth for the launch
configuration. The egress spike (spike/spike.py) imports them so it tests the
REAL flags, not a copy.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import sys
from pathlib import Path
from urllib.parse import urlsplit

from playwright.sync_api import Browser, BrowserContext, Playwright, sync_playwright

NAV_TIMEOUT_MS = 30_000
IDLE_WAIT_MS = 3_000

# Chromium flags on top of Playwright's defaults. Every one removes a source of
# traffic that would not be driven by the page we asked for.
CHROMIUM_ARGS = [
    # No Chromium-initiated background requests (Safe Browsing, field trials, ...).
    "--disable-background-networking",
    # No component-updater fetches.
    "--disable-component-update",
    # No Chrome Sync.
    "--disable-sync",
    # No <a ping> hyperlink-auditing beacons.
    "--no-pings",
    # No Domain Reliability Monitor uploads.
    "--disable-domain-reliability",
    # WebRTC may only use UDP that goes through a proxy -> effectively none.
    "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
    # No DNS-over-HTTPS: name resolution must not bypass the proxy. A later
    # --disable-features REPLACES Playwright's own list, so that list (as of
    # 1.63.0; re-check on a Playwright bump) is repeated here with DnsOverHttps added.
    "--disable-features=DnsOverHttps,AvoidUnnecessaryBeforeUnloadCheckSync,"
    "DestroyProfileOnBrowserClose,DialMediaRouteProvider,GlobalMediaControls,"
    "HttpsUpgrades,LensOverlay,MediaRouter,PaintHolding,"
    "ThirdPartyStoragePartitioning,BlockOriginHeaderModificationOnRedirect,"
    "Translate,AutoDeElevate,OptimizationHints,msForceBrowserSignIn,"
    "msEdgeUpdateLaunchServicesPreferredVersion",
    # Chromium implicitly bypasses the proxy for loopback; force it through so
    # 127.0.0.1/localhost requests reach the proxy and are denied there.
    "--proxy-bypass-list=<-loopback>",
]


def require_env() -> tuple[str, str]:
    """Fail closed: no proxy configuration, no browser."""
    url = os.environ.get("CAPTURE_PROXY_URL", "").strip()
    token = os.environ.get("CAPTURE_PROXY_TOKEN", "").strip()
    if not url or not token:
        raise SystemExit("CAPTURE_PROXY_URL and CAPTURE_PROXY_TOKEN are required")
    return url, token


def launch_browser(p: Playwright, capture_id: str, proxy_url: str, token: str) -> Browser:
    """Fresh Chromium per run; temp profile (Playwright's, under /tmp -> tmpfs)."""
    return p.chromium.launch(
        headless=True,
        chromium_sandbox=True,  # Chromium's own sandbox ON; needs capture-browser/seccomp.json
        args=CHROMIUM_ARGS,
        proxy={
            "server": proxy_url,
            "username": capture_id,
            "password": token,
            "bypass": "",
        },
    )


def stock_user_agent(browser: Browser) -> str:
    """The browser's own UA with the headless marker removed (not hard-coded)."""
    ctx = browser.new_context()
    try:
        page = ctx.new_page()  # about:blank: no network
        ua = page.evaluate("navigator.userAgent")
    finally:
        ctx.close()
    return ua.replace("HeadlessChrome", "Chrome")


def new_context(browser: Browser) -> BrowserContext:
    return browser.new_context(
        service_workers="block",
        accept_downloads=False,
        java_script_enabled=True,
        viewport={"width": 1366, "height": 768},
        ignore_https_errors=False,
        user_agent=stock_user_agent(browser),
    )


def _name(rdn_seq) -> str:
    return rdn_seq.rfc4514_string()


def decode_cert(der: bytes) -> dict:
    from cryptography import x509

    cert = x509.load_der_x509_certificate(der)
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        san_dns = san.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        san_dns = []
    return {
        "subject": _name(cert.subject),
        "issuer": _name(cert.issuer),
        "not_before": cert.not_valid_before_utc.isoformat(),
        "not_after": cert.not_valid_after_utc.isoformat(),
        "san_dns": san_dns,
        "sha256": hashlib.sha256(der).hexdigest(),
    }


def get_cert(cdp, final_url: str) -> dict | None:
    """Certificate of the connection the page already made (no second connection).

    `cdp` must have had `Network.enable` called BEFORE the navigation: Chromium
    only keeps the certificate for responses seen while the domain was enabled
    (a session opened afterwards gets an empty `tableNames`).
    """
    parts = urlsplit(final_url)
    if parts.scheme != "https" or not parts.hostname:
        return None
    host = f"[{parts.hostname}]" if ":" in parts.hostname else parts.hostname
    origin = f"https://{host}" + (f":{parts.port}" if parts.port else "")
    try:
        res = cdp.send("Network.getCertificate", {"origin": origin})
        tables = res.get("tableNames") or []
        if not tables:
            return None
        return decode_cert(base64.b64decode(tables[0]))
    except Exception:  # noqa: BLE001 - cert is best-effort evidence, never fatal
        return None


def capture(p: Playwright, capture_id: str, url: str, proxy_url: str, token: str) -> dict:
    browser = launch_browser(p, capture_id, proxy_url, token)
    result: dict = {
        "capture_id": capture_id,
        "requested_url": url,
        "final_url": None,
        "status": None,
        "redirect_chain": [],
        "title": None,
        "requests": [],
        "cert": None,
        "error": None,
    }
    try:
        context = new_context(browser)
        page = context.new_page()
        cdp = context.new_cdp_session(page)
        cdp.send("Network.enable")
        seen: list = []
        page.on("request", lambda r: seen.append(r))
        try:
            resp = page.goto(url, wait_until="load", timeout=NAV_TIMEOUT_MS)
            if resp is not None:
                result["status"] = resp.status
                chain = []
                req = resp.request.redirected_from
                while req is not None:
                    r = req.response()
                    chain.append({"url": req.url, "status": r.status if r else None})
                    req = req.redirected_from
                result["redirect_chain"] = list(reversed(chain))
        except Exception as exc:  # noqa: BLE001 - recorded, not raised
            result["error"] = str(exc)
            # No response (e.g. a certificate error after a redirect): rebuild the
            # chain from the navigation requests Playwright did see.
            navs = [r for r in seen if r.is_navigation_request()]
            if navs:
                chain = []
                req = navs[-1].redirected_from
                while req is not None:
                    r = req.response()
                    chain.append({"url": req.url, "status": r.status if r else None})
                    req = req.redirected_from
                result["redirect_chain"] = list(reversed(chain))
        try:
            page.wait_for_load_state("networkidle", timeout=IDLE_WAIT_MS)
        except Exception:  # noqa: BLE001 - idle wait is best-effort
            pass
        result["final_url"] = page.url
        if result["error"] is None:
            result["title"] = page.title()
            result["cert"] = get_cert(cdp, page.url)
        result["requests"] = [
            {
                "url": r.url,
                "resource_type": r.resource_type,
                "failure": r.failure,
                "is_navigation": r.is_navigation_request(),
            }
            for r in seen
        ]
    finally:
        browser.close()
    return result


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="capture.run")
    ap.add_argument("--capture-id", required=True)
    ap.add_argument("--url", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    proxy_url, token = require_env()
    with sync_playwright() as p:
        result = capture(p, args.capture_id, args.url, proxy_url, token)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "result.json").write_text(json.dumps(result, indent=2))
    return 0 if result["error"] is None else 1


if __name__ == "__main__":
    sys.exit(main())
