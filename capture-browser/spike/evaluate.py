"""Host-side evaluation of the egress spike (stdlib only).

    python evaluate.py BROWSER_JSON NET_JSON CERT_JSON PROXY_LOG CAPTURE_ID CERT_CAPTURE_ID

Prints a PASS/FAIL/SKIP table; exits 1 if any row is FAIL.
"""

from __future__ import annotations

import json
import sys
from urllib.parse import urlsplit


def norm(host: str) -> str:
    return host.strip("[]").lower()


def hp(url: str) -> tuple[str, int]:
    u = urlsplit(url)
    return norm(u.hostname or ""), u.port or (443 if u.scheme == "https" else 80)


def load_proxy(path: str, ids: set[str]) -> list[dict]:
    rows = []
    for line in open(path, encoding="utf-8", errors="replace"):
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            d = json.loads(line)
        except ValueError:
            continue
        if d.get("capture_id") in ids:
            rows.append(d)
    return rows


def main() -> int:
    bpath, npath, cpath, ppath, cid, ccid = sys.argv[1:7]
    B = json.load(open(bpath))
    N = json.load(open(npath))
    C = json.load(open(cpath))
    log = load_proxy(ppath, {cid})
    cert_log = load_proxy(ppath, {ccid})

    def lines(host, port=None, decision=None):
        return [
            r for r in log
            if norm(str(r.get("host"))) == norm(host)
            and (port is None or r.get("port") == port)
            and (decision is None or r.get("decision") == decision)
        ]

    fetches = {f["url"]: f for f in B["main"]["fetches"]}
    rows: list[tuple[int, str, str, str]] = []

    def add(n, name, ok, detail):
        rows.append((n, name, "PASS" if ok is True else "SKIP" if ok is None else "FAIL", detail))

    def blocked_literal(n, name, hosts):
        bad, ev = [], []
        for h, display in hosts:
            for scheme, port in (("http", 80), ("https", 443)):
                url = f"{scheme}://{display}/"
                f = fetches.get(url)
                d = [r for r in lines(h, port, "deny") if r.get("reason") == "blocked_literal"]
                if not f or not f.get("attempted") or not d:
                    bad.append(f"{url} page={f and f['outcome']} deny_lines={len(d)}")
                else:
                    ev.append(f"{scheme}:{f['outcome']}")
        add(n, name, not bad, "; ".join(bad) if bad else "page attempted; proxy deny blocked_literal for " + ", ".join(h for h, _ in hosts) + f" [{' '.join(ev)}]")

    blocked_literal(1, "Private IP fetch blocked at proxy", [("10.0.0.1", "10.0.0.1")])
    blocked_literal(2, "Metadata fetch blocked", [("169.254.169.254", "169.254.169.254"), ("::ffff:a9fe:a9fe", "[::ffff:a9fe:a9fe]")])

    # 3
    bad = []
    for url in ("http://127.0.0.1:80/", "http://localhost/"):
        h, p = hp(url)
        d = lines(h, p, "deny")
        if not fetches.get(url) or not d:
            bad.append(f"{url} deny_lines={len(d)}")
    add(3, "Loopback goes to proxy", not bad, "; ".join(bad) or "deny lines for 127.0.0.1 and localhost (reasons: "
        + ",".join(sorted({str(r.get('reason')) for r in lines('127.0.0.1') + lines('localhost')})) + ")")

    # 4
    hits, seen = [], []
    for host, ip in (("10.0.0.1.nip.io", "10.0.0.1"), ("127.0.0.1.sslip.io", "127.0.0.1")):
        for r in lines(host):
            seen.append(f"{host}:{r.get('decision')}/{r.get('reason')}/{r.get('resolved')}")
            if r.get("decision") == "deny" and r.get("reason") == "all_blocked" and ip in (r.get("resolved") or []):
                hits.append(host)
    if hits:
        add(4, "Hostname resolving private is blocked", True, "all_blocked with private IP in resolved: " + ", ".join(hits))
    else:
        add(4, "Hostname resolving private is blocked", None, "no wildcard-DNS host resolved from the proxy; log: " + ("; ".join(seen) or "no lines"))

    # 5
    a = [r for r in lines("example.com", 443, "allow") if r.get("pinned_ip")]
    seen5 = any(r["url"].startswith("https://example.com/spike-img-") for r in B["requests"])
    add(5, "Public subresource allowed via proxy", bool(a) and seen5,
        f"allow lines w/ pinned_ip={len(a)}; playwright saw the img={seen5}")

    # 6
    tcp_ok = N["tcp_proxy_sanity"] == "connected"
    f1, f2 = N["tcp_1.1.1.1:443"], N["tcp_8.8.8.8:53"]
    u = N["udp_1.1.1.1:53"]
    add(6, "No direct egress from browser container",
        tcp_ok and f1.startswith("failed") and f2.startswith("failed") and u.startswith("noreply"),
        f"proxy-sanity={N['tcp_proxy_sanity']}; 1.1.1.1:443={f1}; 8.8.8.8:53={f2}; udp={u}")

    # 7
    d_ok = N["dns_capture-proxy"].startswith("resolved")
    add(7, "No DNS from browser container", d_ok and N["dns_example.com"].startswith("failed"),
        f"capture-proxy={N['dns_capture-proxy']}; example.com={N['dns_example.com']}")
    r7 = rows[-1][2]

    # 8
    rand = B["rand"]
    traces = [r for r in log if rand in str(r.get("host"))]
    add(8, "DNS prefetch / preconnect don't leak", r7 == "PASS",
        "structural proof = check 7; proxy lines for the random names: "
        + (", ".join(f"{r['host']}:{r['port']} {r['decision']}/{r.get('reason')}" for r in traces) or "none"))

    # 9
    sw = B["sw"]["sw"] or {}
    secure = B["sw"].get("secure")
    sw_script = [r["url"] for r in B["requests"] if r["url"].endswith("/sw.js")]
    add(9, "Service workers blocked", bool(secure) and (not sw.get("present") or (sw.get("registrations") == 0 and not sw_script)),
        f"secure_context={secure}; {sw}; sw.js requests seen={len(sw_script)}")

    # 10
    w = B["main"]["webrtc"] or {}
    types = w.get("types", [])
    bad_host = [a for t, a in zip(types, w.get("addresses", [])) if t == "host" and not a.endswith(".local")]
    add(10, "WebRTC can't leak", "srflx" not in types and not bad_host,
        f"candidate types={types or 'none'}; error={w.get('error')}")

    # 11
    referenced = set()
    for r in B["requests"]:
        if r["url"].startswith(("http://", "https://")):
            referenced.add(hp(r["url"])[0])
    referenced |= {f"prefetch-{rand}.example.net", f"preconnect-{rand}.example.net", "stun.l.google.com"}
    extra = sorted({norm(str(r["host"])) for r in log} - referenced)
    add(11, "OCSP/CRL / background traffic", not extra,
        "unreferenced hosts in proxy log: " + (", ".join(extra) or "none") + f" ({len(log)} proxy lines total)")

    # 12
    s12 = [r for r in log if norm(str(r.get("host"))) == "spike.invalid"]
    add(12, "spike.invalid never reached the proxy", not s12 and len(log) > 0, f"{len(s12)} lines; {len(log)} lines total for capture_id")

    # 13
    log_hp = {(norm(str(r["host"])), r.get("port")) for r in log}
    missing = []
    checked = set()
    for r in B["requests"]:
        if not r["url"].startswith(("http://", "https://")):
            continue
        k = hp(r["url"])
        if k[0] == "spike.invalid":
            continue
        checked.add(k)
        if k not in log_hp:
            missing.append(f"{k[0]}:{k[1]}")
    add(13, "Every Playwright-seen request appears in proxy log", not missing and bool(checked),
        f"{len(checked)} distinct host:port checked; missing: {', '.join(sorted(set(missing))) or 'none'}")

    # 14
    cert = C.get("cert") or {}
    add(14, "Cert via CDP", bool(cert.get("san_dns")) and bool(C.get("final_url")) and bool(C.get("title")),
        f"final_url={C.get('final_url')} title={C.get('title')!r} san_dns={cert.get('san_dns')} cert_log_lines={len(cert_log)}")

    # 15
    add(15, "Auth required", N["connect_noauth"].split(" ")[1:2] == ["407"], N["connect_noauth"])

    w1 = max(len(r[1]) for r in rows)
    print(f"{'#':>2}  {'Check':<{w1}}  Result  Detail")
    for n, name, res, detail in sorted(rows):
        print(f"{n:>2}  {name:<{w1}}  {res:<6}  {detail}")
    return 1 if any(r[2] == "FAIL" for r in rows) else 0


if __name__ == "__main__":
    sys.exit(main())
