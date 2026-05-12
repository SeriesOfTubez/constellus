"""
Maps Nuclei template tags to normalized finding categories.
First match in order wins.
"""

import re

_RULES: list[tuple[str, list[str]]] = [
    ("cve",                  ["cve"]),
    ("app_security",         ["sqli", "xss", "rce", "ssrf", "lfi", "xxe", "ssti",
                              "injection", "traversal", "idor", "csrf",
                              "deserialization", "upload", "open-redirect"]),
    ("exposed_asset",        ["panel", "unauth", "login", "debug", "backup",
                              "exposure", "exposure-files"]),
    ("information_disclosure",["info-disclosure", "leakage", "logs", "token",
                               "api-key", "disclosure", "secret", "leak"]),
    ("configuration",        ["misconfig", "misconfiguration", "default-login",
                              "default-password", "default-credential"]),
    ("network_security",     ["network", "firewall", "ssl", "tls", "dns", "port"]),
    ("outdated_software",    ["eol", "outdated", "version", "end-of-life"]),
]

_CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)


def categorize(tags: list[str]) -> str:
    tag_set = {t.lower() for t in tags}
    for category, keywords in _RULES:
        if tag_set & set(keywords):
            return category
    return "other"


def extract_cve_id(tags: list[str], template_id: str = "") -> str | None:
    for tag in tags:
        m = _CVE_RE.match(tag)
        if m:
            return m.group().upper()
    m = _CVE_RE.search(template_id)
    if m:
        return m.group().upper()
    return None
