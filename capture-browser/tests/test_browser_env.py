"""Chromium gets an allowlisted environment, never the worker's secrets."""

from capture.browser_env import BROWSER_ENV_ALLOWLIST, browser_env


def test_only_allowlisted_keys_pass():
    environ = {
        "CAPTURE_S3_SECRET_KEY": "s", "CAPTURE_S3_ACCESS_KEY": "a", "CAPTURE_PROXY_KEY": "p",
        "AWS_SECRET_ACCESS_KEY": "w", "FOO_TOKEN": "t",
        "PATH": "/usr/bin", "HOME": "/home/x", "LANG": "C.UTF-8",
    }
    assert browser_env(environ) == {"PATH": "/usr/bin", "HOME": "/home/x", "LANG": "C.UTF-8"}


def test_absent_allowlisted_keys_stay_absent():
    out = browser_env({"PATH": "/usr/bin"})
    assert out == {"PATH": "/usr/bin"}
    assert "TZ" in BROWSER_ENV_ALLOWLIST and "TZ" not in out
