"""The environment Chromium gets (importable without Playwright, so CI can test it)."""

from __future__ import annotations

import os
from collections.abc import Mapping

# Allowlist, not denylist: nothing secret reaches Chromium even if a new env var is added later.
BROWSER_ENV_ALLOWLIST = frozenset({
    "PATH", "HOME", "LANG", "LC_ALL", "LC_CTYPE", "TZ", "TMPDIR", "XDG_RUNTIME_DIR",
    "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "FONTCONFIG_PATH", "FONTCONFIG_FILE",
})


def browser_env(environ: Mapping[str, str] = os.environ) -> dict[str, str]:
    """Only the allowlisted keys that are present. Playwright's `env` REPLACES the browser's."""
    return {k: v for k, v in environ.items() if k in BROWSER_ENV_ALLOWLIST}
