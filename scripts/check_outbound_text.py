"""Claude Code PreToolUse hook: block a shell command that would PUBLISH text
containing real data — a `gh` issue/PR/release write, a `gh api` call, or a
`git commit`/`git tag` — when that text matches the local denylists
(scripts/denylist.py).

Reads the hook payload (JSON) on stdin. Exit 0 = allow; exit 2 = block, with
the reason on stderr (Claude Code feeds it back to the model).

What is checked: the command text itself (which includes `-b`/`-m`
arguments and heredoc bodies) plus every body file it names with
`-F`/`--body-file`/`--file`/`--input` or a `field=@file` argument.

Fails CLOSED when:
  - a denylist snapshot is missing (run refresh_target_denylist.py), or
  - a named body file cannot be read — e.g. its path is a shell variable
    (`-F $S/body.md`) the hook cannot expand. Pass a literal path instead.
Any other command is allowed untouched.

The git pre-commit/commit-msg hooks (check_target_domains.py) cover the
diff and the final message too; this hook exists for what git hooks never
see — issue and PR text — and to stop a bad commit message before it is
typed into git at all.
"""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import denylist  # noqa: E402

PUBLISHING = re.compile(
    r"\bgh\s+(?:issue|pr)\s+(?:create|edit|comment|review|close|reopen)\b"
    r"|\bgh\s+release\s+(?:create|edit)\b"
    r"|\bgh\s+api\b"
    r"|\bgit\s+(?:-C\s+\S+\s+)?(?:commit|tag)\b"
)
BODY_FILE = re.compile(
    r"""(?:^|\s)(?:-F|--body-file|--file|--input)(?:\s+|=)("([^"]*)"|'([^']*)'|(\S+))"""
    r"""|=@("([^"]*)"|'([^']*)'|(\S+))"""
)


def _to_native(path: str) -> str:
    # Git Bash style /c/foo -> C:/foo
    m = re.match(r"^/([a-zA-Z])/(.*)$", path)
    return f"{m.group(1).upper()}:/{m.group(2)}" if m else path


def _body_files(command: str) -> list[str]:
    paths = []
    for m in BODY_FILE.finditer(command):
        groups = m.groups()
        quoted = next((g for g in (groups[1], groups[2], groups[5], groups[6]) if g), None)
        # An unquoted path runs up to whitespace, so a following `;`, `&&`,
        # `|` or `)` sticks to it (`-F body.md; echo done`): strip those.
        bare = next((g for g in (groups[3], groups[7]) if g), None)
        value = quoted or (bare.rstrip(";&|)") if bare else None)
        if value and value != "-":
            paths.append(value)
    return paths


def _block(message: str) -> None:
    print(f"BLOCKED by check_outbound_text.py (the data rule): {message}", file=sys.stderr)
    sys.exit(2)


def main() -> None:
    try:
        payload = json.load(sys.stdin)
    except ValueError:
        sys.exit(0)  # not a payload we understand; never block on our own parse error
    command = (payload.get("tool_input") or {}).get("command") or ""
    if not PUBLISHING.search(command):
        sys.exit(0)

    try:
        dl = denylist.load()
    except denylist.DenylistMissing as exc:
        _block(str(exc))

    texts = [("the command", command)]
    cwd = payload.get("cwd") or os.getcwd()
    for raw in _body_files(command):
        if "$" in raw or "`" in raw:
            _block(f"body file {raw!r} uses a shell variable the hook cannot expand; pass a literal path.")
        path = Path(_to_native(raw))
        if not path.is_absolute():
            path = Path(cwd) / path
        try:
            texts.append((f"body file {raw}", path.read_text(encoding="utf-8", errors="replace")))
        except OSError as exc:
            _block(f"cannot read body file {raw!r} to check it ({exc.strerror}); pass a literal, readable path.")

    for label, text in texts:
        hits = dl.find(text)
        if hits:
            _block(
                f"{label} contains real data from the dev DB: {', '.join(hits)}. "
                "Describe the shape, refer to entities by DB id, or use synthetic names."
            )
    for w in dl.warnings:
        print(f"check_outbound_text: WARNING — {w}", file=sys.stderr)
    sys.exit(0)


if __name__ == "__main__":
    main()
