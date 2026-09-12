"""Pre-commit hook: block a commit if it introduces any value from the live
Target denylist (scripts/refresh_target_denylist.py) — real domains, IPs, or
CIDRs this dev environment currently has under management. Runs at two
stages, wired separately in .pre-commit-config.yaml, each passing an
explicit --stage flag so this script never has to guess which one fired:

  --stage pre-commit  — checks added lines in the staged diff (code, docs)
  --stage commit-msg  — checks the commit message file (title + body),
                         whose path pre-commit appends as the final arg

Fails CLOSED if the denylist snapshot is missing (forces one-time setup)
but only WARNS if it looks stale, rather than blocking every commit when
someone simply forgot to refresh it after adding a target — the snapshot
existing at all is the load-bearing part; staleness just narrows the window.
"""

import subprocess
import sys
import time
from pathlib import Path

DENYLIST_PATH = Path(__file__).resolve().parent.parent / ".git" / "target-denylist.txt"
STALE_AFTER_SECONDS = 24 * 3600


def load_denylist() -> list[str]:
    if not DENYLIST_PATH.exists():
        print(
            "check_target_domains: no denylist snapshot found.\n"
            "  Run: python scripts/refresh_target_denylist.py\n"
            "  (requires the dev DB reachable at DATABASE_URL / localhost:5432)",
            file=sys.stderr,
        )
        sys.exit(1)

    age = time.time() - DENYLIST_PATH.stat().st_mtime
    if age > STALE_AFTER_SECONDS:
        hours = int(age // 3600)
        print(
            f"check_target_domains: WARNING — denylist snapshot is {hours}h old. "
            "Targets added since the last refresh won't be caught. "
            "Run scripts/refresh_target_denylist.py to update it.",
            file=sys.stderr,
        )

    return [line.strip() for line in DENYLIST_PATH.read_text(encoding="utf-8").splitlines() if line.strip()]


def added_diff_text() -> str:
    # `encoding` is explicit and `errors` is lenient ON PURPOSE. Bare
    # `text=True` decodes with the platform's preferred encoding — cp1252 on
    # Windows — and the staged diff is UTF-8. Any byte landing in one of
    # cp1252's undefined slots (0x81, 0x8D, 0x8F, 0x90, 0x9D) then raises
    # inside subprocess, `result.stdout` comes back None, and this guard dies
    # with an AttributeError. A variation selector (U+FE0F, the second half
    # of an emoji like ⚠️) is enough to do it.
    #
    # It failed CLOSED, which is the right direction — but a security control
    # that blocks ordinary commits is one a maintainer eventually reaches for
    # `--no-verify` to get past, and this is the control that exists because
    # real customer data reached the repo once already. `errors="replace"`
    # keeps it scanning even when a diff carries genuinely undecodable bytes:
    # a mangled character cannot hide a denylisted value, because every
    # denylist entry is ASCII, so replacement can only ever affect bytes that
    # were never part of a match.
    result = subprocess.run(
        ["git", "diff", "--cached", "--unified=0", "--no-color"],
        capture_output=True, check=True,
        encoding="utf-8", errors="replace",
    )
    added_lines = [
        line[1:] for line in result.stdout.splitlines()
        if line.startswith("+") and not line.startswith("+++")
    ]
    return "\n".join(added_lines)


def find_matches(haystack: str, denylist: list[str]) -> list[str]:
    haystack_lower = haystack.lower()
    return [value for value in denylist if value.lower() in haystack_lower]


def main() -> None:
    if len(sys.argv) < 3 or sys.argv[1] != "--stage" or sys.argv[2] not in ("pre-commit", "commit-msg"):
        print("check_target_domains: usage: check_target_domains.py --stage pre-commit|commit-msg [msg-file]", file=sys.stderr)
        sys.exit(2)
    stage = sys.argv[2]

    denylist = load_denylist()
    if not denylist:
        sys.exit(0)  # empty target list — nothing to check against

    if stage == "commit-msg":
        if len(sys.argv) < 4:
            print("check_target_domains: commit-msg stage requires the message file path", file=sys.stderr)
            sys.exit(2)
        # Same reasoning as added_diff_text(): a commit message is UTF-8 and
        # may legitimately carry characters that are not decodable elsewhere.
        # The guard must scan it, not die on it.
        text = Path(sys.argv[3]).read_text(encoding="utf-8", errors="replace")
        source_desc = "commit message"
    else:
        text = added_diff_text()
        source_desc = "staged changes"

    matches = find_matches(text, denylist)
    if matches:
        print(f"\nBLOCKED — {source_desc} reference{'s' if len(matches) > 1 else ''} a live Target value:", file=sys.stderr)
        for m in sorted(set(matches)):
            print(f"  - {m}", file=sys.stderr)
        print(
            "\nThis is a domain/IP/CIDR currently configured as a Target in the dev "
            "environment — real infrastructure, not example data. If this is "
            "intentional (e.g. writing the actual product code that legitimately "
            "handles this value), use `git commit --no-verify` deliberately. "
            "Otherwise replace it with a fictional placeholder "
            "(RFC 5737 IPs, .example/.test domains, or classic fake company names "
            "like fabrikam.com/contoso.com).",
            file=sys.stderr,
        )
        sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()
