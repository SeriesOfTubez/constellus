"""Pre-commit hook: block a commit if it introduces any value from the local
denylists (scripts/denylist.py, written by scripts/refresh_target_denylist.py):
real Target domains, IPs and CIDRs, and real company names and CIKs from the
dev entity graph (added 2026-10-01). Runs at two stages, wired separately in
.pre-commit-config.yaml, each passing an explicit --stage flag so this script
never has to guess which one fired:

  --stage pre-commit  — checks added lines in the staged diff (code, docs)
  --stage commit-msg  — checks the commit message file (title + body),
                         whose path pre-commit appends as the final arg

Fails CLOSED if a denylist snapshot is missing (forces one-time setup)
but only WARNS if it looks stale, rather than blocking every commit when
someone simply forgot to refresh it after adding a target — the snapshot
existing at all is the load-bearing part; staleness just narrows the window.

The Claude Code PreToolUse hook (scripts/check_outbound_text.py) applies the
same lists to issue and PR text, which no git hook ever sees.
"""

import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import denylist  # noqa: E402


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
    # a mangled character cannot hide a denylisted Target value, because every
    # Target entry is ASCII, so replacement can only ever affect bytes that
    # were never part of a match. (A company name CAN carry non-ASCII letters;
    # a replaced byte inside one can hide that one match, which is the price
    # of never dying on a diff.)
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


def main() -> None:
    if len(sys.argv) < 3 or sys.argv[1] != "--stage" or sys.argv[2] not in ("pre-commit", "commit-msg"):
        print("check_target_domains: usage: check_target_domains.py --stage pre-commit|commit-msg [msg-file]", file=sys.stderr)
        sys.exit(2)
    stage = sys.argv[2]

    try:
        dl = denylist.load()
    except denylist.DenylistMissing as exc:
        print(f"check_target_domains: {exc}", file=sys.stderr)
        sys.exit(1)
    for warning in dl.warnings:
        print(f"check_target_domains: WARNING — {warning}", file=sys.stderr)

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

    matches = dl.find(text)
    if matches:
        print(f"\nBLOCKED — {source_desc} contain{'s' if source_desc == 'commit message' else ''} real data from the dev DB:", file=sys.stderr)
        for m in matches:
            print(f"  - {m}", file=sys.stderr)
        print(
            "\nEach is a live Target (domain/IP/CIDR) or a real company name/CIK "
            "from the dev entity graph — real data, not example data. If this is "
            "intentional (e.g. writing the actual product code that legitimately "
            "handles this value), use `git commit --no-verify` deliberately. "
            "Otherwise replace it with a fictional placeholder "
            "(RFC 5737 IPs, synthetic names like 'Example Holdings A', or classic "
            "fake companies like fabrikam.com/contoso.com/northwind.com).",
            file=sys.stderr,
        )
        sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()
