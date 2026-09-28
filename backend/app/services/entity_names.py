"""Company-name normalisation shared by the entity-graph writers.

Two different comparisons live here, and they are deliberately different:

- `dedup_key` (planning#235): the LLM acquisition reader's variant-tolerant
  key. It drops a trailing defined term (`X, Inc. ("X")`) and ONE legal
  suffix, so the model's `X Labs` and the filing's `X Labs, Inc.` collide.
  Right for "have we already proposed this deal?".
- `self_name_key` (planning#241): the EX-21 filter's "is this row the filer
  itself?" key. It ignores case, whitespace and punctuation but KEEPS the
  legal suffix, because a real subsidiary can carry the parent's name with
  a different suffix (a `Foo Corp` filer with a `Foo, Inc.` operating
  subsidiary, observed live). A suffix-stripped key would drop it.

Neither key is ever used to match across filers.
"""

from __future__ import annotations

import re
import unicodedata

MIN_NAME_LENGTH = 3


def _fold(text: str) -> str:
    return " ".join(unicodedata.normalize("NFKC", text).casefold().split())


# One-for-one, so an index into the translated string is an index into the
# original: patterns match on the translation, names are sliced from the
# original (a stored name keeps the filing's own characters).
_QUOTES = str.maketrans({
    "“": '"', "”": '"', "„": '"', "«": '"', "»": '"', "‘": "'", "’": "'",
})
# A defined term in quotes: `("Examplecorp")`, `(the "Seller")`.
_TERM = r"""\(\s*(?:the\s+)?["']([^"'()]{1,80})["']\s*\)"""
_TRAILING_TERM_RE = re.compile(r"\s*,?\s*" + _TERM + r"\s*$", re.IGNORECASE)
# ONE trailing legal-form suffix. "Company" is deliberately absent: it is
# part of real names ("Own Data Company").
_LEGAL_SUFFIX_RE = re.compile(
    r",?\s+(?:inc|incorporated|llc|l\.l\.c|ltd|limited|corp|corporation|co|plc|s\.a|s\.a\.s|s\.r\.l|s\.p\.a"
    r"|gmbh|ag|n\.v|b\.v|l\.p|lp|llp|pty\.?\s+ltd|a/s|oy|ab|k\.k)\.?$",
    re.IGNORECASE,
)
# Unnamed groups and generic defined terms, matched against the WHOLE folded
# name: "several companies", "13 companies", "the Company", "the Merger".
_GENERIC_NAME_RE = re.compile(
    r"^(?:the\s+)?"
    r"(?:(?:several|various|certain|other|multiple|numerous|some|additional|a\s+few|a\s+number\s+of|two|three"
    r"|four|five|six|seven|eight|nine|ten|eleven|twelve|\d+)\s+)?"
    r"(?:(?:other|additional|small|smaller|private|privately[- ]held|acquired|target)\s+)*"
    r"(?:company|companies|business|businesses|entity|entities|acquisition|acquisitions|acquiree|acquirees"
    r"|target|targets|merger|mergers|transaction|transactions|deal|deals|seller|sellers)$"
)


def split_defined_term(name: str) -> tuple[str, str | None]:
    """`X, Inc. ("X")` → (`X, Inc.`, `X`); no trailing term → (name, None).
    A trailing comma is dropped either way."""
    s = name.strip()
    m = _TRAILING_TERM_RE.search(s.translate(_QUOTES))
    if not m:
        return s.rstrip(" ,"), None
    return s[: m.start()].rstrip(" ,"), m.group(1).strip()


def strip_legal_suffix(name: str) -> str | None:
    """`X, Inc.` → `X`; None when there is no suffix or too little is left."""
    m = _LEGAL_SUFFIX_RE.search(name)
    if not m:
        return None
    stripped = name[: m.start()].rstrip(" ,")
    return stripped if len(stripped) >= MIN_NAME_LENGTH else None


def is_generic(name: str) -> bool:
    return bool(_GENERIC_NAME_RE.match(_fold(name.translate(_QUOTES))))


def dedup_key(name: str) -> str:
    base, _ = split_defined_term(name)
    base = strip_legal_suffix(base) or base
    return _fold(base.translate(_QUOTES)).strip(" .,")


def self_name_key(name: str) -> str:
    """Letters and digits only, folded: `Foo, Inc.` == `FOO INC`, but
    `Foo Corp` != `Foo, Inc.`. "" for a name with no letters or digits."""
    return "".join(ch for ch in _fold(name) if ch.isalnum())
