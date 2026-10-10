"""app.services.llm_grounding — groundedness checking for structured LLM output
(planning#140 slice 1).

Pure and dependency-light on purpose: no DB import, no HTTP import (see
`test_egress_gate_guard.py`'s `_EGRESS` sweep — this module deliberately
stays absent from it). `app.services.llm_connector` is the only caller.

## R2 — the structurer is a transformer, never a source

A schema opts individual fields into grounding by typing them
`Grounded[str]`, `Grounded[int]`, etc. — nested models and lists of models
are walked, so a field buried inside `subsidiaries[2].name` is checked the
same as a top-level one. `check_grounding` returns the DOTTED PATHS of
every field that fails; `llm_connector` treats ANY failing path as the
whole structured attempt failing (`ungrounded` ledger status) — never a
partially-accepted result. The span an LLM's claim is checked against is
provided by the caller (`source_text`, or on the tier-2 split-structuring
path, the tier-1 raw content being re-structured); this module never fetches
one itself.

## The rules, per `Grounded` field

  - `value is None` -> passes. Nothing was claimed, so there is nothing to
    ground (`quote` is ignored in this case, even if set).
  - `value` not None and `quote` empty/None -> FAIL. A claimed value with no
    supporting quote at all.
  - Both `quote` and the span are normalised (Unicode NFKC, casefold,
    whitespace runs collapsed to one space, stripped) before comparing —
    this exists so trivial re-flowing (a line break mid-quote, a smart
    quote vs. straight one, case) doesn't fail a quote that a human would
    accept as a faithful copy. The normalised quote must be a SUBSTRING of
    the normalised span, or FAIL.
  - When `value` is itself a `str`: the normalised value must ALSO be a
    substring of the normalised QUOTE (not the span) — this is the check
    that catches a real quote paired with an invented value (the model
    copies a real sentence verbatim into `quote` but writes something the
    sentence doesn't actually say into `value`).
  - Non-str values (int, float, bool, date, ...): only the quote-in-span
    rule applies. KNOWN GAP, documented rather than silently accepted: a
    number or date is never checked against its own quote's wording — a
    quote that genuinely supports "$4.2M" would pass equally well paired
    with a `value` of 999. Closing this needs type-aware parsing per field
    (a date parser, a number parser with locale/formatting rules) that this
    slice does not build.
"""

from __future__ import annotations

import json
import re
import unicodedata
from typing import Generic, TypeVar

from pydantic import BaseModel

V = TypeVar("V")


class Grounded(BaseModel, Generic[V]):
    """Wraps a single claimed value with the verbatim quote that supports
    it. `value` and `quote` are both optional independently: a field the
    model had nothing to say about is `value=None, quote=None` — never
    forced to invent either."""

    value: V | None
    quote: str | None


def _normalise(text: str) -> str:
    """Unicode NFKC, casefold, collapse all whitespace runs to one space,
    strip. Applied identically to both sides of every comparison below —
    see the module docstring's rules."""
    text = unicodedata.normalize("NFKC", text)
    text = text.casefold()
    return " ".join(text.split())


def check_grounding(instance: BaseModel, span: str) -> list[str]:
    """Walk `instance` (a validated schema instance, possibly containing
    nested models and lists of models) and return the dotted field paths
    (e.g. `"subsidiaries[2].name"`) of every `Grounded` field that fails
    against `span` — see the module docstring for the per-field rules. An
    empty list means every claim in `instance` is grounded (or claimed
    nothing at all)."""
    normalised_span = _normalise(span)
    failures: list[str] = []
    _walk(instance, "", normalised_span, failures)
    return failures


def _walk(value: object, path: str, normalised_span: str, failures: list[str]) -> None:
    if isinstance(value, Grounded):
        _check_grounded_field(value, path, normalised_span, failures)
        return
    if isinstance(value, BaseModel):
        for field_name in type(value).model_fields:
            child = getattr(value, field_name)
            child_path = f"{path}.{field_name}" if path else field_name
            _walk(child, child_path, normalised_span, failures)
        return
    if isinstance(value, (list, tuple)):
        for i, item in enumerate(value):
            _walk(item, f"{path}[{i}]", normalised_span, failures)
        return
    # A plain scalar (or None) outside a Grounded wrapper — nothing to
    # check; only fields explicitly typed Grounded[...] opt into grounding.


def _check_grounded_field(field: Grounded, path: str, normalised_span: str, failures: list[str]) -> None:
    if field.value is None:
        return  # nothing claimed — quote is ignored even if set
    if not field.quote:
        failures.append(path)
        return

    normalised_quote = _normalise(field.quote)
    if not normalised_quote or normalised_quote not in normalised_span:
        failures.append(path)
        return

    if isinstance(field.value, str):
        normalised_value = _normalise(field.value)
        if normalised_value not in normalised_quote:
            failures.append(path)


# ── path grounding (planning#226) ────────────────────────────────────────────
#
# A statement that cites a FIELD of a structured input, rather than quoting a
# span of text: `{statement, source_field, value}`, where `source_field` is a
# path into the exact JSON the caller sent (`asset.ports[0].banner_snippet`)
# and `value` is what the model says it read there. `check_path_grounding`
# returns None when the citation holds, else the reason it does not:
#
#   - `path_invalid`     the path does not parse (grammar below).
#   - `path_not_found`   a key or index along it does not exist in `data`.
#   - `path_not_scalar`  it resolves to an object, a list or null. Citing a
#                        container would let any value pass ("it's somewhere
#                        under `asset`"), so only a leaf can be cited.
#   - `value_empty`      nothing was claimed to be read there.
#   - `value_not_at_path` the leaf does not hold `value`. For a string leaf,
#                        the normalised value must be a substring of the
#                        normalised leaf AND either be the whole leaf or at
#                        least `MIN_PATH_VALUE_CHARS` long (so "1" cannot be
#                        "found" in any banner). For a number or boolean
#                        leaf, the normalised value must EQUAL the leaf's
#                        JSON text (`9.8`, `true`).
#
# Path grammar: dot-separated segments, each an identifier optionally
# followed by one or more `[n]` list indexes: `related[2].title`,
# `asset.resolves_to[0].ports[1].port`. No quoting, no wildcards.
#
# KNOWN GAP, the same one `check_grounding` documents for value-vs-quote:
# this proves the model read `value` at `source_field`. It does not prove
# the prose of `statement` says what `value` supports.

MIN_PATH_VALUE_CHARS = 3

_SEGMENT = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)((?:\[\d+\])*)")
_INDEX = re.compile(r"\[(\d+)\]")


def _parse_path(path: str) -> list[str | int] | None:
    if not path or path != path.strip():
        return None
    steps: list[str | int] = []
    for segment in path.split("."):
        m = _SEGMENT.fullmatch(segment)
        if m is None:
            return None
        steps.append(m.group(1))
        steps.extend(int(i) for i in _INDEX.findall(m.group(2)))
    return steps


_MISSING = object()


def resolve_path(data: object, path: str) -> object:
    """The value at `path` in `data`, or `_MISSING`. Raises ValueError when
    the path does not parse."""
    steps = _parse_path(path)
    if steps is None:
        raise ValueError(f"invalid path {path!r}")
    node = data
    for step in steps:
        if isinstance(step, str):
            if not isinstance(node, dict) or step not in node:
                return _MISSING
            node = node[step]
        else:
            if not isinstance(node, list) or step >= len(node):
                return _MISSING
            node = node[step]
    return node


def check_path_grounding(data: object, source_field: str, value: str | None) -> str | None:
    """None when `value` is at `source_field` in `data`; else the reason
    (see the section comment above)."""
    try:
        node = resolve_path(data, source_field)
    except ValueError:
        return "path_invalid"
    if node is _MISSING:
        return "path_not_found"
    if node is None or isinstance(node, (dict, list)):
        return "path_not_scalar"
    claimed = _normalise(value or "")
    if not claimed:
        return "value_empty"
    if isinstance(node, str):
        leaf = _normalise(node)
        if claimed not in leaf:
            return "value_not_at_path"
        if claimed != leaf and len(claimed) < MIN_PATH_VALUE_CHARS:
            return "value_not_at_path"
        return None
    if claimed != _normalise(json.dumps(node)):
        return "value_not_at_path"
    return None
