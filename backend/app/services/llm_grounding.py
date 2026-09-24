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
