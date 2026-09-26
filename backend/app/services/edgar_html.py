"""app.services.edgar_html — stdlib-only HTML parsing for SEC EDGAR
documents (planning#213, L4 slice 2).

Two independent jobs, both built on the SAME low-level cell/row collector
(`_RowCollector`, an `html.parser.HTMLParser` subclass — the spec forbids
a new dependency, so no `lxml`/`BeautifulSoup`):

  1. **The filing index table** (`parse_index_table`) — locates the
     `-index.htm` documents table (identified by a header row containing a
     `Type` cell) and returns each data row as a dict keyed by its header
     column names (`Seq`, `Description`, `Document`, `Type`, `Size` in a
     real SEC index). `app.services.edgar_ingest` uses this to find the
     EX-21 exhibit **by its `Type` cell, never by filename** (a filer can
     name the file anything).
  2. **The EX-21 exhibit table** (`parse_ex21_rows`) — returns every
     non-empty-cell row across the document (dropping empty cells and
     empty rows per the spec), or `None` if the document contains no
     `<tr>` at all (a plain `<p>`/`<div>`/`<pre>` list — the
     `ex21_unparsed` signal; this module deliberately does not attempt to
     guess at paragraph parsing).

A third job, `render_text_lines` + `find_business_combinations_section`, is
a stdlib port of the research method's `extract_bc.js`: render an
arbitrary 10-K document (including iXBRL, whose `ix:*` tags are just tags
to an `HTMLParser` — their text is kept, nothing special-cased) to a flat
list of stripped, non-empty lines, then locate the Business Combinations /
Acquisitions footnote by **taking the LAST heading match** — the FIRST is
almost always the table of contents (planning#213's decisions comment).

## Cell text normalisation, one rule everywhere in this module

`html.unescape` happens for free: `HTMLParser(convert_charrefs=True)` (the
default) hands `handle_data` already-decoded text, so `&amp;`/`&#160;`
never reach this module as literal markup. Every whitespace run — spaces,
tabs, newlines, and NBSP (`\\xa0`, which `str.split()` does NOT treat as
whitespace on its own) — is collapsed to one space and the result is
stripped, via `_collapse_ws`. Nothing in this module reaches out to the
network or any other `app.services` module.
"""

from __future__ import annotations

import re
from html.parser import HTMLParser

# ── low-level cell/row collection, shared by both table jobs ────────────────


def _collapse_ws(s: str) -> str:
    # Replace NBSP with an ordinary space FIRST — str.split() with no
    # argument splits on ASCII/Unicode whitespace runs, but \xa0 alone is
    # not treated as a separator by every Python version the same way as a
    # plain space is guaranteed to be, so this makes the collapse explicit
    # rather than relying on that.
    return " ".join(s.replace("\xa0", " ").split())


class _RowCollector(HTMLParser):
    """Collects every `<tr>` (grouped by its enclosing `<table>`, with a
    nested table's rows folded into its parent's) as a list of cell-text
    lists. A `<tr>` with no enclosing `<table>` at all (malformed markup)
    is still collected, into a synthetic trailing "table" — the two real
    consumers (`parse_index_table`, `parse_ex21_rows`) only care that SOME
    row was seen, not that the markup was well-formed.
    """

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.tables: list[list[list[str]]] = []
        self.saw_any_tr: bool = False
        self._table_stack: list[list[list[str]]] = []
        self._orphan_rows: list[list[str]] = []
        self._current_row: list[str] | None = None
        self._in_cell = False
        self._cell_chunks: list[str] = []

    def handle_starttag(self, tag: str, attrs) -> None:
        if tag == "table":
            self._table_stack.append([])
        elif tag == "tr":
            self.saw_any_tr = True
            self._current_row = []
        elif tag in ("td", "th"):
            self._in_cell = True
            self._cell_chunks = []

    def handle_startendtag(self, tag: str, attrs) -> None:
        # Self-closing spellings (`<tr/>`, `<td/>`) never appear in real
        # SEC markup, but handling them the same as the open-tag case costs
        # nothing and avoids a silent no-op on odd input.
        self.handle_starttag(tag, attrs)
        self.handle_endtag(tag)

    def handle_endtag(self, tag: str) -> None:
        if tag in ("td", "th") and self._in_cell:
            text = _collapse_ws("".join(self._cell_chunks))
            if self._current_row is not None:
                self._current_row.append(text)
            self._in_cell = False
            self._cell_chunks = []
        elif tag == "tr" and self._current_row is not None:
            target = self._table_stack[-1] if self._table_stack else self._orphan_rows
            target.append(self._current_row)
            self._current_row = None
        elif tag == "table" and self._table_stack:
            finished = self._table_stack.pop()
            if self._table_stack:
                self._table_stack[-1].extend(finished)
            else:
                self.tables.append(finished)

    def handle_data(self, data: str) -> None:
        if self._in_cell:
            self._cell_chunks.append(data)

    def close(self) -> None:
        super().close()
        if self._orphan_rows:
            self.tables.append(self._orphan_rows)


def parse_index_table(html: str) -> list[dict[str, str]] | None:
    """Returns the first table whose header row contains a `Type` cell, as
    a list of `{header_name: cell_text}` dicts (one per data row, header
    row excluded) — or `None` if no such table exists. A row shorter than
    the header is padded with `""` for the missing trailing columns rather
    than raising, since a real index page's `Size` column is sometimes
    blank for a directory-only entry."""
    collector = _RowCollector()
    collector.feed(html)
    collector.close()
    for table in collector.tables:
        if not table:
            continue
        header = [h.strip() for h in table[0]]
        if "Type" not in header:
            continue
        rows: list[dict[str, str]] = []
        for row in table[1:]:
            if not row:
                continue
            rows.append({col: (row[i] if i < len(row) else "") for i, col in enumerate(header)})
        return rows
    return None


def parse_ex21_rows(html: str) -> list[list[str]] | None:
    """Returns every row (as a list of non-empty cell strings) across every
    `<tr>` in the document, dropping empty cells and rows left empty by
    that drop — or `None` if the document contains NO `<tr>` at all (the
    `ex21_unparsed` signal for a paragraph-style EX-21)."""
    collector = _RowCollector()
    collector.feed(html)
    collector.close()
    if not collector.saw_any_tr:
        return None
    rows: list[list[str]] = []
    for table in collector.tables:
        for row in table:
            cells = [c for c in row if c]
            if cells:
                rows.append(cells)
    return rows


# ── EX-21 heading-row predicate (spec §4, ONE documented rule) ──────────────

_HEADING_FIRST_CELL_RE = re.compile(
    r"^(name( of (subsidiary|entity|company))?|subsidiar(y|ies)( name)?|entity( name)?|legal name)$",
    re.IGNORECASE,
)
_HEADING_SECOND_CELL_RE = re.compile(r"^(jurisdiction|state|country)\b", re.IGNORECASE)


def is_heading_row(cells: list[str]) -> bool:
    """True when `cells` is an EX-21 table heading/label row rather than a
    real subsidiary row. Three independent sufficient conditions:

      1. exactly one cell, and it ends with `:` (a section label like
         "Subsidiaries of the Registrant:")
      2. the FIRST cell matches a name-column header vocabulary
         (case-insensitive)
      3. there is a second cell, and it matches a jurisdiction-column
         header vocabulary (case-insensitive)

    Does NOT check "is this row the filer's own current name" — that
    comparison needs the filer's name, which this module never has; the
    caller (`app.services.edgar_ingest`) does that comparison itself,
    separately, by exact string equality."""
    if len(cells) == 1 and cells[0].endswith(":"):
        return True
    if cells and _HEADING_FIRST_CELL_RE.match(cells[0].strip()):
        return True
    if len(cells) >= 2 and _HEADING_SECOND_CELL_RE.match(cells[1].strip()):
        return True
    return False


# ── text rendering (a stdlib port of the research method's extract_bc.js) ──

_SKIP_TAGS = frozenset({"script", "style"})
_BREAK_TAGS = frozenset({"p", "div", "tr", "li", "h1", "h2", "h3", "h4", "h5", "h6", "table", "br"})


class _TextRenderer(HTMLParser):
    """Renders a document to a flat list of stripped, non-empty lines.
    `<script>`/`<style>` content is dropped entirely; a line break is
    emitted at the CLOSE of `p, div, tr, li, h1-h6, table` and at `br`
    (open or self-closing); everything else's text simply accumulates onto
    the current line, which is exactly what makes table cells "space-
    joined" — `<td>`/`<th>` are not break tags, so a row's cells run
    together until the enclosing `</tr>` flushes the line. iXBRL `ix:*`
    tags match none of `_SKIP_TAGS`/`_BREAK_TAGS` by construction (a tag
    name comparison, not a namespace-aware one), so they fall through as
    ordinary unknown tags — exactly "just tags; their text is kept"."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.lines: list[str] = []
        self._current: list[str] = []
        self._skip_depth = 0

    def handle_starttag(self, tag: str, attrs) -> None:
        if tag in _SKIP_TAGS:
            self._skip_depth += 1
            return
        if tag == "br":
            self._flush()

    def handle_startendtag(self, tag: str, attrs) -> None:
        if tag == "br":
            self._flush()

    def handle_endtag(self, tag: str) -> None:
        if tag in _SKIP_TAGS:
            self._skip_depth = max(0, self._skip_depth - 1)
            return
        if tag in _BREAK_TAGS:
            self._flush()

    def handle_data(self, data: str) -> None:
        if self._skip_depth:
            return
        self._current.append(data)

    def _flush(self) -> None:
        text = _collapse_ws(" ".join(self._current)).strip()
        if text:
            self.lines.append(text)
        self._current = []

    def close(self) -> None:
        self._flush()
        super().close()


def render_text_lines(html: str) -> list[str]:
    renderer = _TextRenderer()
    renderer.feed(html)
    renderer.close()
    return renderer.lines


# ── Business Combinations / Acquisitions heading match (spec §5) ───────────

# Vocabulary widened from the research script's "Business Combinations" to
# also match "Acquisition(s)" (Jason, 2026-09-25 decisions comment: filers
# title this note either way).
_HEADING_LINE_RE = re.compile(
    r"^(note\s*\d+\s*[-–—.:]?\s*|\d+\s*[.:)-]\s*)?(business combinations?|acquisitions?)$",
    re.IGNORECASE,
)

# The "next note" end-of-section signal: either another numbered/"Note N"
# heading, or the research script's all-caps heading rule.
_NEXT_HEADING_RE = re.compile(r"^(note\s*\d+|\d+\s*[.:)])\s*[-–—.:]?\s*[A-Za-z]", re.IGNORECASE)
_ALL_CAPS_HEADING_RE = re.compile(r"^[A-Z][A-Z ,&'\-]{5,60}$")

_MIN_BODY_LINES = 10
_MAX_SECTION_LINES = 600


def find_business_combinations_section(lines: list[str]) -> tuple[int, int, str, int] | None:
    """Returns `(start_line, end_line, heading, heading_match_count)` for
    the Business Combinations / Acquisitions footnote, or `None` if no
    heading line matches at all (the `sections_not_found` signal).

    Takes the **LAST** matching line — the research method's own rule,
    because the FIRST match in a 10-K is essentially always its table of
    contents, not the footnote body. `end_line` is EXCLUSIVE: the first
    line at least `_MIN_BODY_LINES` after `start_line` that looks like the
    start of the NEXT note (by either heading shape), capped at
    `start_line + _MAX_SECTION_LINES` lines so a heading match with no
    discernible "next note" (e.g. the last footnote in the document) still
    produces a bounded section rather than swallowing the rest of the
    filing.

    ⚠ Known limitation, carried into `entity_filing_sections`' own
    docstring: the LAST match can land on a LATER, unrelated mention (a
    subsequent-events note also titled "Acquisitions"). `heading_match_
    count` is returned specifically so a reader can see that ambiguity —
    this function extracts a CANDIDATE section, it does not verify one.
    """
    matches = [i for i, line in enumerate(lines) if _HEADING_LINE_RE.match(line.strip())]
    if not matches:
        return None

    start = matches[-1]
    heading = lines[start].strip()
    match_count = len(matches)

    limit = min(len(lines), start + _MAX_SECTION_LINES)
    end = limit
    for i in range(start + _MIN_BODY_LINES, limit):
        candidate = lines[i].strip()
        if _NEXT_HEADING_RE.match(candidate) or _ALL_CAPS_HEADING_RE.match(candidate):
            end = i
            break

    return start, end, heading, match_count
