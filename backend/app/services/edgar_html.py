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
Acquisitions footnote by **preferring a `Note N`/`N.`-prefixed match, LAST
among those; otherwise the LAST bare match** (planning#220, defect 3,
2026-09-26 — refined from the original "always take the LAST heading
match" rule, which a live run showed can pick a bare table-cell column
header instead of the actual note; see that function's own docstring).

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
# A per-PAGE running header (e.g. "PART II", "ITEM 8") — all-caps shaped
# like a real heading, but it repeats on every page of the filing and must
# never end a section on its own (planning#220 defect 4, the live run:
# `PART II` recurred inside a note's body and truncated the stored section
# at the next page break instead of the next note). Case-sensitive: a
# lowercase "part ii" inside ordinary prose is not this filer's running
# header convention and should not be specially excluded.
_RUNNING_HEADER_RE = re.compile(r"^(PART\s+[IVX]+|ITEM\s+\d+[A-Z]?)\.?$")

_MIN_BODY_LINES = 10
_MAX_SECTION_LINES = 600


def find_business_combinations_section(lines: list[str]) -> tuple[int, int, str, int] | None:
    """Returns `(start_line, end_line, heading, heading_match_count)` for
    the Business Combinations / Acquisitions footnote, or `None` if no
    heading line matches at all (the `sections_not_found` signal).

    ## Start: prefer a numbered match, LAST among those; otherwise LAST bare
       (planning#220 defect 3, decided by Jason 2026-09-26)

    A plain "take the LAST match" rule (the research method's original
    rule, kept for a document with no numbered match at all) picks a bare
    table-cell column header over the real note heading on a live filing:
    a goodwill roll-forward table's own "Acquisitions" column header,
    rendered as its own line by this module's text renderer, sorts AFTER
    the real `NOTE n — BUSINESS COMBINATIONS` heading it follows. A
    `Note N` / `N.`-prefixed match is essentially always the actual note
    heading (a table cell is never itself numbered that way), so when ANY
    such match exists, this function takes the LAST *numbered* one —
    still LAST, not FIRST, because a later numbered note can itself be
    titled "Acquisitions" (a subsequent-events note, say) and the FIRST
    match in a 10-K is still essentially always the table of contents.
    Only when NO match carries a `Note N`/`N.` prefix does this fall back
    to the original LAST-bare-match rule.

    ## End: follows the shape of the start (planning#220 defect 4)

    A NUMBERED start ends ONLY at the next `_NEXT_HEADING_RE` line (another
    numbered/"Note N" heading) — the all-caps signal is ignored entirely
    for a numbered start, because a numbered note's body can legitimately
    contain an all-caps line (a page's running header, e.g. `PART II` or a
    financial-statement caption like `CONSOLIDATED FINANCIAL STATEMENTS`)
    that is not the start of the NEXT note. A BARE start still uses both
    signals (there is no numbered shape to prefer), but a `_RUNNING_HEADER_
    RE` line (`PART [IVX]+` / `ITEM n[A-Z]?`) never counts as the all-caps
    end signal — a filer that repeats `PART II` on every page must not
    truncate a bare-titled section at the next page break instead of the
    next real heading. `end_line` is EXCLUSIVE, first checked at least
    `_MIN_BODY_LINES` after `start_line`, capped at `start_line +
    _MAX_SECTION_LINES` lines so a heading match with no discernible "next
    note" (e.g. the last footnote in the document) still produces a
    bounded section rather than swallowing the rest of the filing.

    `heading_match_count` is `len(matches)` — EVERY line matching the
    heading vocabulary, numbered or bare, anywhere in the document (used
    for `start` selection or not). It is NOT scoped to the stored section.

    ⚠ Known limitations, carried into `entity_filing_sections`' own
    docstring:
      - The LAST-numbered (or LAST-bare, when no numbered match exists)
        rule can still land on a LATER, unrelated mention — e.g. a
        numbered subsequent-events note ALSO titled "Acquisitions" still
        wins over the real Business Combinations note by virtue of being
        LAST among numbered matches.
      - `_NEXT_HEADING_RE`'s `\\d+\\s*[.:)]` shape can match an ordinary
        enumerated body line (e.g. `2. The Company acquired...`), which
        would end a NUMBERED section early — this function extracts a
        CANDIDATE section, it does not verify one, and `heading_match_
        count` (plus a low body-line count relative to `_MAX_SECTION_
        LINES`) is the signal a later reader has to notice this.
    """
    match_pairs = [(i, m) for i, line in enumerate(lines) if (m := _HEADING_LINE_RE.match(line.strip()))]
    if not match_pairs:
        return None

    matches = [i for i, _m in match_pairs]
    numbered = [i for i, m in match_pairs if m.group(1)]
    start = numbered[-1] if numbered else matches[-1]
    start_is_numbered = bool(numbered)
    heading = lines[start].strip()
    match_count = len(matches)

    limit = min(len(lines), start + _MAX_SECTION_LINES)
    end = limit
    for i in range(start + _MIN_BODY_LINES, limit):
        candidate = lines[i].strip()
        if _NEXT_HEADING_RE.match(candidate):
            end = i
            break
        if not start_is_numbered and _ALL_CAPS_HEADING_RE.match(candidate) and not _RUNNING_HEADER_RE.match(candidate):
            end = i
            break

    return start, end, heading, match_count


# ── the filer's own website, as the 10-K states it (planning#216) ──────────
#
# A 10-K almost always says where the filer publishes its SEC reports ("We
# make available free of charge on our website at www.example.com …"),
# usually in Item 1's "Available Information". That sentence is the filer
# naming its OWN domain in a document it signed, so it is evidence, not a
# guess — unlike SEC's own `website` / `investorWebsite` submissions fields,
# which a live probe (2026-09-26) found empty on 50 of 50 filers.
#
# Anchor first, domain second: a domain is only taken from a short window
# AFTER an anchor phrase that says the site is the filer's. A bare domain
# anywhere else in a 10-K (a customer, a vendor, a regulator, a filing
# agent) is never a candidate. This function never sees the filer's name,
# and nothing here maps a name to a domain.

_WEBSITE_ANCHOR_RE = re.compile(
    r"\b(?:our|the\s+company[’']s|its)\s+"
    r"(?:(?:corporate|investor(?:\s+relations)?|principal|primary)\s+)?"
    r"(?:web\s?site|internet\s+(?:web\s?)?site|internet\s+address|home\s?page)\b",
    re.IGNORECASE,
)
_WEBSITE_WINDOW = 160
# `(?:https?://)?` then one or more labels then an alphabetic TLD. The
# lookahead stops a sentence-final period, a path, or closing punctuation
# from being read as part of the host.
_WEBSITE_DOMAIN_RE = re.compile(
    r"(?:https?://)?((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24})"
    r"(?=$|[/\s,;:)\]\"'”’]|\.(?:$|[\s\"'”’)]))",
    re.IGNORECASE,
)
_WEBSITE_EXCLUDED_SUFFIXES = (".gov",)
_QUOTE_MAX = 500


def _sentence_around(line: str, start: int, end: int) -> str:
    """The sentence of `line` containing `[start, end)`, capped at
    `_QUOTE_MAX` characters around that span. A sentence boundary is a
    `.`/`!`/`?` followed by whitespace — a domain's own dots are never
    followed by whitespace, so they never split it."""
    left = max(line.rfind(". ", 0, start), line.rfind("! ", 0, start), line.rfind("? ", 0, start))
    s = 0 if left < 0 else left + 2
    rights = [i for i in (line.find(". ", end), line.find("! ", end), line.find("? ", end)) if i >= 0]
    e = min(rights) + 1 if rights else len(line)
    if e - s > _QUOTE_MAX:
        s = max(s, start - (_QUOTE_MAX - (end - start)) // 2)
        e = min(e, s + _QUOTE_MAX)
    return line[s:e].strip()


def find_website_mentions(lines: list[str]) -> list[tuple[str, str]]:
    """Returns `(domain, quote)` pairs, one per distinct domain, in first-
    mention order. `domain` is lowercased with a leading `www.` removed;
    `quote` is the sentence it came from and always contains `domain`
    case-insensitively (migration 0064's `ck_candidate_domains_quote_
    contains_domain` depends on that). Only the FIRST domain after each
    anchor is taken — "our website at www.a.com and the SEC's website at
    www.sec.gov" must not yield the second."""
    found: dict[str, str] = {}
    for line in lines:
        for anchor in _WEBSITE_ANCHOR_RE.finditer(line):
            window_end = min(len(line), anchor.end() + _WEBSITE_WINDOW)
            m = _WEBSITE_DOMAIN_RE.search(line, anchor.end(), window_end)
            if m is None:
                continue
            host = m.group(1).lower()
            if host.startswith("www."):
                host = host[4:]
            if "." not in host or host.endswith(_WEBSITE_EXCLUDED_SUFFIXES) or host in found:
                continue
            quote = _sentence_around(line, anchor.start(), m.end())
            if host not in quote.lower():
                continue
            found[host] = quote
    return list(found.items())
