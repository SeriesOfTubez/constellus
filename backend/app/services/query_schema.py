"""The attack-surface query language: published schema + validator (planning#227).

One JSON query object is shared by Explore's builder (#53), the chat assistant (#228,
which emits it through `llm_connector.structured()`) and the backend, which
validates it here and compiles it in `query_compiler`. **Nothing in the object
is ever interpolated into SQL**: field and relation names are looked up in the
registry below (an unknown name is an error, not a column), and every value is
bound as a parameter.

Shape (version 1)::

    {
      "version": 1,
      "entity": "asset" | "finding" | "entity" | "relation" | "domain",
      "where": <node>,                      # optional
      "sort": [{"field": "...", "dir": "asc" | "desc"}],
      "limit": 100,
      "include": {"suppressed": false, "third_party": false,
                  "excluded_verifications": false}
    }

    <node> := {"all": [<node>, ...]} | {"any": [<node>, ...]} | {"not": <node>}
            | {"exists": {"relation": "finding" | "port", "where": <node>}}
            | {"field": "<name>", "op": "<op>", "value": <value>}

Relationships (slice 1): a finding query may filter on its asset's fields
directly (many-to-one). An asset query reaches its findings and its open ports
only through `exists` blocks, so "any port where service = nginx AND number =
443" means one port entry, not two different ones. Ports live in
`asset_state.open_ports` JSONB (Jason, 2026-10-10: asset filters for now, not
first-class entities). Tables only; graph output comes with #53.

Validation runs in two passes, both before any SQL exists: pydantic for the
structure (unknown keys, wrong JSON types), then `validate()` against the field
registry (unknown field, operator not allowed for the type, value of the wrong
type, field used outside its relation). Every error carries a path such as
`where.all[2].field`.

The caps are constants by decision (Jason, 2026-10-10); they are published in
`published_schema()` so the UI and the LLM see the same limits the validator
enforces.
"""

from __future__ import annotations

import math
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Annotated, Any, Literal, Union

from pydantic import (
    BaseModel,
    ConfigDict,
    Discriminator,
    Field as PydField,
    StrictBool,
    StrictInt,
    StrictStr,
    Tag,
    WithJsonSchema,
    ValidationError,
)

from app.models.asset import AssetType
from app.models.scope_candidate import CANDIDATE_STATUSES
from app.models.entity_relation import EVENT_DATE_PRECISIONS, RELATION_STATUSES, RELATION_TYPES
from app.models.finding import FindingState, Severity
from app.models.org_entity import RELATIONSHIPS
from app.services.claims_query import SURFACE_VALUES
from app.services.risk_scorer import BANDS

QUERY_VERSION = 1

# ── caps (constants by decision; published) ─────────────────────────────────
DEFAULT_LIMIT = 100
MAX_LIMIT = 500
MAX_DEPTH = 6            # nesting of all/any/not/exists below `where`
MAX_PREDICATES = 40      # field predicates in the whole object
MAX_LIST_ITEMS = 100     # values in an `in` / `not_in` list; children of all/any
MAX_STRING = 256         # any string value
MAX_SORT = 3
STATEMENT_TIMEOUT_MS = 10_000  # per query, transaction-local
COUNT_CAP = 10_000       # count mode: an exact count up to here, then "10,000+" (planning#228)


# ── field registry ──────────────────────────────────────────────────────────

@dataclass(frozen=True)
class FieldSpec:
    name: str            # "<namespace>.<field>", e.g. "finding.severity"
    type: str            # one of OPERATORS_BY_TYPE
    description: str
    enum: tuple[str, ...] | None = None
    sortable: bool = True

    @property
    def namespace(self) -> str:
        return self.name.split(".", 1)[0]


OPERATORS_BY_TYPE: dict[str, tuple[str, ...]] = {
    "string": ("eq", "ne", "in", "not_in", "contains", "starts_with", "is_null"),
    "enum": ("eq", "ne", "in", "not_in", "is_null"),
    "integer": ("eq", "ne", "gt", "gte", "lt", "lte", "in", "is_null"),
    "number": ("eq", "ne", "gt", "gte", "lt", "lte", "is_null"),
    "boolean": ("eq", "is_null"),
    "datetime": ("gt", "gte", "lt", "lte", "is_null"),
    "uuid": ("eq", "ne", "in"),
    "string_list": ("has", "is_empty"),
}

# Fields whose operators are narrower than their type's. `asset.engagement_id`
# is a many-valued membership (an asset can be linked to targets of several
# engagements), so `ne` would be ambiguous: "any other engagement" or "not this one".
# The three `*.family_of` fields are the same kind of membership (planning#230
# slice 2): the corporate family of an engagement's subject entity. `parent_relation`
# is a membership-style special case (a confirmed parent edge points into the entity).
FIELD_OPERATORS_OVERRIDE: dict[str, tuple[str, ...]] = {
    "asset.engagement_id": ("eq", "in"),
    "entity.family_of": ("eq", "in"),
    "entity.parent_relation": ("eq", "in"),
    "relation.family_of": ("eq", "in"),
    "domain.family_of": ("eq", "in"),
}


def operators_for(spec: "FieldSpec") -> tuple[str, ...]:
    return FIELD_OPERATORS_OVERRIDE.get(spec.name, OPERATORS_BY_TYPE[spec.type])


OPERATORS: dict[str, str] = {
    "eq": "equals the value",
    "ne": "does not equal the value (rows where the field is empty are not matched)",
    "in": "equals one of the values (a list)",
    "not_in": "equals none of the values (a list)",
    "gt": "greater than", "gte": "greater than or equal",
    "lt": "less than", "lte": "less than or equal",
    "contains": "contains the value as a case-insensitive substring",
    "starts_with": "starts with the value, case-insensitive",
    "is_null": "value true: the field is empty; value false: it is set",
    "has": "the list contains this exact value",
    "is_empty": "value true: the list is empty or missing; value false: it has entries",
}

_SEVERITIES = tuple(s.value for s in Severity)
_FINDING_STATES = tuple(s.value for s in FindingState)
_VERIFICATIONS = ("unverified", "confirmed_ours", "rejected_shared_infra", "ownership_unverifiable")

FIELDS: tuple[FieldSpec, ...] = (
    # asset — assets_canonical, plus asset_state for surface/hosting
    FieldSpec("asset.id", "uuid", "Asset id.", sortable=False),
    FieldSpec("asset.engagement_id", "uuid",
              "Engagement the asset belongs to: it is linked to a target of that engagement. "
              "An asset can belong to several.", sortable=False),
    FieldSpec("asset.type", "enum", "Asset type.", tuple(t.value for t in AssetType)),
    FieldSpec("asset.value", "string", "Hostname, IP address or other identity value."),
    FieldSpec("asset.parent_value", "string", "Parent value (e.g. the apex a hostname belongs to)."),
    FieldSpec("asset.record_type", "string", "DNS record type (A, AAAA, CNAME, ...) for dns_record assets."),
    FieldSpec("asset.content", "string", "DNS record content (what the record points to)."),
    FieldSpec("asset.first_seen_at", "datetime", "When the asset was first observed."),
    FieldSpec("asset.last_seen_at", "datetime", "When the asset was last observed."),
    FieldSpec("asset.suppressed", "boolean", "The asset is suppressed right now (an expired ignore is not)."),
    FieldSpec("asset.tags", "string_list", "Tags on the asset.", sortable=False),
    FieldSpec("asset.surface", "enum",
              "Ownership estate: proven_ours, claimed_ours, not_ours (third-party), or unknown.",
              tuple(sorted(SURFACE_VALUES))),
    FieldSpec("asset.hosting_provider", "string", "Hosting provider from the tenancy classifier."),
    FieldSpec("asset.is_datacenter", "boolean", "Hosted in a known datacenter/cloud range."),
    # finding — findings_canonical
    FieldSpec("finding.id", "uuid", "Finding id.", sortable=False),
    FieldSpec("finding.title", "string", "Finding title."),
    FieldSpec("finding.severity", "enum", "Severity.", _SEVERITIES),
    FieldSpec("finding.state", "enum", "Triage state.", _FINDING_STATES),
    FieldSpec("finding.type", "string", "Finding type (e.g. cve, exposure, dangling_dns)."),
    FieldSpec("finding.source", "string", "Producing source (e.g. nuclei, shodan)."),
    FieldSpec("finding.category", "string", "Finding category."),
    FieldSpec("finding.cve_id", "string", "CVE identifier, when the finding is a CVE."),
    FieldSpec("finding.cwe", "string", "CWE identifier."),
    FieldSpec("finding.cvss_score", "number", "CVSS base score (0-10)."),
    FieldSpec("finding.epss_score", "number", "EPSS probability (0-1)."),
    FieldSpec("finding.epss_percentile", "number", "EPSS percentile (0-1)."),
    FieldSpec("finding.kev", "boolean", "Listed in CISA KEV."),
    FieldSpec("finding.has_exploit", "boolean", "A public exploit is known."),
    FieldSpec("finding.ransomware_use", "boolean", "Known ransomware use."),
    FieldSpec("finding.risk_score", "integer", "Constellus Risk Score (0-100)."),
    FieldSpec("finding.risk_band", "enum", "Risk band derived from the risk score.", tuple(BANDS)),
    FieldSpec("finding.verification", "enum",
              "Ownership verification. rejected_shared_infra and ownership_unverifiable are "
              "hidden unless include.excluded_verifications is set.", _VERIFICATIONS),
    FieldSpec("finding.ssvc_exploitation", "enum", "SSVC exploitation.", ("none", "poc", "active")),
    FieldSpec("finding.ssvc_automatable", "boolean", "SSVC automatable."),
    FieldSpec("finding.ssvc_technical_impact", "enum", "SSVC technical impact.", ("total", "partial")),
    FieldSpec("finding.first_seen_at", "datetime", "When the finding was first observed."),
    FieldSpec("finding.last_seen_at", "datetime", "When the finding was last observed."),
    FieldSpec("finding.resolved_at", "datetime", "When the finding was resolved."),
    FieldSpec("finding.tags", "string_list", "Tags on the finding.", sortable=False),
    # port — one entry of asset_state.open_ports (JSONB); only inside exists:port
    FieldSpec("port.number", "integer", "Port number.", sortable=False),
    FieldSpec("port.protocol", "string", "Transport protocol (tcp/udp).", sortable=False),
    FieldSpec("port.service", "string", "Detected service name (e.g. http, ssh).", sortable=False),
    FieldSpec("port.version", "string", "Detected service version string.", sortable=False),
    FieldSpec("port.banner", "string", "Banner snippet.", sortable=False),
    FieldSpec("port.cpe", "string_list", "CPE strings detected on the port.", sortable=False),
    FieldSpec("port.jarm", "string", "JARM TLS fingerprint.", sortable=False),
    FieldSpec("port.cert_subject_cn", "string", "TLS certificate subject CN.", sortable=False),
    FieldSpec("port.cert_issuer_cn", "string", "TLS certificate issuer CN.", sortable=False),
    FieldSpec("port.cert_issuer_org", "string", "TLS certificate issuer organisation.", sortable=False),
    FieldSpec("port.cert_sans", "string_list", "TLS certificate subject alternative names.", sortable=False),
    # entity — org_entities (planning#230 slice 2)
    FieldSpec("entity.id", "uuid", "Entity id.", sortable=False),
    FieldSpec("entity.name", "string", "Legal name of the company."),
    FieldSpec("entity.relationship", "enum",
              "What the company is to us: ours or ma_target. Empty when unset.", tuple(sorted(RELATIONSHIPS))),
    FieldSpec("entity.has_cik", "boolean", "The company has an SEC CIK recorded."),
    FieldSpec("entity.created_at", "datetime", "When the entity was created."),
    FieldSpec("entity.family_of", "uuid",
              "Engagement id. The company is in the corporate family of that engagement's subject "
              "(the subject included): reachable down CONFIRMED subsidiary_of / acquired edges only.",
              sortable=False),
    FieldSpec("entity.parent_relation", "enum",
              "A CONFIRMED parent edge of this type points into the company as the child: "
              "subsidiary_of (it is a subsidiary of another company) or acquired (another company acquired it).",
              ("subsidiary_of", "acquired"), sortable=False),
    # relation — entity_relations; one row per source assertion
    FieldSpec("relation.id", "uuid", "Relation record id.", sortable=False),
    FieldSpec("relation.type", "enum", "Relation type.", tuple(sorted(RELATION_TYPES))),
    FieldSpec("relation.status", "enum", "Review status.", tuple(sorted(RELATION_STATUSES))),
    FieldSpec("relation.event_date", "datetime",
              "When the event happened (acquisition date, name change), as UTC midnight of the recorded "
              "date. Read it together with relation.event_date_precision: a year-precision date is "
              "stored as January 1st and means only the year."),
    FieldSpec("relation.event_date_precision", "enum", "How precise event_date is.",
              tuple(sorted(EVENT_DATE_PRECISIONS))),
    FieldSpec("relation.subject_id", "uuid", "Subject entity id.", sortable=False),
    FieldSpec("relation.object_id", "uuid", "Object entity id.", sortable=False),
    FieldSpec("relation.subject_name", "string", "Legal name of the subject entity."),
    FieldSpec("relation.object_name", "string", "Legal name of the object entity."),
    FieldSpec("relation.family_of", "uuid",
              "Engagement id. The subject OR the object is in the corporate family of that "
              "engagement's subject.", sortable=False),
    # domain — scope_candidates of kind 'domain'
    FieldSpec("domain.id", "uuid", "Candidate domain id.", sortable=False),
    FieldSpec("domain.name", "string", "The domain name."),
    FieldSpec("domain.status", "enum",
              "Review status: open (awaiting a decision, or still a lead), claimed (a person put it in scope), "
              "rejected.", tuple(sorted(CANDIDATE_STATUSES))),
    FieldSpec("domain.proposable", "boolean",
              "The candidate clears the propose bar (a Strong signal, or Supporting signals from two "
              "families). An open candidate that does not is a lead, not awaiting review.", sortable=False),
    FieldSpec("domain.root_id", "uuid", "The organization (root company) the candidate belongs to.",
              sortable=False),
    FieldSpec("domain.entity_id", "uuid",
              "Company the domain is attributed to; empty until the candidate is claimed.", sortable=False),
    FieldSpec("domain.entity_name", "string", "Legal name of that company; empty until claimed."),
    FieldSpec("domain.family_of", "uuid",
              "Engagement id. The domain's organization is in the corporate family of that engagement's "
              "subject.", sortable=False),
)

FIELDS_BY_NAME: dict[str, FieldSpec] = {f.name: f for f in FIELDS}

# Which namespaces each root entity reads directly, and which relations it may
# open with `exists`. Inside an exists block only that relation's namespace is
# readable, and exists blocks do not nest (slice 1).
ENTITIES: dict[str, dict[str, Any]] = {
    "asset": {
        "description": "One row per canonical asset.",
        "namespaces": ("asset",),
        "relations": ("finding", "port"),
        "include": ("suppressed", "third_party", "excluded_verifications"),
        "output": ("asset.id", "asset.type", "asset.value", "asset.record_type", "asset.content",
                   "asset.surface", "asset.suppressed", "asset.tags",
                   "asset.first_seen_at", "asset.last_seen_at"),
    },
    "finding": {
        "description": "One row per canonical finding, with its asset.",
        "namespaces": ("finding", "asset"),
        "relations": ("port",),
        "include": ("excluded_verifications",),
        "output": ("finding.id", "finding.title", "finding.severity", "finding.state",
                   "finding.type", "finding.source", "finding.cve_id", "finding.cvss_score",
                   "finding.epss_score", "finding.kev", "finding.risk_score", "finding.risk_band",
                   "finding.verification", "finding.first_seen_at", "finding.last_seen_at",
                   "asset.id", "asset.type", "asset.value"),
    },
    "entity": {
        "description": "One row per company (org entity) in the entity graph.",
        "namespaces": ("entity",),
        "relations": (),
        "include": (),
        "output": ("entity.id", "entity.name", "entity.relationship", "entity.has_cik"),
    },
    "relation": {
        "description": "One row per SOURCE ASSERTION about a relationship between two companies "
                       "(two sources reporting the same acquisition are two rows), with both names.",
        "namespaces": ("relation",),
        "relations": (),
        "include": (),
        "output": ("relation.id", "relation.type", "relation.status", "relation.event_date",
                   "relation.event_date_precision",
                   "relation.subject_id", "relation.subject_name", "relation.object_id",
                   "relation.object_name"),
    },
    "domain": {
        "description": "One row per candidate domain (a domain that signals say may belong to an organization).",
        "namespaces": ("domain",),
        "relations": (),
        "include": (),
        "output": ("domain.id", "domain.name", "domain.status", "domain.proposable", "domain.root_id",
                   "domain.entity_id", "domain.entity_name"),
    },
}

RELATIONS: dict[str, str] = {
    "finding": "Any of the asset's findings matches (excluded verifications obey include).",
    "port": "Any one of the asset's open ports matches all conditions in the block.",
}

INCLUDE_FLAGS: dict[str, str] = {
    "suppressed": "Also return assets that are suppressed right now (hidden by default).",
    "third_party": "Also return third-party context assets (surface not_ours; hidden by default).",
    "excluded_verifications": "Also return findings rejected as shared infrastructure or "
                              "ownership-unverifiable (hidden by default: not proven ours).",
}


# ── structure (pydantic) ────────────────────────────────────────────────────

class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)


_SCALAR_JSON = [{"type": "string", "maxLength": MAX_STRING}, {"type": "number"},
                {"type": "integer"}, {"type": "boolean"}]
# The value's type depends on the field, so it is checked in `validate()`
# (clean, field-aware messages) rather than by a pydantic union, whose errors
# name every union arm. The published JSON Schema still states the shape.
Value = Annotated[Any, WithJsonSchema({"anyOf": [
    *_SCALAR_JSON,
    {"type": "array", "items": {"anyOf": _SCALAR_JSON}, "maxItems": MAX_LIST_ITEMS},
    {"type": "null"},
]})]


class Predicate(_Strict):
    field: Annotated[StrictStr, PydField(max_length=64)]
    op: Literal[tuple(OPERATORS)]  # type: ignore[valid-type]
    value: Value = None


class AllNode(_Strict):
    all: Annotated[list["Node"], PydField(min_length=1, max_length=MAX_LIST_ITEMS)]


class AnyNode(_Strict):
    any: Annotated[list["Node"], PydField(min_length=1, max_length=MAX_LIST_ITEMS)]


class NotNode(_Strict):
    not_: "Node" = PydField(alias="not")


class ExistsBody(_Strict):
    relation: Literal[tuple(RELATIONS)]  # type: ignore[valid-type]
    where: "Node | None" = None


class ExistsNode(_Strict):
    exists: ExistsBody


_NODE_KEYS = ("all", "any", "not", "exists")


def _node_kind(v: Any) -> str | None:
    if isinstance(v, dict):
        for k in _NODE_KEYS:
            if k in v:
                return f"<{k}>"
        return "<predicate>"
    for cls, tag in ((AllNode, "<all>"), (AnyNode, "<any>"), (NotNode, "<not>"),
                     (ExistsNode, "<exists>"), (Predicate, "<predicate>")):
        if isinstance(v, cls):
            return tag
    return None


Node = Annotated[
    Union[
        Annotated[AllNode, Tag("<all>")],
        Annotated[AnyNode, Tag("<any>")],
        Annotated[NotNode, Tag("<not>")],
        Annotated[ExistsNode, Tag("<exists>")],
        Annotated[Predicate, Tag("<predicate>")],
    ],
    Discriminator(_node_kind, custom_error_type="invalid_node",
                  custom_error_message="must be an object: all, any, not, exists, or a field predicate"),
]


class SortKey(_Strict):
    field: Annotated[StrictStr, PydField(max_length=64)]
    dir: Literal["asc", "desc"] = "asc"


class Include(_Strict):
    suppressed: StrictBool = False
    third_party: StrictBool = False
    excluded_verifications: StrictBool = False


class Query(_Strict):
    version: Literal[1] = QUERY_VERSION
    entity: Literal[tuple(ENTITIES)]  # type: ignore[valid-type]
    where: Node | None = None
    sort: Annotated[list[SortKey], PydField(max_length=MAX_SORT)] = []
    limit: Annotated[StrictInt, PydField(ge=1, le=MAX_LIMIT)] = DEFAULT_LIMIT
    include: Include = Include()


for _m in (AllNode, AnyNode, NotNode, ExistsBody, ExistsNode, Query):
    _m.model_rebuild()


# ── errors ──────────────────────────────────────────────────────────────────

class QueryError(Exception):
    """An invalid query object. `errors` is a list of {path, message}."""

    def __init__(self, errors: list[dict[str, str]]):
        self.errors = errors
        super().__init__("; ".join(f"{e['path']}: {e['message']}" for e in errors))


def _format_loc(loc: tuple[Any, ...]) -> str:
    out = ""
    for seg in loc:
        if isinstance(seg, str) and seg.startswith("<"):
            continue  # union tag, not part of the user's path
        if isinstance(seg, int):
            out += f"[{seg}]"
        else:
            out += ("." if out else "") + ("not" if seg == "not_" else str(seg))
    return out or "(query)"


# ── semantic validation ─────────────────────────────────────────────────────

def _type_ok(spec: FieldSpec, v: Any) -> str | None:
    """None if `v` is a valid single value for the field, else the problem."""
    t = spec.type
    if t in ("string", "string_list"):
        if not isinstance(v, str):
            return "expected a string"
        return None if len(v) <= MAX_STRING else f"string must be at most {MAX_STRING} characters"
    if t == "enum":
        if not isinstance(v, str):
            return "expected a string"
        return None if v in spec.enum else f"{v!r} is not one of {list(spec.enum)}"
    if t == "integer":
        return None if isinstance(v, int) and not isinstance(v, bool) else "expected an integer"
    if t == "number":
        if isinstance(v, bool) or not isinstance(v, (int, float)):
            return "expected a number"
        return None if math.isfinite(v) else "expected a finite number"
    if t == "boolean":
        return None if isinstance(v, bool) else "expected true or false"
    if t == "datetime":
        if not isinstance(v, str):
            return "expected an ISO-8601 timestamp string"
        try:
            dt = datetime.fromisoformat(v)
        except ValueError:
            return "expected an ISO-8601 timestamp string"
        return None if dt.tzinfo is not None else "timestamp must include a timezone (e.g. Z or +00:00)"
    if t == "uuid":
        if not isinstance(v, str):
            return "expected a UUID string"
        try:
            uuid.UUID(v)
        except ValueError:
            return "expected a UUID string"
        return None
    return f"unsupported field type {t}"  # pragma: no cover - registry is static


def _check_predicate(p: Predicate, path: str, readable: tuple[str, ...], hint: str,
                     errors: list[dict[str, str]]) -> None:
    spec = FIELDS_BY_NAME.get(p.field)
    if spec is None:
        errors.append({"path": f"{path}.field", "message": f"unknown field {p.field!r}"})
        return
    if spec.namespace not in readable:
        errors.append({"path": f"{path}.field",
                       "message": f"{p.field!r} cannot be used here; {hint}"})
        return
    allowed = operators_for(spec)
    if p.op not in allowed:
        errors.append({"path": f"{path}.op",
                       "message": f"operator {p.op!r} is not allowed for {spec.type} field "
                                  f"{p.field!r}; allowed: {list(allowed)}"})
        return
    vpath = f"{path}.value"
    if p.op in ("is_null", "is_empty"):
        if not isinstance(p.value, bool):
            errors.append({"path": vpath, "message": f"{p.op} takes true or false"})
        return
    if p.op in ("in", "not_in"):
        if not isinstance(p.value, list) or not p.value:
            errors.append({"path": vpath, "message": f"{p.op} takes a non-empty list"})
            return
        if len(p.value) > MAX_LIST_ITEMS:
            errors.append({"path": vpath, "message": f"{p.op} takes at most {MAX_LIST_ITEMS} values"})
            return
        for i, item in enumerate(p.value):
            problem = _type_ok(spec, item)
            if problem:
                errors.append({"path": f"{vpath}[{i}]", "message": problem})
        return
    if isinstance(p.value, list) or p.value is None:
        errors.append({"path": vpath, "message": f"{p.op} takes a single value"})
        return
    problem = _type_ok(spec, p.value)
    if problem:
        errors.append({"path": vpath, "message": problem})
        return
    if p.op in ("contains", "starts_with") and p.value == "":
        errors.append({"path": vpath, "message": f"{p.op} needs a non-empty string"})


def validate(raw: Any) -> Query:
    """Parse and validate a query object. Raises QueryError; never touches the DB."""
    if not isinstance(raw, dict):
        raise QueryError([{"path": "(query)", "message": "the query must be a JSON object"}])
    try:
        q = Query.model_validate(raw)
    except ValidationError as exc:
        raise QueryError([
            {"path": _format_loc(tuple(e["loc"])), "message": e["msg"]} for e in exc.errors()
        ]) from None

    errors: list[dict[str, str]] = []
    entity = ENTITIES[q.entity]
    root_ns: tuple[str, ...] = entity["namespaces"]
    count = 0

    def walk(node: Any, path: str, depth: int, readable: tuple[str, ...], hint: str,
             in_exists: bool) -> None:
        nonlocal count
        if depth > MAX_DEPTH:
            errors.append({"path": path, "message": f"nested deeper than {MAX_DEPTH} levels"})
            return
        if isinstance(node, AllNode):
            for i, child in enumerate(node.all):
                walk(child, f"{path}.all[{i}]", depth + 1, readable, hint, in_exists)
        elif isinstance(node, AnyNode):
            for i, child in enumerate(node.any):
                walk(child, f"{path}.any[{i}]", depth + 1, readable, hint, in_exists)
        elif isinstance(node, NotNode):
            walk(node.not_, f"{path}.not", depth + 1, readable, hint, in_exists)
        elif isinstance(node, ExistsNode):
            rel = node.exists.relation
            if in_exists:
                errors.append({"path": f"{path}.exists",
                               "message": "exists blocks cannot be nested"})
                return
            if rel not in entity["relations"]:
                errors.append({"path": f"{path}.exists.relation",
                               "message": f"a {q.entity} query has no relation {rel!r}; "
                                          f"allowed: {list(entity['relations'])}"})
                return
            if node.exists.where is not None:
                walk(node.exists.where, f"{path}.exists.where", depth + 1, (rel,),
                     f"inside exists:{rel} only {rel}.* fields are allowed", True)
        else:
            count += 1
            _check_predicate(node, path, readable, hint, errors)

    if q.where is not None:
        other = [r for r in entity["relations"]]
        hint = f"a {q.entity} query reads {', '.join(n + '.*' for n in root_ns)} directly"
        if other:
            hint += f"; use an exists block for {', '.join(r + '.*' for r in other)}"
        walk(q.where, "where", 1, root_ns, hint, False)
    if count > MAX_PREDICATES:
        errors.append({"path": "where", "message": f"more than {MAX_PREDICATES} conditions"})

    for i, s in enumerate(q.sort):
        spec = FIELDS_BY_NAME.get(s.field)
        if spec is None:
            errors.append({"path": f"sort[{i}].field", "message": f"unknown field {s.field!r}"})
        elif spec.namespace not in root_ns or not spec.sortable:
            errors.append({"path": f"sort[{i}].field",
                           "message": f"cannot sort a {q.entity} query by {s.field!r}"})

    for flag in ("suppressed", "third_party"):
        if getattr(q.include, flag) and flag not in entity["include"]:
            errors.append({"path": f"include.{flag}",
                           "message": "applies to asset queries only"})

    if errors:
        raise QueryError(errors)
    return q


# ── the published schema (read by the UI and the LLM) ───────────────────────

def published_schema() -> dict[str, Any]:
    return {
        "version": QUERY_VERSION,
        "entities": {
            name: {
                "description": e["description"],
                "fields": [f.name for f in FIELDS if f.namespace in e["namespaces"]],
                "relations": list(e["relations"]),
                "include": list(e["include"]),
                "output": list(e["output"]),
            }
            for name, e in ENTITIES.items()
        },
        "relations": {
            name: {"description": d,
                   "fields": [f.name for f in FIELDS if f.namespace == name]}
            for name, d in RELATIONS.items()
        },
        "fields": [
            {"name": f.name, "type": f.type, "description": f.description,
             "operators": list(operators_for(f)), "sortable": f.sortable,
             **({"enum": list(f.enum)} if f.enum else {})}
            for f in FIELDS
        ],
        "operators": OPERATORS,
        "include": INCLUDE_FLAGS,
        "limits": {
            "default_limit": DEFAULT_LIMIT, "max_limit": MAX_LIMIT, "max_depth": MAX_DEPTH,
            "max_conditions": MAX_PREDICATES, "max_list_items": MAX_LIST_ITEMS,
            "max_string_length": MAX_STRING, "max_sort_keys": MAX_SORT,
            "statement_timeout_ms": STATEMENT_TIMEOUT_MS, "count_cap": COUNT_CAP,
        },
        "query_json_schema": Query.model_json_schema(by_alias=True),
    }
