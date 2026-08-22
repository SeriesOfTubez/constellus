"""
Tag service — applies auto-tag rules and manages manual tags.

Rule condition format
---------------------
Simple:
  {"field": "asset_type", "op": "eq",         "value": "dns_record"}
  {"field": "value",      "op": "glob",        "value": "*.cloudfront.net"}
  {"field": "severity",   "op": "in",          "value": ["critical", "high"]}
  {"field": "kev",        "op": "eq",          "value": true}

Metadata field (assets only):
  {"field": "metadata.proxied", "op": "eq", "value": false}

Compound (AND / OR):
  {"all": [cond, cond, ...]}
  {"any": [cond, cond, ...]}
"""

import fnmatch
import logging
from typing import Any

from sqlalchemy.orm import Session

from app.models.tag_rule import TagRule

log = logging.getLogger(__name__)

ENTITY_TYPES = ("target", "asset", "finding")


# ── Condition evaluator ───────────────────────────────────────────────────────

def _get_field(entity: Any, field: str, metadata: dict | None = None) -> Any:
    """Resolve one rule `field` against `entity`.

    `metadata.<key>` fields are the reason this takes an explicit `metadata`
    override (planning#144 L3c-3). Asset rules address an open-ended key set
    — `metadata.<key>` is documented as a supported field on TagRule and
    nothing validates the key — so unlike every other reader in this slice
    these cannot be repointed at a specific claim or column. Callers supply
    the right reconstruction for their path instead:

      * asset_writer evaluates rules against a row that does not exist yet
        and therefore has no claims to reconstruct from — it passes the
        in-batch DiscoveredAsset's own metadata, the same dict the rule saw
        before this change.
      * reevaluate_all walks persisted rows — it passes the claims-layer
        reconstruction from `metadata_bridge`.

    `metadata=None` keeps the old `entity.asset_metadata` fallback, which is
    what target/finding rules (no metadata fields at all) still take.
    """
    if field.startswith("metadata."):
        key = field[9:]
        meta = metadata if metadata is not None else (getattr(entity, "asset_metadata", None) or {})
        return meta.get(key)
    return getattr(entity, field, None)


def _evaluate(condition: dict, entity: Any, metadata: dict | None = None) -> bool:
    if "all" in condition:
        return all(_evaluate(c, entity, metadata) for c in condition["all"])
    if "any" in condition:
        return any(_evaluate(c, entity, metadata) for c in condition["any"])

    field = condition.get("field", "")
    op = condition.get("op", "eq")
    expected = condition.get("value")
    actual = _get_field(entity, field, metadata)

    if op == "eq":
        return actual == expected
    if op == "neq":
        return actual != expected
    if op == "contains":
        return isinstance(actual, str) and isinstance(expected, str) and expected.lower() in actual.lower()
    if op == "glob":
        return isinstance(actual, str) and isinstance(expected, str) and fnmatch.fnmatch(actual.lower(), expected.lower())
    if op == "startswith":
        return isinstance(actual, str) and isinstance(expected, str) and actual.lower().startswith(expected.lower())
    if op == "in":
        return actual in (expected if isinstance(expected, list) else [expected])
    if op == "not_in":
        return actual not in (expected if isinstance(expected, list) else [expected])
    if op == "exists":
        return actual is not None
    return False


# ── Public helpers ────────────────────────────────────────────────────────────

def apply_rules_preloaded(rules: list, entity: Any, metadata: dict | None = None) -> list[str]:
    """Evaluate a pre-fetched list of TagRule objects. Use in batch writers to
    avoid N+1 queries. `metadata` overrides the source for `metadata.<key>`
    rule fields — see `_get_field`."""
    tags_to_add: list[str] = []
    for rule in rules:
        try:
            if _evaluate(rule.condition, entity, metadata):
                tags_to_add.append(rule.tag)
        except Exception:
            log.debug("Tag rule %s evaluation error", rule.id, exc_info=True)
    return tags_to_add


def apply_rules(db: Session, entity: Any, entity_type: str) -> list[str]:
    """
    Evaluate all enabled rules for the given entity_type against entity.
    Returns the list of tags that should be added (does not modify the entity).
    """
    rules = (
        db.query(TagRule)
        .filter(TagRule.entity_type == entity_type, TagRule.enabled == True)  # noqa: E712
        .all()
    )
    tags_to_add: list[str] = []
    for rule in rules:
        try:
            if _evaluate(rule.condition, entity):
                tags_to_add.append(rule.tag)
        except Exception:
            log.debug("Tag rule %s evaluation error on %s", rule.id, entity_type, exc_info=True)
    return tags_to_add


def merge_tags(existing: list[str], new_tags: list[str]) -> list[str]:
    """Merge new_tags into existing, preserving order and deduplicating."""
    seen = set(existing)
    result = list(existing)
    for tag in new_tags:
        if tag not in seen:
            seen.add(tag)
            result.append(tag)
    return result


def set_entity_tags(entity: Any, tags: list[str]) -> None:
    """Replace tags on entity with the provided list (deduplicated, sorted)."""
    entity.tags = sorted(set(tags))


def add_rule_tags(db: Session, entity: Any, entity_type: str) -> None:
    """Evaluate rules and merge resulting tags onto entity in-place."""
    new_tags = apply_rules(db, entity, entity_type)
    if new_tags:
        entity.tags = merge_tags(entity.tags or [], new_tags)


# ── Bulk re-evaluation ────────────────────────────────────────────────────────

def reevaluate_all(db: Session) -> dict[str, int]:
    """
    Re-run all enabled rules against every entity in the DB.
    Adds tags; never removes tags that were manually applied.
    Returns counts of updated entities per type.
    """
    from app.models.asset_canonical import AssetCanonical
    from app.models.finding_canonical import FindingCanonical
    from app.models.target import Target
    from app.services import metadata_bridge

    counts: dict[str, int] = {"target": 0, "asset": 0, "finding": 0}

    for entity_type, model in [("target", Target), ("asset", AssetCanonical), ("finding", FindingCanonical)]:
        rules = (
            db.query(TagRule)
            .filter(TagRule.entity_type == entity_type, TagRule.enabled == True)  # noqa: E712
            .all()
        )
        if not rules:
            continue

        # Process in batches to avoid loading all rows at once
        offset = 0
        batch = 500
        while True:
            rows = db.query(model).offset(offset).limit(batch).all()
            if not rows:
                break
            # planning#144 L3c-3: asset rules can address any `metadata.<key>`,
            # so reconstruct the whole dict from the claims layer rather than
            # read the asset_metadata column — batch-loaded per 500-row page,
            # not per row. Only assets have metadata fields; targets and
            # findings pass None and keep the plain attribute path.
            bridged: dict = {}
            if entity_type == "asset":
                sources = metadata_bridge.load_bridge_sources(db, [r.id for r in rows])
                for row in rows:
                    claims = sources.get(row.id, metadata_bridge.EMPTY_BRIDGE_SOURCES)
                    bridged[row.id] = metadata_bridge.bridge_metadata(row, claims.get("state"), claims)
            for entity in rows:
                metadata = bridged.get(entity.id) if entity_type == "asset" else None
                new_tags: list[str] = []
                for rule in rules:
                    try:
                        if _evaluate(rule.condition, entity, metadata):
                            new_tags.append(rule.tag)
                    except Exception:
                        pass
                if new_tags:
                    entity.tags = merge_tags(entity.tags or [], new_tags)
                    counts[entity_type] += 1
            db.commit()
            offset += batch

    return counts
