"""Seed the kind lab with the minimum a backend capture needs (planning#327). TEST ONLY.

Creates, through the real services and only if absent: the synthetic company
"Example Holdings A", marked ours by the lab admin (`entity_relationship.set_ours`),
and one open candidate `example.com` (`candidates.add_by_person`). No engagement, no
Target, no observer, no raw inserts. It refuses (exit 2) on anything unexpected rather
than repairing it, and it refuses to touch ANY database unless the database name ends
in `_lab` AND the database comment is exactly `constellus-kind-lab` (set by
`scripts/kind-lab.sh up`).

It is never shipped in the backend image. `scripts/kind-lab.sh backend-e2e` runs it as

    kubectl exec -i deploy/backend -c backend -- python - <admin-email> < scripts/lab_seed.py

(the image WORKDIR is /app, so `import app` resolves from the cwd with `python -`).
Prints only the candidate id on stdout.
"""

from __future__ import annotations

import sys
import uuid

LAB_MARKER = "constellus-kind-lab"
ORG_NAME = "Example Holdings A"
DOMAIN = "example.com"
_REFERENCE = "kind lab seed (planning#327)"
_EXCERPT = "Example Holdings A operates example.com. Synthetic kind lab seed (planning#327)."
_QUOTE = "Example Holdings A operates example.com"


class LabSeedRefused(Exception):
    """The lab is not in the state this seed expects; nothing was changed."""


def lab_db_refusal(name: str | None, comment: str | None) -> str | None:
    """A reason to refuse, or None only for a `_lab` database carrying the lab marker."""
    if not name or not name.endswith("_lab"):
        return f"database {name!r} does not end in '_lab'"
    if comment != LAB_MARKER:
        return f"database {name!r} does not carry the kind lab marker comment"
    return None


def check_lab_db(db) -> None:
    from sqlalchemy import text

    row = db.execute(
        text(
            "SELECT current_database(), shobj_description(d.oid, 'pg_database') "
            "FROM pg_database d WHERE d.datname = current_database()"
        )
    ).one_or_none()
    name, comment = (row[0], row[1]) if row else (None, None)
    reason = lab_db_refusal(name, comment)
    if reason is not None:
        raise LabSeedRefused(reason)


def seed(db, admin_email: str) -> uuid.UUID:
    from sqlalchemy import select

    from app.models.org_entity import RELATIONSHIP_OURS, OrgEntity
    from app.models.scope_candidate import ScopeCandidate
    from app.models.user import User, UserRole
    from app.services.entity_relationship import set_ours
    from app.services.org_discovery.candidates import add_by_person

    admin = db.execute(select(User).where(User.email == admin_email)).scalar_one_or_none()
    if admin is None:
        raise LabSeedRefused("the lab admin does not exist")
    if not admin.is_active or admin.role != UserRole.ADMIN.value:
        raise LabSeedRefused("the lab admin is not an active admin")

    entities = db.execute(select(OrgEntity).where(OrgEntity.legal_name == ORG_NAME)).scalars().all()
    if len(entities) > 1:
        raise LabSeedRefused(f"more than one company is named {ORG_NAME!r}")
    if entities:
        entity = entities[0]
    else:
        entity = OrgEntity(id=uuid.uuid4(), legal_name=ORG_NAME)
        db.add(entity)
        db.commit()

    if entity.relationship is None:
        set_ours(db, entity_id=entity.id, reference=_REFERENCE, user=admin)
        db.refresh(entity)
    elif entity.relationship != RELATIONSHIP_OURS:
        raise LabSeedRefused(f"{ORG_NAME!r} is already marked {entity.relationship!r}, not ours")

    candidate = db.execute(
        select(ScopeCandidate).where(ScopeCandidate.root_entity_id == entity.id, ScopeCandidate.value == DOMAIN)
    ).scalar_one_or_none()
    if candidate is not None:
        if candidate.status != "open" or candidate.kind != "domain":
            raise LabSeedRefused(f"the {DOMAIN} candidate is not an open domain candidate")
        return candidate.id
    candidate = add_by_person(
        db, root_entity_id=entity.id, via_entity_id=entity.id, domain=DOMAIN,
        source_url="https://example.com/", excerpt=_EXCERPT, quote=_QUOTE, user=admin,
    )
    return candidate.id


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: lab_seed.py <admin-email>", file=sys.stderr)
        return 2
    from app.core.database import SessionLocal

    db = SessionLocal()
    try:
        check_lab_db(db)
        candidate_id = seed(db, argv[1])
    except LabSeedRefused as exc:
        db.rollback()
        print(f"lab_seed: refused: {exc}", file=sys.stderr)
        return 2
    finally:
        db.close()
    print(str(candidate_id))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
