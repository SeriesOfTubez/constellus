"""app.services.web_classifier_eval - does showing the model corrected
examples help? (planning#231 slice 3). Run it by hand:

    python -m app.services.web_classifier_eval --corrections                  # plan only, no calls
    python -m app.services.web_classifier_eval --corrections --live --max-calls 40
    python -m app.services.web_classifier_eval --asset <uuid> --live --max-calls 4

`--corrections` replays every stored correction twice, with and without
examples (an override is never its own example: `similar_corrections`
excludes the subject, which makes the with-examples run leave-one-out), and
compares the model's answer with the administrator's label. `--asset` runs
each web endpoint of one asset as it is now and without
`endpoint.title_after_redirect`, for eyeballing; there is no label.

Reads only: nothing is written to `web_classifications` or the overrides (the
`llm_calls` ledger rows `llm_connector.structured` writes are expected and
count against the daily budget). Output is ids, ports, kinds, environments
and counts - never a title, hostname or snapshot. Without `--live` it makes no
call; with `--live` it refuses to start unless `--max-calls` covers the plan.
"""

from __future__ import annotations

import argparse
import copy
import sys
import uuid
from collections import defaultdict
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.database import SessionLocal
from app.models.asset_canonical import AssetCanonical
from app.models.web_classification import WebEndpointOverride
from app.services import llm_connector
from app.services.finding_writeup import resolve_scope
from app.services.web_classifier import (
    ClassificationOut, _prune, build_input, messages_for, prompt_data, shape, similar_corrections, web_endpoints,
)


@dataclass
class Case:
    asset_id: uuid.UUID
    port: int
    variant: str
    data: dict
    examples: list[WebEndpointOverride]
    label: tuple[str, str] | None


def corrections_cases(db: Session, *, with_examples: bool) -> list[Case]:
    """One case per stored correction: its snapshot is the subject and its
    kind/environment the label."""
    cases: list[Case] = []
    overrides = db.execute(
        select(WebEndpointOverride).order_by(WebEndpointOverride.asset_canonical_id, WebEndpointOverride.port)
    ).scalars().all()
    for o in overrides:
        asset = db.get(AssetCanonical, o.asset_canonical_id)
        if asset is None:
            continue
        data = o.input_snapshot
        examples = similar_corrections(db, asset, o.port, data) if with_examples else []
        cases.append(Case(
            asset_id=o.asset_canonical_id, port=o.port,
            variant="with_examples" if with_examples else "without_examples",
            data=data, examples=examples, label=(o.kind, o.environment),
        ))
    return cases


def asset_cases(db: Session, asset_id: uuid.UUID) -> list[Case]:
    asset = db.get(AssetCanonical, asset_id)
    if asset is None:
        raise ValueError(f"asset {asset_id} not found")
    cases: list[Case] = []
    for entry in web_endpoints(db, asset):
        data = build_input(asset, entry)
        cases.append(Case(asset_id, entry["port"], "current", data, [], None))
        stripped = copy.deepcopy(data)
        stripped.get("endpoint", {}).pop("title_after_redirect", None)
        cases.append(Case(asset_id, entry["port"], "no_title_after_redirect", _prune(stripped), [], None))
    return cases


def run(db: Session, cases: list[Case], *, max_calls: int) -> list[dict]:
    if len(cases) > max_calls:
        raise ValueError(f"{len(cases)} cases exceed --max-calls {max_calls}; nothing was called")
    results: list[dict] = []
    for case in cases:
        asset = db.get(AssetCanonical, case.asset_id)
        scope = resolve_scope(db, asset)
        label_kind, label_env = case.label if case.label else (None, None)
        row = {
            "asset_id": str(case.asset_id), "port": case.port, "variant": case.variant, "model": None,
            "kind": None, "environment": None, "label_kind": label_kind, "label_environment": label_env,
            "agree_kind": None, "agree_environment": None, "error": None,
        }
        try:
            answer = llm_connector.structured(
                db, role=llm_connector.Role.CLASSIFY,
                messages=messages_for(prompt_data(case.data, case.examples)), schema=ClassificationOut,
                target_id=scope.target_id, engagement_id=None,
                task=f"web_classification_eval:{case.asset_id}:{case.port}:{case.variant}",
                force_strict=scope.force_strict, source_text=None,
            )
        except llm_connector.LLMError as exc:
            db.rollback()
            row["error"] = type(exc).__name__
            results.append(row)
            continue
        shaped = shape(answer.value, case.data)
        row.update(model=answer.model, kind=shaped["kind"], environment=shaped["environment"])
        if case.label is not None:
            row["agree_kind"] = shaped["kind"] == label_kind
            row["agree_environment"] = shaped["environment"] == label_env
        results.append(row)
    return results


def summarise(results: list[dict]) -> list[dict]:
    groups: dict[tuple[str, str | None], list[dict]] = defaultdict(list)
    for r in results:
        groups[(r["variant"], r["model"])].append(r)
    out = []
    for (variant, model), rows in sorted(groups.items(), key=lambda kv: (kv[0][0], str(kv[0][1]))):
        labelled = [r for r in rows if not r["error"] and r["agree_kind"] is not None]
        out.append({
            "variant": variant, "model": model, "n": len(rows), "errors": sum(1 for r in rows if r["error"]),
            "labelled": len(labelled),
            "kind_agree": sum(1 for r in labelled if r["agree_kind"]),
            "environment_agree": sum(1 for r in labelled if r["agree_environment"]),
        })
    return out


def _plan(cases: list[Case]) -> dict[str, int]:
    counts: dict[str, int] = defaultdict(int)
    for c in cases:
        counts[c.variant] += 1
    return dict(counts)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="web_classifier_eval", description=__doc__.split("\n")[0])
    what = parser.add_mutually_exclusive_group(required=True)
    what.add_argument("--corrections", action="store_true", help="replay stored corrections, with/without examples")
    what.add_argument("--asset", type=uuid.UUID, help="run one asset's web endpoints")
    parser.add_argument("--live", action="store_true", help="make the LLM calls (default: print the plan only)")
    parser.add_argument("--max-calls", type=int, default=None, help="hard cap on calls; required with --live")
    args = parser.parse_args(argv)

    db = SessionLocal()
    try:
        if args.corrections:
            cases = corrections_cases(db, with_examples=True) + corrections_cases(db, with_examples=False)
        else:
            cases = asset_cases(db, args.asset)
        print(f"plan: {len(cases)} calls {_plan(cases)}")
        if not args.live:
            print("dry run: no calls made (add --live --max-calls N)")
            return 0
        if args.max_calls is None or args.max_calls < len(cases):
            print(f"refused: --live needs --max-calls >= {len(cases)}", file=sys.stderr)
            return 2
        results = run(db, cases, max_calls=args.max_calls)
        for r in results:
            print({k: r[k] for k in ("asset_id", "port", "variant", "model", "kind", "environment",
                                     "label_kind", "label_environment", "error")})
        for s in summarise(results):
            print(s)
        return 0
    finally:
        db.close()


if __name__ == "__main__":
    sys.exit(main())
