"""Every GET route says where it stands on row-level read scope (planning#261).

A new GET route that is in none of the three dicts below fails
`test_every_get_route_is_classified`, naming the route: whoever adds it must
decide, in review, whether it returns rows `read_scope` governs.

- `SCOPED`: the handler filters what it returns through `services/read_scope`
  (or `read_scope.engagement_visible`), and `test_read_scope_api.py` /
  the module's own tests pin it.
- `NOT_YET_SCOPED`: returns rows the rule should govern but does not yet. The
  value names the slice that will: `"1b"` (the rest of the asset / target /
  engagement surface), `"entity"` (the entity graph, after planning#277).
  This dict is a debt list; it must only shrink.
- `EXEMPT`: returns no rows the rule governs (health, auth, settings, static
  schemas, administration of users and connectors...). The value says why.

Each route is in exactly one dict, and no dict names a route that no longer
exists, so the lists cannot rot.
"""

from app.tests._route_access import iter_app_routes

SCOPED = {
    "/api/assets/": "asset_clause",
    "/api/assets/{asset_id}": "asset_clause, 404",
    "/api/assets/{asset_id}/web-classifications": "asset_clause",
    "/api/web-endpoints": "asset_clause on the endpoint's asset and each hop's asset",
    "/api/edges/{node_type}/{node_id}": "root + hydrated endpoints, asset/finding/target clauses",
    "/api/findings/": "finding_clause",
    "/api/findings/clusters": "finding_clause before grouping",
    "/api/findings/clusters/members": "finding_clause",
    "/api/findings/clusters/ai-writeup": "viewer's member view; write-up hidden unless every member is readable",
    "/api/findings/security-score": "finding_clause on every aggregate",
    "/api/findings/{finding_id}": "finding_clause, 404",
    "/api/findings/{finding_id}/ai-writeup": "finding_clause, 404",
    "/api/findings/{finding_id}/epss-history": "finding_clause, 404",
    "/api/connectors/": "connector_instance_clause on each type's instances",
    "/api/connectors/bindable-organizations": "entity_clause on the organization roots",
    "/api/connectors/domains": "connector_instance_clause on the instances, target_clause on the manual targets",
    "/api/connectors/instances/{instance_id}": "connector_instance_clause, 404",
    "/api/connectors/instances/{instance_id}/config": "connector_instance_clause, 404",
    "/api/connectors/instances/{instance_id}/zones": "connector_instance_clause, 404",
    "/api/connectors/instances/{instance_id}/zone-clashes": "connector_instance_clause, 404",
    "/api/reports": "engagement_visible",
    "/api/reports/{report_id}": "engagement_visible",
    "/api/reports/{report_id}/markdown": "engagement_visible",
}

NOT_YET_SCOPED = {
    # asset / target / engagement surface
    "/api/assets/whois": "1b",
    "/api/assets/whois-domain": "1b",
    "/api/claims/absence": "1b",
    "/api/claims/surface/{asset_id}": "1b",
    "/api/engagements/": "1b",
    "/api/engagements/{engagement_id}": "1b",
    "/api/hygiene/": "1b",
    "/api/hygiene/{asset_id}": "1b",
    "/api/scans/": "1b",
    "/api/scans/{scan_id}": "1b",
    "/api/scan-templates/": "1b",
    "/api/scan-templates/{template_id}": "1b",
    "/api/tags/": "1b",
    "/api/tags/rules": "1b",
    "/api/targets/": "1b",
    "/api/targets/{target_id}": "1b",
    # finding / asset content reaching admins by another route
    "/api/notifications/alerts": "1b",
    "/api/notifications/digests": "1b",
    "/api/notifications/digests/{digest_id}": "1b",
    "/api/logs/": "1b",
    # the entity graph
    "/api/entities/": "entity",
    "/api/entities/edgar-ingest/runs": "entity",
    "/api/entities/edgar-ingest/runs/{run_id}": "entity",
    "/api/entities/evidence/{fetch_id}": "entity",
    "/api/entities/onboarding/registrant-search": "entity",
    "/api/entities/relations": "entity",
    "/api/entities/{entity_id}": "entity",
    "/api/entities/{entity_id}/acquisition-read/runs": "entity",
    "/api/entities/{entity_id}/destination": "entity",
    "/api/entities/{entity_id}/edges": "entity",
    "/api/entities/{entity_id}/filing-events": "entity",
    "/api/entities/{entity_id}/filing-sections": "entity",
    "/api/entities/{entity_id}/registrant-candidates": "entity",
    "/api/entities/{entity_id}/registrant-link": "entity",
    "/api/entities/{entity_id}/subsidiary-listings": "entity",
    # organizations (planning#277): the hooks are called, and grant everything today
    "/api/organizations/": "entity",
    "/api/organizations/{org_id}/candidates": "entity",
    "/api/organizations/candidates/{candidate_id}": "entity",
    "/api/organizations/{org_id}/summary": "entity",
    "/api/organizations/{org_id}/tree": "entity",
    "/api/organizations/locate/{entity_id}": "entity",
}

EXEMPT = {
    "/api/audit/": "admin-only audit trail of requests, not estate rows",
    "/api/audit/facets": "admin-only audit filter values",
    "/api/auth/me": "the caller's own profile",
    "/api/auth/saml/config": "SSO configuration",
    "/api/auth/saml/config/preview-metadata": "SSO configuration",
    "/api/auth/saml/login": "starts the SSO redirect",
    "/api/chat/conversations": "the caller's own transcripts; tool results were scoped when produced",
    "/api/chat/conversations/{conversation_id}": "the caller's own transcript",
    "/api/engagements/{engagement_id}/assignments": "who holds a role on an engagement: administration, admin-only",
    "/api/health": "liveness",
    "/api/llm/models": "AI configuration",
    "/api/llm/role-bindings": "AI configuration",
    "/api/llm/status": "AI configuration",
    "/api/logs/settings": "logging configuration",
    "/api/logs/sources": "logging configuration",
    "/api/monitoring/policies": "monitoring configuration",
    "/api/notifications/digest-settings": "notification configuration",
    "/api/notifications/rules": "notification configuration",
    "/api/organizations/filer-search": "external SEC lookup; reads no stored rows",
    "/api/organizations/signal-types": "the static signal catalogue; reads no stored rows",
    "/api/query/schema": "the static query schema; the rows come from POST /api/query, which applies read_scope",
    "/api/scan-templates/_/jobs": "admin-only scheduler state",
    "/api/settings/": "application settings",
    "/api/settings/branding": "login-page branding",
    "/api/system/monitoring-status": "scheduler status",
    "/api/system/status": "first-run status",
    "/api/users/": "user administration",
    "/api/users/{user_id}": "user administration",
}


def _get_paths() -> set[str]:
    return {path for method, path, _route in iter_app_routes() if method == "GET"}


def test_every_get_route_is_classified():
    known = set(SCOPED) | set(NOT_YET_SCOPED) | set(EXEMPT)
    missing = sorted(_get_paths() - known)
    assert not missing, (
        f"GET route(s) {missing} are in none of SCOPED / NOT_YET_SCOPED / EXEMPT "
        "(app/tests/test_read_scope_sweep.py). If it returns rows read_scope governs, scope it and add it to "
        "SCOPED; if not, add it to EXEMPT with the reason."
    )


def test_each_route_is_in_exactly_one_dict():
    dicts = {"SCOPED": SCOPED, "NOT_YET_SCOPED": NOT_YET_SCOPED, "EXEMPT": EXEMPT}
    for path in set(SCOPED) | set(NOT_YET_SCOPED) | set(EXEMPT):
        homes = [name for name, d in dicts.items() if path in d]
        assert len(homes) == 1, f"{path} is in {homes}"


def test_no_dict_names_a_route_that_is_gone():
    stale = sorted((set(SCOPED) | set(NOT_YET_SCOPED) | set(EXEMPT)) - _get_paths())
    assert not stale, f"these are classified but no longer exist: {stale}"


def test_not_yet_scoped_names_a_known_slice():
    assert set(NOT_YET_SCOPED.values()) <= {"1b", "entity"}
