"""The permission catalogue (planning#243 slice 1).

What it is: the closed list of things a caller can be allowed to do
(`Permission`, values `"<resource>.<action>"`) and the table saying which role
holds which (`ROLE_PERMISSIONS`). Routes ask `require_permission(Permission.X)`
(see `app/api/deps.py`); a handler that must decide on request *content* asks
`has_permission(user, Permission.X)`. Nothing else in the code base compares a
`User.role` to anything.

This module is the ONLY place role -> capability lives. Granularity is
resource.action plus named actions, not one permission per endpoint: every
route, reads included, carries exactly one route permission, and all routes
sharing a permission admit exactly the same roles.

Slice 1 is a pure refactor: the table below reproduces, route for route, the
access the former `require_role(...)` guards gave (held fixed by the parity
test against `tests/fixtures/route_access_baseline.json`).

Planned: planning#261 will add a scope to role assignments (which entities /
engagements a grant covers), and slice 2 of planning#243 makes roles
DB-defined; `ROLE_PERMISSIONS` then becomes a seed rather than the truth.

Fail closed: a role this table does not know holds nothing.
"""

import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum

from app.models.user import UserRole


class Permission(StrEnum):
    # assets
    ASSETS_READ = "assets.read"
    ASSETS_UPDATE = "assets.update"
    ASSETS_DELETE = "assets.delete"
    ASSETS_SCAN = "assets.scan"

    # web classifications and the AI correction of them
    WEB_CLASSIFICATIONS_READ = "web_classifications.read"
    WEB_CLASSIFICATIONS_GENERATE = "web_classifications.generate"
    AI_CORRECT = "ai.correct"

    # findings
    FINDINGS_READ = "findings.read"
    FINDINGS_TRIAGE = "findings.triage"
    FINDINGS_VERIFY = "findings.verify"
    FINDINGS_GENERATE_WRITEUP = "findings.generate_writeup"

    # targets
    TARGETS_READ = "targets.read"
    TARGETS_CREATE = "targets.create"
    TARGETS_UPDATE = "targets.update"
    TARGETS_DELETE = "targets.delete"
    TARGETS_SET_AGGRESSIVENESS = "targets.set_aggressiveness"
    TARGETS_RECHECK = "targets.recheck"
    TARGETS_ACKNOWLEDGE = "targets.acknowledge"
    TARGETS_VERIFY = "targets.verify"
    TARGETS_SET_ENTITY = "targets.set_entity"
    TARGETS_WIDEN_ENGAGEMENT = "targets.widen_engagement"

    # engagements
    ENGAGEMENTS_READ = "engagements.read"
    ENGAGEMENTS_CREATE = "engagements.create"
    ENGAGEMENTS_UPDATE = "engagements.update"
    ENGAGEMENTS_DELETE = "engagements.delete"
    ENGAGEMENTS_TRANSITION = "engagements.transition"
    # planning#261: read data under a restricting-posture engagement without
    # an assignment on it (held globally; see `Grants.reads_all_restricted`)
    ENGAGEMENTS_READ_RESTRICTED = "engagements.read_restricted"
    ENGAGEMENTS_READ_ASSIGNMENTS = "engagements.read_assignments"
    ENGAGEMENTS_MANAGE_ASSIGNMENTS = "engagements.manage_assignments"

    # entities (the corporate graph)
    ENTITIES_READ = "entities.read"
    ENTITIES_CREATE = "entities.create"
    ENTITIES_SEARCH_REGISTRANTS = "entities.search_registrants"
    ENTITIES_PROPOSE_CANDIDATE = "entities.propose_candidate"
    ENTITIES_DECIDE_CANDIDATE = "entities.decide_candidate"
    ENTITIES_DECIDE_RELATION = "entities.decide_relation"
    ENTITIES_INGEST = "entities.ingest"
    ENTITIES_SEED_ONBOARDING = "entities.seed_onboarding"
    ENTITIES_GENERATE_ACQUISITION_READ = "entities.generate_acquisition_read"
    ENTITIES_LINK_REGISTRANT = "entities.link_registrant"
    ENTITIES_SET_MA_TARGET = "entities.set_ma_target"
    ENTITIES_MARK_OURS = "entities.mark_ours"

    # organizations: a root company and its discovered scope (planning#277)
    ORGANIZATIONS_CREATE = "organizations.create"

    # scans and scan templates
    SCANS_READ = "scans.read"
    SCANS_CREATE = "scans.create"
    SCANS_UPDATE = "scans.update"
    SCANS_DELETE = "scans.delete"
    SCANS_CANCEL = "scans.cancel"
    SCAN_TEMPLATES_READ = "scan_templates.read"
    SCAN_TEMPLATES_READ_JOBS = "scan_templates.read_jobs"
    SCAN_TEMPLATES_CREATE = "scan_templates.create"
    SCAN_TEMPLATES_UPDATE = "scan_templates.update"
    SCAN_TEMPLATES_DELETE = "scan_templates.delete"
    SCAN_TEMPLATES_RUN = "scan_templates.run"

    # connectors
    CONNECTORS_READ = "connectors.read"
    CONNECTORS_READ_CONFIG = "connectors.read_config"
    CONNECTORS_CONFIGURE = "connectors.configure"
    CONNECTORS_TOGGLE = "connectors.toggle"
    CONNECTORS_SYNC = "connectors.sync"
    CONNECTORS_TEST = "connectors.test"

    # users, sign-in and SSO
    USERS_READ_SELF = "users.read_self"
    USERS_READ_ANY = "users.read_any"
    USERS_CREATE = "users.create"
    USERS_UPDATE = "users.update"
    AUTH_READ = "auth.read"
    SAML_READ = "saml.read"
    SAML_CONFIGURE = "saml.configure"

    # platform administration
    SETTINGS_READ = "settings.read"
    SETTINGS_UPDATE = "settings.update"
    LOGS_READ = "logs.read"
    LOGS_CONFIGURE = "logs.configure"
    LOGS_DELETE = "logs.delete"
    AUDIT_READ = "audit.read"
    SYSTEM_READ = "system.read"

    # tags
    TAGS_READ = "tags.read"
    TAGS_READ_RULES = "tags.read_rules"
    TAGS_MANAGE_RULES = "tags.manage_rules"
    TAGS_ASSIGN = "tags.assign"
    TAGS_EVALUATE_RULES = "tags.evaluate_rules"

    # monitoring and notifications
    MONITORING_READ = "monitoring.read"
    MONITORING_CREATE = "monitoring.create"
    MONITORING_UPDATE = "monitoring.update"
    MONITORING_DELETE = "monitoring.delete"
    NOTIFICATIONS_READ = "notifications.read"
    NOTIFICATIONS_CREATE = "notifications.create"
    NOTIFICATIONS_UPDATE = "notifications.update"
    NOTIFICATIONS_DELETE = "notifications.delete"
    NOTIFICATIONS_CONFIGURE = "notifications.configure"

    # graph, claims, hygiene
    GRAPH_READ = "graph.read"
    CLAIMS_READ = "claims.read"
    HYGIENE_READ = "hygiene.read"
    HYGIENE_RECOMPUTE = "hygiene.recompute"

    # LLM, query, chat, reports
    LLM_READ = "llm.read"
    LLM_CONFIGURE = "llm.configure"
    LLM_REFRESH_MODELS = "llm.refresh_models"
    QUERY_READ = "query.read"
    QUERY_RUN = "query.run"
    CHAT_READ = "chat.read"
    CHAT_CREATE = "chat.create"
    CHAT_ASK = "chat.ask"
    CHAT_DELETE = "chat.delete"
    REPORTS_READ = "reports.read"
    REPORTS_CREATE = "reports.create"
    REPORTS_DELETE = "reports.delete"

    # domain verification (router not mounted today; kept guarded)
    DOMAINS_READ = "domains.read"
    DOMAINS_CREATE = "domains.create"
    DOMAINS_VERIFY = "domains.verify"
    DOMAINS_DELETE = "domains.delete"


P = Permission

# Every role can do these: reads, plus the self-service and conversational
# actions that only ever touch the caller's own records.
_EVERYONE: frozenset[Permission] = frozenset({
    P.ASSETS_READ, P.WEB_CLASSIFICATIONS_READ, P.FINDINGS_READ, P.TARGETS_READ,
    P.ENGAGEMENTS_READ, P.ENTITIES_READ, P.SCANS_READ, P.SCAN_TEMPLATES_READ,
    P.CONNECTORS_READ, P.USERS_READ_SELF, P.AUTH_READ, P.SYSTEM_READ, P.TAGS_READ,
    P.GRAPH_READ, P.CLAIMS_READ, P.HYGIENE_READ, P.QUERY_READ, P.QUERY_RUN,
    P.CHAT_READ, P.CHAT_CREATE, P.CHAT_ASK, P.CHAT_DELETE, P.REPORTS_READ,
    P.DOMAINS_READ,
})

# What an integration admin may do on top: run and configure the scanning
# estate (targets, scans, connectors, monitoring, notifications, triage).
_INTEGRATION_ADMIN_EXTRA: frozenset[Permission] = frozenset({
    P.ASSETS_UPDATE, P.ASSETS_DELETE, P.ASSETS_SCAN,
    P.FINDINGS_TRIAGE, P.FINDINGS_VERIFY,
    P.TARGETS_CREATE, P.TARGETS_UPDATE, P.TARGETS_DELETE,
    P.TARGETS_SET_AGGRESSIVENESS, P.TARGETS_RECHECK, P.TARGETS_ACKNOWLEDGE,
    P.TARGETS_VERIFY,
    P.ENGAGEMENTS_CREATE, P.ENTITIES_SET_MA_TARGET,
    P.SCANS_CREATE, P.SCANS_UPDATE, P.SCANS_DELETE, P.SCANS_CANCEL,
    P.SCAN_TEMPLATES_CREATE, P.SCAN_TEMPLATES_UPDATE, P.SCAN_TEMPLATES_DELETE,
    P.SCAN_TEMPLATES_RUN,
    P.CONNECTORS_READ_CONFIG, P.CONNECTORS_CONFIGURE, P.CONNECTORS_TOGGLE,
    P.CONNECTORS_SYNC, P.CONNECTORS_TEST,
    P.SAML_READ, P.SAML_CONFIGURE,
    P.LOGS_READ,
    P.TAGS_READ_RULES, P.TAGS_MANAGE_RULES, P.TAGS_ASSIGN,
    P.MONITORING_READ, P.MONITORING_CREATE, P.MONITORING_UPDATE, P.MONITORING_DELETE,
    P.NOTIFICATIONS_READ, P.NOTIFICATIONS_CREATE, P.NOTIFICATIONS_UPDATE,
    P.NOTIFICATIONS_DELETE, P.NOTIFICATIONS_CONFIGURE,
    P.DOMAINS_CREATE, P.DOMAINS_VERIFY, P.DOMAINS_DELETE,
})

ROLE_PERMISSIONS: dict[str, frozenset[Permission]] = {
    UserRole.VIEWER.value: _EVERYONE,
    UserRole.REPORT_ADMIN.value: _EVERYONE | {P.REPORTS_CREATE, P.REPORTS_DELETE},
    UserRole.INTEGRATION_ADMIN.value: _EVERYONE | _INTEGRATION_ADMIN_EXTRA,
    UserRole.ADMIN.value: frozenset(Permission),
}


# ── scoped assignments (planning#261) ────────────────────────────────────────

@dataclass(frozen=True)
class Grants:
    """What a principal's role assignments add up to. `global_role` is the role
    of the global assignment (None if there is none); `engagement_roles` maps
    engagement id -> role for engagement-scoped ones."""

    global_role: str | None
    engagement_roles: Mapping[uuid.UUID, str] = field(default_factory=dict)

    def _global_holds(self, permission: Permission) -> bool:
        return self.global_role is not None and permission in ROLE_PERMISSIONS.get(self.global_role, frozenset())

    def allows(self, permission: Permission) -> bool:
        """The route gate. A global assignment grants its role's permissions.
        An engagement-scoped one grants only its role's `<resource>.read`
        permissions here (Jason, 2026-10-22: read visibility only in slice 1;
        per-row write checks come with planning#243 slice 2). Which rows it
        then sees is `read_scope`'s business."""
        if self._global_holds(permission):
            return True
        if not permission.value.endswith(".read"):
            return False
        return any(permission in ROLE_PERMISSIONS.get(r, frozenset()) for r in self.engagement_roles.values())

    @property
    def reads_all_restricted(self) -> bool:
        """A global role holding `engagements.read_restricted` (admin) reads
        every engagement's data. Any other global role does NOT: it sees the
        owned estate and day_0/integrated data only (Jason, 2026-10-22)."""
        return self._global_holds(Permission.ENGAGEMENTS_READ_RESTRICTED)

    def readable_engagements(self, permission: Permission) -> frozenset[uuid.UUID]:
        """Engagements whose restricted data an engagement assignment opens
        for `permission`: the assignment's role must hold it."""
        return frozenset(e for e, r in self.engagement_roles.items()
                         if permission in ROLE_PERMISSIONS.get(r, frozenset()))


_GRANTS_ATTR = "_planning261_grants"


def compute_grants(user) -> Grants:
    global_role, engagement_roles = None, {}
    for a in getattr(user, "assignments", None) or ():
        if a.engagement_id is None:
            global_role = getattr(a.role, "value", a.role)
        else:
            engagement_roles[a.engagement_id] = getattr(a.role, "value", a.role)
    return Grants(global_role=global_role, engagement_roles=engagement_roles)


def snapshot_grants(user) -> Grants:
    """Compute once and pin on the instance (a plain attribute, so a commit
    that expires the mapped ones does not drop it and a detached user, as the
    chat tools hold, still answers). `get_current_user` calls this; nothing
    else should, so a test that edits a user's assignments sees the edit."""
    grants = compute_grants(user)
    user.__dict__[_GRANTS_ATTR] = grants
    return grants


def grants_of(user) -> Grants:
    return user.__dict__.get(_GRANTS_ATTR) or compute_grants(user)


def has_permission(user, permission: Permission) -> bool:
    """True if `user`'s role assignments grant `permission` (`Grants.allows`).
    `users.role` is NOT read: it only feeds the global assignment
    (models/role_assignment.py). An unknown role holds nothing."""
    return grants_of(user).allows(permission)
