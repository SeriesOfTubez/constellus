"""Tests for the target-domain allowlist boundary in dns_resolve._emit_assets
(planning#125).

Real bug this replaces: onboarding a customer domain surfaced Azure App
Service's internal front-end (*.cloudapp.azure.com), HubSpot CMS's
portal-keyed hosting hops (*.sites.hubspot.net / *.hscoscdn30.net), and
Refined's shared custom-domain proxy (*.refined.site) as their own
first-class dns_record assets — none of these were in the old curated
DEFAULT_CDN_SUFFIXES denylist, so boundary detection never fired. The fix
flips the check: a hop is suppressed when its target is NOT a subdomain of
any of the org's *declared* target domains, regardless of whether it's a
recognized CDN/SaaS provider. No suffix list, curated or otherwise, is
involved anymore — these tests use made-up third-party hostnames on purpose
to prove the boundary doesn't depend on recognizing the provider.

planning#147 changed what happens to the boundary TARGET: it used to be
discarded with the rest of the chain, and is now captured as a third-party
context node so a WHOIS check / takeover fingerprint / vendor-incident query
has something to attach to. The suppression these tests exist to protect is
unchanged and still asserted — everything PAST the boundary stays gone, and
the captured node carries `third_party` so it never enters active scanning.
"capture != scan eligibility" is the whole distinction.

Pure-function tests against `_emit_assets` directly (no DB, no network) —
`name_records` here is exactly the shape `_try_resolve` produces.
"""

from app.services.discovery.dns_resolve import _emit_assets, _is_owned


# ── _is_owned ────────────────────────────────────────────────────────────────

def test_is_owned_exact_match():
    assert _is_owned("example.com", frozenset({"example.com"})) is True


def test_is_owned_subdomain_match():
    assert _is_owned("app.example.com", frozenset({"example.com"})) is True


def test_is_owned_unrelated_domain_not_owned():
    assert _is_owned("evil-example.com", frozenset({"example.com"})) is False


def test_is_owned_suffix_lookalike_not_owned():
    # "notexample.com" must not match "example.com" via naive suffix slicing.
    assert _is_owned("notexample.com", frozenset({"example.com"})) is False


# ── _emit_assets boundary behavior ──────────────────────────────────────────

def _by_value(assets, value):
    return [a for a in assets if a.value == value]


def test_third_party_hop_suppressed_with_no_suffix_list_involved():
    """app.example.com -> waws-prod-xyz.cloudapp.azure.com (A record).
    cloudapp.azure.com is never named anywhere in dns_resolve.py anymore —
    it's suppressed purely because it isn't a declared target domain."""
    name_records = {
        "app.example.com": [
            {"type": "CNAME", "content": "waws-prod-xyz.cloudapp.azure.com"},
            {"type": "A", "content": "20.1.2.3"},
        ],
    }
    owned_domains = frozenset({"example.com"})

    assets = _emit_assets(name_records, "dns_resolve", "example.com", owned_domains)

    # The customer-owned CNAME hop, annotated as a boundary.
    boundary = _by_value(assets, "app.example.com")[0]
    assert boundary.asset_metadata["record_type"] == "CNAME"
    assert boundary.asset_metadata["content"] == "waws-prod-xyz.cloudapp.azure.com"
    assert boundary.asset_metadata["cdn"] is True
    assert boundary.asset_metadata["cdn_domain"] == "waws-prod-xyz.cloudapp.azure.com"

    # planning#147: the boundary TARGET is captured as context — but as a
    # bare node, with no record_type/content, because we deliberately never
    # resolved past it and must not invent an observation.
    captured = _by_value(assets, "waws-prod-xyz.cloudapp.azure.com")[0]
    assert captured.asset_metadata["third_party"] is True
    assert captured.asset_metadata["relationship"] == "dependency"
    assert captured.asset_metadata["discovered_via"] == "cname"
    assert "record_type" not in captured.asset_metadata
    assert "content" not in captured.asset_metadata
    assert captured.parent_value is None

    # The third-party IP is still suppressed — capture stops at the boundary.
    assert not _by_value(assets, "20.1.2.3")
    assert len(assets) == 2


def test_multihop_chain_boundary_on_first_out_of_scope_hop():
    """go.contoso.com -> go.pardot.com -> app-ue1-public.fe.pardot.com -> A.
    Boundary must land on the FIRST out-of-scope hop, not the terminal —
    otherwise the intermediate SaaS name gets misattributed as the
    customer's own record."""
    name_records = {
        "go.contoso.com": [
            {"type": "CNAME", "content": "go.pardot.com"},
            {"type": "CNAME", "content": "app-ue1-public.fe.pardot.com"},
            {"type": "A", "content": "10.10.10.10"},
        ],
    }
    owned_domains = frozenset({"contoso.com"})

    assets = _emit_assets(name_records, "dns_resolve", "contoso.com", owned_domains)

    owned = _by_value(assets, "go.contoso.com")[0]
    assert owned.asset_metadata["cdn_domain"] == "go.pardot.com"

    # planning#147: the FIRST out-of-scope hop is the captured node...
    captured = _by_value(assets, "go.pardot.com")[0]
    assert captured.asset_metadata["third_party"] is True

    # ...and nothing beyond it. Capturing the intermediate SaaS name is the
    # point; walking into the vendor's own estate is not.
    assert not _by_value(assets, "app-ue1-public.fe.pardot.com")
    assert not _by_value(assets, "10.10.10.10")
    assert len(assets) == 2


def test_cname_to_a_different_declared_target_is_not_suppressed():
    """A CNAME hop landing on a *different* target the same org has declared
    must NOT be treated as a boundary — owned_domains covers every declared
    target, not just this chain's own apex."""
    name_records = {
        "app.fabrikam.com": [
            {"type": "CNAME", "content": "svc.northwind.com"},
            {"type": "A", "content": "198.51.100.5"},
        ],
    }
    owned_domains = frozenset({"fabrikam.com", "northwind.com"})

    assets = _emit_assets(name_records, "dns_resolve", "fabrikam.com", owned_domains)

    assert _by_value(assets, "app.fabrikam.com")
    assert _by_value(assets, "svc.northwind.com")
    assert _by_value(assets, "198.51.100.5")
    # No hop was annotated as a suppressed boundary.
    assert all("cdn" not in a.asset_metadata for a in assets)
    # planning#147 acceptance: a CNAME to another declared target must not be
    # mis-captured as third-party. svc.northwind.com is a real owned record
    # here, not a context node — if this ever flips, the capture rule has
    # started eating the org's own cross-target CNAMEs (#125's failure mode).
    assert all(not a.asset_metadata.get("third_party") for a in assets)


def test_direct_a_record_under_own_domain_unaffected():
    """No CNAME hop at all — a literal, org-configured A record stays exactly
    as before even though the allowlist mechanism now exists."""
    name_records = {
        "mail.example.com": [
            {"type": "A", "content": "203.0.113.9"},
        ],
    }
    owned_domains = frozenset({"example.com"})

    assets = _emit_assets(name_records, "dns_resolve", "example.com", owned_domains)

    assert _by_value(assets, "mail.example.com")
    assert _by_value(assets, "203.0.113.9")
    assert all("cdn" not in a.asset_metadata for a in assets)
    assert all(not a.asset_metadata.get("third_party") for a in assets)


def test_bare_terminal_not_owned_is_dropped_entirely():
    """A name with no CNAME chain that itself isn't under any declared
    target (e.g. a stray CT hit) is dropped whole — there's no customer
    record to annotate or scan."""
    name_records = {
        "some-saas-tenant.example.net": [
            {"type": "A", "content": "192.0.2.44"},
        ],
    }
    owned_domains = frozenset({"example.com"})

    assets = _emit_assets(name_records, "dns_resolve", "example.com", owned_domains)

    assert assets == []
