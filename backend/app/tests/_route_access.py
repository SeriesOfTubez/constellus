"""Route-access introspection shared by the permission-parity tests.

`route_access` reports who may call a route, read off the dependency tree.
The baseline JSON in `fixtures/route_access_baseline.json` was generated from
the pre-catalogue code (`require_role`); `test_permissions.py` recomputes the
same mapping from `require_permission` and asserts equality (planning#243).
"""

from fastapi.routing import APIRoute

from app.api.deps import get_current_user
from app.models.user import UserRole

ALL_ROLES = sorted(r.value for r in UserRole)
SPA_CATCH_ALL = "/{full_path:path}"


def walk(dependant, _seen=None):
    """Yield every Dependant in the tree (including the root)."""
    _seen = _seen if _seen is not None else set()
    if id(dependant) in _seen:
        return
    _seen.add(id(dependant))
    yield dependant
    for d in dependant.dependencies:
        yield from walk(d, _seen)


def _role_closure(call):
    """The tuple of UserRole held by a `require_role` closure, else None."""
    if getattr(call, "__qualname__", "") != "require_role.<locals>.dependency":
        return None
    for cell in call.__closure__ or ():
        if isinstance(cell.cell_contents, tuple) and all(
            isinstance(r, UserRole) for r in cell.cell_contents
        ):
            return cell.cell_contents
    raise AssertionError("require_role closure holds no role tuple")


def route_access(route: APIRoute):
    nodes = list(walk(route.dependant))
    if not any(n.call is get_current_user for n in nodes):
        return "public"
    found = [r for r in (_role_closure(n.call) for n in nodes) if r is not None]
    if len(found) > 1:
        raise AssertionError(f"{route.path}: more than one role dependency")
    if found:
        return sorted(r.value for r in found[0])
    return list(ALL_ROLES)


def _flatten(candidates):
    """FastAPI >= 0.141 keeps included routers lazy (`_IncludedRouter`);
    their `effective_candidates()` carry the fully prefixed path, methods and
    dependant. Walk them down to the leaf route contexts."""
    for c in candidates:
        if hasattr(c, "effective_candidates"):
            yield from _flatten(c.effective_candidates())
        else:
            yield c


def iter_app_routes():
    """(method, path, route) for every mounted API route, one per method.

    `route` is the effective route (full mounted path); it exposes `.path`,
    `.methods` and `.dependant` like an `APIRoute`.
    """
    from app.main import app

    for route in _flatten(app.routes):
        if not isinstance(getattr(route, "original_route", route), APIRoute):
            continue
        if route.path == SPA_CATCH_ALL:
            continue
        for method in sorted(route.methods - {"HEAD", "OPTIONS"}):
            yield method, route.path, route
