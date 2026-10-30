"""Put capture-browser/ on sys.path so tests can `import capture.spool` (no Playwright)."""

import base64
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.fixture(autouse=True)
def _restore_environ():
    """worker._drop_store_env pops CAPTURE_S3_* from the real os.environ, which
    monkeypatch does not restore for keys it never set (CI's CAPTURE_S3_TEST_*)."""
    saved = dict(os.environ)
    yield
    os.environ.clear()
    os.environ.update(saved)


class _FakeCdp:
    def send(self, method, params=None):
        if method == "Page.captureScreenshot":
            return {"data": base64.b64encode(b"RIFF....WEBP").decode()}
        return {}  # Network.enable / Network.getCertificate (no tableNames -> cert None)


class _FakePage:
    url = "https://example.com/"

    def evaluate(self, expr):
        return "Mozilla/5.0 (X11; Linux) HeadlessChrome/999.0 Safari/537.36"

    def on(self, *a):
        pass

    def goto(self, *a, **kw):
        return None

    def wait_for_load_state(self, *a, **kw):
        pass

    def title(self):
        return "t"


class _FakeCtx:
    def __init__(self):
        self.routes = []

    def route(self, pattern, handler):
        self.routes.append((pattern, handler))

    def new_page(self):
        return _FakePage()

    def close(self):
        pass

    def new_cdp_session(self, page):
        return _FakeCdp()


class _FakeBrowser:
    def __init__(self):
        self.context_kwargs = []
        self.contexts = []
        self.launch_kwargs = []

    def new_context(self, **kw):
        self.context_kwargs.append(kw)
        ctx = _FakeCtx()
        self.contexts.append(ctx)
        return ctx

    def close(self):
        pass


@pytest.fixture
def fake_playwright(monkeypatch):
    """Fake only the Playwright transport (sync_playwright -> chromium.launch ->
    browser.new_context); capture.run, capture_page and new_context are REAL."""
    import types

    browser = _FakeBrowser()

    class _P:
        chromium = types.SimpleNamespace(
            launch=lambda **kw: (browser.launch_kwargs.append(kw), browser)[1]
        )

    class _CM:
        def __enter__(self):
            return _P()

        def __exit__(self, *a):
            return False

    mod = types.ModuleType("playwright.sync_api")
    for name in ("Browser", "BrowserContext", "Playwright"):
        setattr(mod, name, object)
    mod.sync_playwright = lambda: _CM()
    monkeypatch.setitem(sys.modules, "playwright", types.ModuleType("playwright"))
    monkeypatch.setitem(sys.modules, "playwright.sync_api", mod)
    monkeypatch.setenv("CAPTURE_PROXY_URL", "http://proxy.example.test:3128")
    sys.modules.pop("capture.run", None)  # re-import against the fake
    yield browser
    sys.modules.pop("capture.run", None)  # never leak a fake-bound module
