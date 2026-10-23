"""Current-version lookup when apps.apple.com rate-limits (HTTP 429): no
caching of the 429, a short backoff, the last version seen as fallback.
Run: python tests/run_lookup_fallback_checks.py  (prints LOOKUP OK)
"""
import json
import os
import sys
import tempfile

HOME = tempfile.mkdtemp()
os.environ["HOME"] = HOME
os.environ["USERPROFILE"] = HOME
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from ipatool_api.services import appstore as appstore_mod  # noqa: E402
from ipatool_api.services.appstore import AppStoreService  # noqa: E402
from ipatool_api.services.errors import PlatformLookupEmptyError  # noqa: E402
from ipatool_api.services.models import Account, App  # noqa: E402

calls = []
mode = {"status": 429}


class FakeResponse:
    def __init__(self, status, payload=None):
        self.status_code = status
        self._payload = payload or {}
        self.text = ""

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            import requests

            err = requests.HTTPError(f"{self.status_code}")
            err.response = self
            raise err


def fake_get(url, **kwargs):
    calls.append(url)
    if "/api/apps/v1/catalog/" in url:
        if mode["status"] == 200:
            return FakeResponse(200, {"data": [{"id": "555", "type": "apps", "attributes": {"deviceFamilies": ["iphone"], "platformAttributes": {"ios": {
                "externalVersionId": 900, "bundleId": "com.x"}}}}]})
        return FakeResponse(mode["status"])
    return FakeResponse(mode["status"])  # the app page


appstore_mod.requests.get = fake_get
appstore_mod.time.sleep = lambda s: None


def empty_lookup(self, app, catalog, country):
    raise PlatformLookupEmptyError("platform version lookup returned no app")


AppStoreService._platform_version_lookup = empty_lookup

sys.argv = ["x"]
import app as appmod  # noqa: E402

flask_app = appmod.build_app(appmod.parse_args(["--host", "127.0.0.1"]))
account = Account(email="a@b.c", password_token="t", directory_services_id="1", name="A", store_front="143441-1,34",
                  password="")
app = App(id=555, bundle_id="com.x")

with flask_app.test_request_context():
    flask_app.preprocess_request()
    from ipatool_api.routes.api import _service

    svc = _service()
    # 1) rate-limited, nothing remembered: lookup fails, the site isn't hammered
    try:
        svc.lookup_latest_external_version_id(account, app, "iphone")
        raise AssertionError("expected a failure")
    except PlatformLookupEmptyError:
        pass
    assert svc.apps_site_rate_limited()
    catalog_calls = [c for c in calls if "/catalog/" in c]
    assert len(catalog_calls) == 2, catalog_calls  # one request + one short retry, then backoff
    calls.clear()
    try:
        svc.lookup_latest_external_version_id(account, app, "iphone")
    except PlatformLookupEmptyError:
        pass
    assert not calls, calls  # backoff: apps.apple.com not asked again

    # 2) the 429 wasn't cached as "not listed": once the block lifts, it's asked again
    appstore_mod._APPS_SITE_BACKOFF.discard("429")
    mode["status"] = 200
    assert svc.lookup_latest_external_version_id(account, app, "iphone") == "900"
    saved = json.load(open(os.path.join(HOME, ".ipatool", "known_versions.json")))
    assert saved["555"]["versionId"] == "900", saved

    # 3) rate-limited again, but the version is remembered: it's used
    appstore_mod._CATALOG_CACHE._data.clear()
    mode["status"] = 429
    assert svc.lookup_latest_external_version_id(account, app, "iphone") == "900"
    assert svc.arcade_latest_version_id(account, app) == "900"

    # 4) the newest id wins; older ones don't overwrite it
    svc._known_versions.remember(555, "950")
    svc._known_versions.remember(555, "700")
    assert svc._known_versions.get(555)[0] == "950"

# 5) the route explains the rate limit when nothing is remembered
from ipatool_api.services.errors import ArcadeNotSupportedError  # noqa: E402

AppStoreService.list_versions = lambda self, account, app, ext=None, platform="": (_ for _ in ()).throw(
    ArcadeNotSupportedError("Subscription Required"))
AppStoreService.is_arcade = lambda self, account, app: True
AppStoreService.list_versions_community = lambda self, app: type("O", (), {"entries": []})()
AppStoreService.account_info = lambda self: account
import ipatool_api.routes.api as api  # noqa: E402

api._resolve_supported_app = lambda params, account, version_key="externalVersionId": App(id=777, bundle_id="com.y")
api._resolve_external_version_id = lambda account, app, platform, value: value
appstore_mod._APPS_SITE_BACKOFF.set("429", True)
client = flask_app.test_client()
response = client.get("/api/versions?appId=777")
body = response.get_json()
assert response.status_code >= 400 and "rate-limiting" in body.get("error", ""), body
print("LOOKUP OK")
