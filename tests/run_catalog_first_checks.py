"""/api/versions/catalog ("Private catalog first") and /api/cache/clear.
Run: python tests/run_catalog_first_checks.py  (prints CATALOG FIRST OK)"""
import os
import sys
import tempfile

HOME = tempfile.mkdtemp()
os.environ["HOME"] = HOME
os.environ["USERPROFILE"] = HOME
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from ipatool_api.services import appstore as appstore_mod  # noqa: E402
from ipatool_api.services.appstore import AppStoreService  # noqa: E402
from ipatool_api.services.models import Account  # noqa: E402


def fake_login(self, email, password, auth_code=None, rotate_session=True):
    account = Account(email=email, password_token="T", directory_services_id="1", name="A",
                      store_front="143441-1,34", password=password)
    self._persist_account(account)
    return account


AppStoreService.login = fake_login
AppStoreService.BUILTIN_CATALOG = dict(AppStoreService.BUILTIN_CATALOG, repo="")  # checked without the built-in one
from ipatool_api.services import catalog  # noqa: E402

sys.argv = ["x"]
import app as appmod  # noqa: E402

client = appmod.build_app(appmod.parse_args(["--host", "127.0.0.1"])).test_client()
assert client.post("/api/auth/login", json={"email": "ann@example.com", "password": "pw"}).status_code == 200
assert client.get("/api/versions/catalog?appId=555").get_json() == {
    "configured": False, "found": False, "updatedAt": "", "bundleId": "", "entries": []}
assert "catalogFirst" not in client.get("/").get_data(as_text=True)  # no checkbox without a catalog

reads = []


class FakeCatalog:
    def read(self, app_id):
        reads.append(app_id)
        doc = {"appId": 555, "bundleId": "com.x", "updatedAt": "2026-10-20T10:00:00Z", "versions": {
            "900": {"status": "ok", "version": "2.0", "build": "200", "minimumOs": "15.0"},
            "800": {"status": "lost"}}}
        return (doc if int(app_id) == 555 else None), None

    def describe(self):
        return "fake"


catalog._catalog = FakeCatalog()
assert "catalogFirst" in client.get("/").get_data(as_text=True)
body = client.get("/api/versions/catalog?appId=555").get_json()
assert body["found"] and body["updatedAt"].startswith("2026-10-20") and body["bundleId"] == "com.x", body
assert [(e["externalVersionId"], e["status"], e["build"], e["minimumOs"]) for e in body["entries"]] == [
    ("900", "ok", "200", "15.0"), ("800", "lost", None, None)], body["entries"]
assert client.get("/api/versions/catalog?appId=777").get_json()["found"] is False
client.get("/api/versions/catalog?appId=555")
assert reads.count(555) == 1, reads  # cached
appstore_mod._MIN_OS_CACHE.set(("1", "2"), ("iOS", "1"))
cleared = client.post("/api/cache/clear", json={}).get_json()["cleared"]
assert cleared >= 3, cleared  # two catalog files + the minimum-OS entry
client.get("/api/versions/catalog?appId=555")
assert reads.count(555) == 2, reads  # read again after clearing
assert appstore_mod._MIN_OS_CACHE.get(("1", "2")) is None
print("CATALOG FIRST OK")
