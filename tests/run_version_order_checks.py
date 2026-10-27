"""Community versions come newest first (by version id, as in the private
catalog); app info from the public lookup; the App Store label only for the
version on sale now.
Run: python tests/run_version_order_checks.py  (prints VERSION ORDER OK)
"""
import os
import sys
import tempfile

HOME = tempfile.mkdtemp()
os.environ["HOME"] = HOME
os.environ["USERPROFILE"] = HOME
os.environ.setdefault("IPATOOL_NO_VAULT_OFFER", "1")
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from ipatool_api.services import appstore as appstore_mod  # noqa: E402
from ipatool_api.services.appstore import AppStoreService  # noqa: E402
from ipatool_api.services.models import Account, App, CommunityVersionEntry  # noqa: E402


def entry(vid, created):
    return CommunityVersionEntry(external_version_id=vid, bundle_version="v" + vid, created_at=created, source="timbrd")


AppStoreService._private_catalog_entries = lambda self, app: None
AppStoreService._community_source = lambda self, name, url, param, app: (
    [entry("100", "2024-05-01"), entry("900", "Jan 2 2023"), entry("30", None), entry("850", "2025-01-01")]
    if name == "timbrd" else [])
service = AppStoreService.__new__(AppStoreService)
ids = [e.external_version_id for e in service.list_versions_community(App(id=1)).entries]
assert ids == ["900", "850", "100", "30"], ids


class Result:
    def __init__(self, data):
        self.data = data


seen = []


def fake_send(self, request):
    seen.append(request.url)
    if "country=ru" in request.url:
        return Result({"results": []})
    return Result({"results": [{"trackId": 6478063606, "trackName": "DREDGE+", "bundleId": "com.blacksaltgames.dredgeplus",
                                "version": "1.2"}]})


AppStoreService._send_request = fake_send
account = Account(email="", password_token="", directory_services_id="", name="", store_front="143469-16,32")
info = service.app_info(account, app_id="6478063606")
assert info == {"name": "DREDGE+", "bundleId": "com.blacksaltgames.dredgeplus", "version": "1.2"}, info
assert "id=6478063606" in seen[0] and "country=us" in seen[-1], seen
assert service.app_info(account) == {"name": "", "bundleId": "", "version": ""}

# The App Store's own version label: only for the version on sale now.

history = {"2.2": "2025-05-01", "2.1": "2025-03-10", "2.0": "2025-01-20"}
AppStoreService._web_external_version_id = lambda self, account, app: "900"
AppStoreService._app_store_history_dates = lambda self, account, app: history
CATALOG = {}
AppStoreService._catalog_app = lambda self, app, cc, platform="iphone": CATALOG.get(cc)
sv = lambda vid, disp: service._store_version(account, App(id=1), vid)
# no catalog answer: the app's page (its current id + the newest history entry)
assert sv("900", "2.2.1") == "2.2" and sv("800", "2.1") == ""
# the catalog API wins: its id with its own label, or the public lookup's version
appstore_mod._CURRENT_LABEL_CACHE._data.clear()
CATALOG["ru"] = {"externalVersionId": "950", "versionDisplay": "3.0"}
assert sv("950", "3.0.4") == "3.0" and sv("900", "2.2.1") == ""
appstore_mod._CURRENT_LABEL_CACHE._data.clear()
CATALOG["ru"] = {"externalVersionId": "950", "versionDisplay": ""}
assert sv("950", "3.0.4") == "1.2"            # fake_send's lookup answer
assert service.current_store_version(account, App(id=1)) == ("950", "1.2")
# the catalog API's own label field
from ipatool_api.services.appstore import _parse_catalog_app  # noqa: E402
parsed = _parse_catalog_app({"data": [{"id": "1", "type": "apps", "attributes": {"deviceFamilies": ["iphone"],
    "platformAttributes": {"ios": {"externalVersionId": 950, "versionHistory": [{"versionDisplay": "3.0"}]}}}}]},
    App(id=1), "iphone")
assert parsed["externalVersionId"] == "950" and parsed["versionDisplay"] == "3.0", parsed
print("VERSION ORDER OK")
