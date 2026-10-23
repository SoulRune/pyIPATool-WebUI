"""GitHubCatalog.read_path / write_path (the collector's app list file), with
a fake GitHub API. Run: python tests/run_catalog_path_checks.py"""
import base64
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from ipatool_api.services import catalog  # noqa: E402

FILES = {}
CALLS = []


class Resp:
    def __init__(self, status, body=None):
        self.status_code, self._body, self.text = status, body or {}, json.dumps(body or {})

    def json(self):
        return self._body


class FakeSession:
    headers = {}

    def get(self, url, params=None, timeout=None, verify=None):
        CALLS.append(("GET", url))
        path = url.split("/contents/", 1)[1]
        if path not in FILES:
            return Resp(404)
        content, sha = FILES[path]
        return Resp(200, {"encoding": "base64", "content": base64.b64encode(content).decode(), "sha": sha})

    def put(self, url, json=None, timeout=None, verify=None):
        CALLS.append(("PUT", url, json["message"]))
        path = url.split("/contents/", 1)[1]
        if path in FILES and json.get("sha") != FILES[path][1]:
            return Resp(409)
        sha = f"s{len(CALLS)}"
        FILES[path] = (base64.b64decode(json["content"]), sha)
        return Resp(201, {"content": {"sha": sha}})


repo = catalog.GitHubCatalog("me/cat", "tok", "main", "apps")
repo._session = FakeSession()
assert repo.read_path("collector/apps.json") == (None, None)
sha = repo.write_path("collector/apps.json", {"apps": [{"spec": "1"}]}, None, "app list: 1 app")
doc, got = repo.read_path("/collector//apps.json")          # slashes normalised
assert doc == {"apps": [{"spec": "1"}]} and got == sha, (doc, got)
try:
    repo.write_path("collector/apps.json", {"apps": []}, "stale", "x")
    raise AssertionError("expected a conflict")
except catalog.CatalogError as exc:
    assert str(exc) == "conflict"
for bad in ("../secrets.json", "a/../../b", ""):
    try:
        repo.read_path(bad)
        raise AssertionError(bad)
    except catalog.CatalogError:
        pass
# per-app files still go to <prefix>/<id>.json
repo.write(42, {"appId": 42, "versions": {}}, None, "app 42")
assert repo.read(42)[0]["appId"] == 42 and "apps/42.json" in FILES
print("CATALOG PATH OK")
