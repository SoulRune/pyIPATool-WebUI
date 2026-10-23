"""Offline end-to-end checks of the web UI against a faked Apple backend.

Run: python tests/run_webui_checks.py  (prints ALL OK)
"""
import io, os, sys, plistlib, tempfile, time, zipfile
HOME = tempfile.mkdtemp(); os.environ["HOME"] = HOME; os.environ["USERPROFILE"] = HOME
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from ipatool_api.services import session_crypto as sc
from ipatool_api.services.appstore import AppStoreService
from ipatool_api.services.http_client import HTTPResult
from ipatool_api.services.models import BagOutput, SAPConfig

# ---- crypto: both backends, tamper detection
for backend in ("aes", "stdlib"):
    saved = sc.AESGCM
    if backend == "stdlib": sc.AESGCM = None
    c = sc.SessionCipher(os.urandom(32))
    blob = c.seal(b"hello world" * 50)
    assert c.open(blob) == b"hello world" * 50
    bad = bytearray(blob); bad[-5] ^= 1
    try: c.open(bytes(bad)); raise SystemExit("tamper not detected")
    except sc.SessionDecryptError: pass
    other = sc.SessionCipher(os.urandom(32))
    try: other.open(blob); raise SystemExit("wrong key accepted")
    except sc.SessionDecryptError: pass
    sc.AESGCM = saved
    print("crypto ok:", backend)
# cross-format: stdlib-sealed opens when AES available
k=os.urandom(32); sc_saved=sc.AESGCM; sc.AESGCM=None; b=sc.SessionCipher(k).seal(b"x"); sc.AESGCM=sc_saved
assert sc.SessionCipher(k).open(b)==b"x"; print("cross-format ok")

from ipatool_api.services.models import SearchOutput
# ---- fake Apple
def make_ipa(path):
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("Payload/Foo.app/Info.plist", plistlib.dumps({"CFBundleExecutable": "Foo"}))
        z.writestr("Payload/Foo.app/Foo", os.urandom(200000))
        z.writestr("Payload/Foo.app/PlugIns/Ext.appex/Info.plist", plistlib.dumps({"CFBundleExecutable": "Ext"}))
SRC_IPA = os.path.join(HOME, "src.ipa"); make_ipa(SRC_IPA)

def fake_bag(self): return BagOutput(auth_endpoint="https://buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/authenticate", sap=SAPConfig("https://s/","https://c/",200))
SIGNED=[]
class FakeSigner:
    def sign(self, body): SIGNED.append(body); return b"SIG"
    def close(self): pass
AppStoreService._create_signer=lambda self, cfg, hw: FakeSigner()
def fake_send(self, request, allow_decode_error=False):
    if "authenticate" in request.url:
        assert request.signer is not None, "login must be signed"
        request.signer(request.payload.serialize()[0])
        body = plistlib.loads(request.payload.serialize()[0])
        if body["password"] == "needs2fa":
            return HTTPResult(200, {}, {"customerMessage": "MZFinance.BadLogin.Configurator_message"})
        from requests.cookies import create_cookie; import time as _t
        self._http.session.cookies.set_cookie(create_cookie("mz_at0-123", "C" * 400, domain=".apple.com", path="/", expires=int(_t.time()) + 86400))
        self._http.session.cookies.set_cookie(create_cookie("hsaccnt", "1", domain=".apple.com", path="/WebObjects"))  # session cookie
        self._http._cookie_store.save()
        return HTTPResult(200, {"X-Set-Apple-Store-Front": "143443-1,29", "pod": "25"},
                          {"passwordToken": "SECRET_TOKEN_123", "dsPersonId": "123",
                           "accountInfo": {"appleId": body["appleId"], "address": {"firstName": "Ann", "lastName": "B"}}})
    if "itunes.apple.com/lookup" in request.url:
        # Arcade check: app 777 plays an Apple Arcade game (no price at all);
        # everything else is an ordinary free app.
        app_id = request.url.split("id=")[1].split("&")[0]
        item = {"trackId": int(app_id), "kind": "software", "bundleId": "com.example.foo", "trackName": "Foo"}
        if app_id != "777":
            item.update(price=0.0, formattedPrice="Free")
        return HTTPResult(200, {}, {"resultCount": 1, "results": [item]})
    raise AssertionError(request.url)
def fake_dl_req(self, account, app, guid, ext, platform=""):
    DL_VERSIONS.append((int(app.id), ext))
    return HTTPResult(200, {}, {"songList": [{"URL": "https://x/y", "metadata": {"bundleShortVersionString": "1.2", "softwareVersionBundleId": "com.example.foo", "itemName": "Foo App", "softwareVersionExternalIdentifiers": [1,2], "softwareVersionExternalIdentifier": 2},
                                              "sinfs": [{"id": 0, "sinf": b"SINFDATA"}]}]})
def fake_file(self, url, dest, on_progress=None):
    import shutil; shutil.copy(SRC_IPA, dest); on_progress and on_progress(10, 10)
AppStoreService.bag = fake_bag
# App Store catalog API (ipatool e3932ce): app 777 is an Arcade game whose
# current version is 999; anything else isn't listed (-> iTunes lookup check).
AppStoreService._catalog_app = lambda self, app, country, platform="iphone": (
    {"externalVersionId": "999", "bundleId": "com.example.foo", "supportsArcade": True} if int(app.id) == 777 else None)
DL_VERSIONS = []
AppStoreService._send_request = fake_send
AppStoreService._send_download_request = fake_dl_req
AppStoreService._download_file = fake_file
AppStoreService._minimum_os = lambda self, app, version_id, url, size=None: ("iOS", "15.0")  # no CDN in tests

sys.argv = ["x"]
import app as appmod

def mkapp(*argv):
    args = appmod.parse_args(list(argv))
    return appmod.build_app(args)

# ---- browser mode
bapp = mkapp("--host", "0.0.0.0")
A = bapp.test_client(); B = bapp.test_client()
J = {"Content-Type": "application/json"}
r = A.post("/api/auth/login", json={"email": "ann@example.com", "password": "pw"})
assert r.status_code == 200, r.get_json()
assert "password" not in r.get_json()["account"] and "passwordToken" not in r.get_json()["account"], r.get_json()
setc = r.headers.getlist("Set-Cookie"); print("cookies set:", [c.split("=")[0] for c in setc], "size", sum(len(c) for c in setc))
assert all("HttpOnly" in c and "SameSite=Lax" in c for c in setc)
assert not any("SECRET_TOKEN" in c or "ann@example.com" in c or "CCCC" in c for c in setc)
assert A.get("/api/account").status_code == 200
assert A.get("/api/account").get_json()["account"] == {"email": "ann@example.com", "name": "Ann B", "storeFront": "143443-1,29"}
assert B.get("/api/account").get_json()["account"] is None
assert not os.path.exists(os.path.join(HOME, ".ipatool", "keychain.json")), "browser mode must not write keychain"
print("browser isolation ok")

# state round trip: Apple cookie and guid persisted
with bapp.test_request_context(headers={"Cookie": "; ".join(f"{c.key}={c.value}" for c in A._cookies.values())}):
    from flask import request
    st = bapp.config["SESSION_CODEC"].load(request.cookies)
    assert st.load_account().password_token == "SECRET_TOKEN_123"
    assert any(c.name == "mz_at0-123" for c in st.cookies.jar)
    assert not any(c.name == "hsaccnt" for c in st.cookies.jar), "session cookies must not outlive the request"
    assert st._guid and len(st._guid) == 12
print("cookie roundtrip ok")

# tampered cookie -> logged out, cookie deleted
C = bapp.test_client()
C.set_cookie("ipatool_s0", "AAAA" + "x" * 100)
r = C.get("/api/account"); assert r.status_code == 200 and r.get_json()["account"] is None
assert any("ipatool_s0=;" in h for h in r.headers.getlist("Set-Cookie")), r.headers
print("tamper handling ok")

# 2FA required keeps session (guid) for the next attempt
D = bapp.test_client()
r = D.post("/api/auth/login", json={"email": "d@x.com", "password": "needs2fa"})
assert r.status_code == 401 and r.get_json()["authCodeRequired"]
assert r.headers.getlist("Set-Cookie"), "guid must persist between 2FA steps"
print("2fa flow ok")

# CSRF
assert A.post("/api/purchase", data='{"appId":1}', headers={"Content-Type": "text/plain"}).status_code == 415
assert A.post("/api/purchase", json={"appId": 1}, headers={"Origin": "http://evil.example"}).status_code == 403
assert A.post("/api/auth/logout", data="", headers={"Content-Type": "text/plain"}).status_code == 415
print("csrf ok")

# validation
assert A.get("/api/search?term=x&limit=abc").status_code == 400

# downloads + ownership
r = A.post("/api/download-jobs", json={"appId": 42, "externalVersionId": "2", "saveToServerFolder": True})
assert r.status_code == 403, "server save must be off in browser mode"
r = A.post("/api/download-jobs", json={"appId": 42, "externalVersionId": "2"})
jid = r.get_json()["jobId"]
for _ in range(50):
    j = A.get(f"/api/download-jobs/{jid}").get_json()
    if j["status"] in ("ready", "error"): break
    time.sleep(0.1)
assert j["status"] == "ready", j
assert B.get(f"/api/download-jobs/{jid}").status_code == 404
assert B.get(f"/api/download-jobs/{jid}/file").status_code == 404
f = A.get(f"/api/download-jobs/{jid}/file")
assert f.status_code == 200 and "filename*=" in f.headers["Content-Disposition"], f.headers
z = zipfile.ZipFile(io.BytesIO(f.data)); names = z.namelist()
assert z.testzip() is None
assert "iTunesMetadata.plist" in names and "Payload/Foo.app/SC_Info/Foo.sinf" in names, names
assert z.read("Payload/Foo.app/SC_Info/Foo.sinf") == b"SINFDATA"
md = plistlib.loads(z.read("iTunesMetadata.plist")); assert md["apple-id"] == "ann@example.com"
assert not [n for n in os.listdir(os.path.join(HOME, ".ipatool", "temp_downloads", jid)) if n.endswith(".part")]
print("download job ok:", names)

# logout clears
r = A.post("/api/auth/logout", json={})
assert r.status_code == 200 and any("ipatool_s0=;" in h for h in r.headers.getlist("Set-Cookie"))
assert A.get("/api/account").get_json()["account"] is None
print("logout ok")

# ---- local mode
lapp = mkapp("--host", "127.0.0.1")
L = lapp.test_client()
assert L.get("/", headers={"Host": "evil.example:5002"}).status_code == 400
assert L.get("/", headers={"Host": "localhost:5002"}).status_code == 200
assert L.get("/", headers={"Host": "127.0.0.1:5002"}).status_code == 200
assert L.get("/", headers={"Host": "[::1]:5002"}).status_code == 200
print("trusted hosts ok")
r = L.post("/api/auth/login", json={"email": "loc@example.com", "password": "pw"}, headers={"Host": "localhost:5002"})
assert r.status_code == 200 and "password" not in r.get_json()["account"]
kc = os.path.join(HOME, ".ipatool", "keychain.json")
assert os.path.exists(kc) and oct(os.stat(kc).st_mode & 0o777) == "0o600", oct(os.stat(kc).st_mode)
assert oct(os.stat(os.path.join(HOME, ".ipatool", "cookies.lwp")).st_mode & 0o777) == "0o600"
r = L.post("/api/download-jobs", json={"appId": 42, "externalVersionId": "2", "saveToServerFolder": True}, headers={"Host": "localhost"})
jid = r.get_json()["jobId"]
for _ in range(50):
    j = L.get(f"/api/download-jobs/{jid}", headers={"Host": "localhost"}).get_json()
    if j["status"] in ("ready", "error"): break
    time.sleep(0.1)
assert j["status"] == "ready" and j["serverPath"].endswith(".ipa"), j
assert os.path.exists(os.path.join(HOME, "Downloads", "IPATool", "42_1.2.ipa"))
r = L.post("/api/download", json={"appId": 42, "outputPath": "/tmp/evil"}, headers={"Host": "localhost"})
assert r.status_code == 200 and "Downloads" in r.get_json()["destinationPath"] and not os.path.exists("/tmp/evil")
print("local mode ok")

# index renders with the right hint / class
html = A.get("/").data.decode()
assert "no-server-save" in html and "encrypted cookie" in html
html = L.get("/", headers={"Host": "localhost"}).data.decode()
assert "no-server-save" not in html and "Local mode" in html
assert SIGNED, "no signed request"

# ---- Apple Arcade: normal flow; community fallback only if Apple refuses the list
X = mkapp("--host", "0.0.0.0").test_client()
assert X.post("/api/auth/login", json={"email": "ann@example.com", "password": "pw"}).status_code == 200
r = X.get("/api/versions?appId=777")
assert r.status_code == 200 and r.get_json().get("externalVersionIdentifiers"), ("Arcade versions go through Apple", r.get_json())
assert X.get("/api/version-metadata?appId=777&versionId=5").status_code == 200, "older Arcade versions aren't blocked"
assert X.get("/api/version-metadata?appId=777&versionId=5").get_json()["minimumOsVersion"] == "15.0"
_orig_lv = AppStoreService.list_versions
def _refusing(self, account, app, *a, **k):
    if int(app.id) == 777:
        from ipatool_api.services.errors import AppStoreError
        raise AppStoreError("an unknown error has occurred")
    return _orig_lv(self, account, app, *a, **k)
AppStoreService.list_versions = _refusing
_orig_comm0 = AppStoreService.list_versions_community
AppStoreService.list_versions_community = lambda self, app: (_ for _ in ()).throw(__import__("ipatool_api.services.errors", fromlist=["x"]).AppStoreError("offline"))
j = X.get("/api/versions?appId=777").get_json()
assert j.get("arcade") is True and j.get("arcadeLatestVersionId") == "999", j
assert "license" not in j["error"].lower(), "Arcade message must not trigger the UI's license flow"
def _not_subscribed(self, account, app, *a, **k):
    from ipatool_api.services.errors import ArcadeRefusedError, ARCADE_NOT_SUBSCRIBED_MESSAGE
    raise ArcadeRefusedError(ARCADE_NOT_SUBSCRIBED_MESSAGE, metadata={"customerMessage": "Subscription Required"})
AppStoreService.list_versions = _not_subscribed
r = X.get("/api/versions?appId=777"); j = r.get_json()
assert j.get("arcade") is True and not j.get("licenseRequired") and j.get("arcadeLatestVersionId") == "999", j
# pinned to an older version Apple answers the list (probing community ids)
from ipatool_api.services.models import CommunityVersionsOutput, CommunityVersionEntry, ListVersionsOutput
import inspect
_fields = [p for p in inspect.signature(CommunityVersionEntry).parameters]
def _entry(v):
    kw = {f: None for f in _fields}; kw["external_version_id"] = v
    return CommunityVersionEntry(**kw)
_orig_comm = AppStoreService.list_versions_community
AppStoreService.list_versions_community = lambda self, app: CommunityVersionsOutput(source="timbrd", entries=[_entry("7"), _entry("3"), _entry("5")])
PROBES = []
def _pinned_only(self, account, app, version=None, platform=""):
    PROBES.append(version)
    if str(version) == "5":
        return ListVersionsOutput(external_version_identifiers=["3", "5", "999"], latest_external_version_id="5")
    from ipatool_api.services.errors import ArcadeRefusedError, ARCADE_NOT_SUBSCRIBED_MESSAGE
    raise ArcadeRefusedError(ARCADE_NOT_SUBSCRIBED_MESSAGE)
AppStoreService.list_versions = _pinned_only
j = X.get("/api/versions?appId=777").get_json()
assert j.get("arcadeProbeVersionId") == "5" and j["externalVersionIdentifiers"] == ["3", "5", "999"], (j, PROBES)
assert PROBES[:3] == [None, "7", "5"], PROBES
AppStoreService.list_versions_community = _orig_comm
AppStoreService.list_versions = _orig_lv
_orig_purchase = AppStoreService._purchase_with_params
AppStoreService._purchase_with_params = lambda self, account, app, guid, pricing: None
assert X.post("/api/purchase", json={"appId": 777}).status_code == 200, "Arcade games can be added to the account"
AppStoreService._purchase_with_params = _orig_purchase
DL_VERSIONS.clear()
r = X.post("/api/download-jobs", json={"appId": 777, "externalVersionId": "5"})
assert r.status_code in (200, 202), r.get_json()
job_id = r.get_json()["jobId"]
for _ in range(100):
    st = X.get(f"/api/download-jobs/{job_id}").get_json()
    if st.get("status") in ("ready", "error", "failed"):
        break
    time.sleep(0.05)
assert (777, "5") in DL_VERSIONS, ("older Arcade versions are requested from Apple", DL_VERSIONS, st)
r = X.get("/api/versions?appId=42")
assert r.get_json().get("arcade") is None, "ordinary apps must not be flagged as Arcade"

# ---- search region
seen_countries = []
_orig_search = AppStoreService.search
AppStoreService.search = lambda self, acc, term, limit, include_tvos=False, platform="", country="": (
    seen_countries.append(country) or SearchOutput(count=0, results=[]))
assert X.get("/api/search?term=x&country=us").status_code == 200
assert X.get("/api/search?term=x").status_code == 200
assert X.get("/api/search?term=x&country=ZZ").status_code == 400, "unknown regions are rejected"
assert seen_countries == ["US", ""], seen_countries
AppStoreService.search = _orig_search
print("ALL OK")
