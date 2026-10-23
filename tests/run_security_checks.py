"""Public-server protections: the access password (gate, cookie, brute-force
limit, no open redirect, OTA links and /source stay open), the per-IP limit on
Apple sign-ins, /source packing only code, the disk-space check."""
import os
import sys
import tempfile
from pathlib import Path

HOME = tempfile.mkdtemp()
os.environ["HOME"] = HOME
os.environ["USERPROFILE"] = HOME
os.environ.setdefault("IPATOOL_NO_VAULT_OFFER", "1")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import app as appmod  # noqa: E402
from ipatool_api.routes import ui  # noqa: E402
from ipatool_api.services import appstore  # noqa: E402
from ipatool_api.services.errors import AppStoreError  # noqa: E402

secret_file = Path(HOME) / "access.txt"
secret_file.write_text("correct horse battery\n", encoding="utf-8")
app = appmod.build_app(appmod.parse_args(["--host", "127.0.0.1", "--behind-proxy", "--trusted-host", "ipa.example.org",
                                          "--access-password-file", str(secret_file)]))
assert app.config["SESSION_MODE"] == "browser" and app.config.get("ACCESS_GATE")


def headers(ip="198.51.100.1"):
    return {"Host": "127.0.0.1", "X-Forwarded-Host": "ipa.example.org", "X-Forwarded-Proto": "https",
            "X-Forwarded-For": ip}


c = app.test_client()
r = c.get("/", headers=headers())
assert r.status_code == 302 and "/access" in r.headers["Location"], (r.status_code, r.headers.get("Location"))
assert c.get("/api/account", headers=headers()).status_code == 401
assert c.get("/source", headers=headers()).status_code == 200
assert c.get("/static/css/style.css", headers=headers()).status_code == 200
assert c.get("/ota/nojob/notoken/manifest.plist", headers=headers()).status_code == 404  # not gated, just unknown
page = c.get("/access", headers=headers())
assert page.status_code == 200 and b'type="password"' in page.data

# wrong passwords: 403, then 429 after 8 tries from one address
for _ in range(8):
    assert c.post("/access", data={"password": "nope"}, headers=headers()).status_code == 403
assert c.post("/access", data={"password": "correct horse battery"}, headers=headers()).status_code == 429
# another address, right password: cookie, back to a local page only
r = c.post("/access", data={"password": "correct horse battery", "next": "//evil.example/x"},
           headers=headers("198.51.100.2"))
assert r.status_code == 302 and r.headers["Location"].endswith("/") and "evil" not in r.headers["Location"], r.headers
cookie = r.headers["Set-Cookie"]
assert "ipatool_access=" in cookie and "HttpOnly" in cookie and "Secure" in cookie and "SameSite=Lax" in cookie
assert c.get("/", headers=headers("198.51.100.2")).status_code == 200
assert c.get("/api/account", headers=headers("198.51.100.2")).status_code == 200
# a forged cookie doesn't pass
c2 = app.test_client()
c2.set_cookie("ipatool_access", "9999999999.deadbeef", domain="ipa.example.org")
assert c2.get("/", headers=headers("198.51.100.3")).status_code == 302

# Apple sign-ins: at most 10 per 10 min per address (each runs the emulator)
J = {**headers("198.51.100.2"), "Content-Type": "application/json", "Origin": "https://ipa.example.org"}
codes = [c.post("/api/auth/login", json={}, headers=J).status_code for _ in range(11)]
assert codes[:10] == [400] * 10 and codes[10] == 429, codes

# /source: code and documentation only
for name, wanted in (("vault.py", True), ("session_crypto.py", True), ("LICENSE", True), ("README.md", True),
                     ("github-token.txt", False), ("master-password.txt", False), ("secrets.json", False),
                     ("server.key", False), ("cert.pem", False), (".env", False), ("app.log", False),
                     ("App.ipa", False), ("requirements.txt", True)):
    assert ui._source_file_wanted(name) is wanted, name

# disk: a download that wouldn't fit (twice the package + the reserve) is refused up front
try:
    appstore._check_disk_space(Path(HOME) / "x.ipa", 1 << 50, 1 << 50)
    raise AssertionError("expected a refusal")
except AppStoreError as exc:
    assert "not enough free disk space" in str(exc)
appstore._check_disk_space(Path(HOME) / "x.ipa", 1 << 20, 1 << 20)
# under a path prefix the gate sends back to the prefixed page
c3 = app.test_client()
pre = {**headers("198.51.100.4"), "X-Forwarded-Prefix": "/ipa"}
r = c3.get("/versions?x=1", headers=pre)
assert r.status_code == 302 and "/ipa/access?next=/ipa/versions" in r.headers["Location"].replace("%2F", "/").replace("%3F", "?"), r.headers["Location"]
r = c3.post("/access", data={"password": "correct horse battery"}, headers=pre)
assert r.headers["Location"].endswith("/ipa/"), r.headers["Location"]

# IPv6: limits per /64 (addresses inside one are free to rotate)
from ipatool_api import access  # noqa: E402

with app.test_request_context("/", environ_base={"REMOTE_ADDR": "2001:db8:1:2:aaaa::1"}):
    first = access.client_ip()
with app.test_request_context("/", environ_base={"REMOTE_ADDR": "2001:db8:1:2:bbbb::9"}):
    assert access.client_ip() == first == "2001:db8:1:2::/64"
with app.test_request_context("/", environ_base={"REMOTE_ADDR": "::ffff:198.51.100.9"}):
    assert access.client_ip() == "198.51.100.9"
print("SECURITY OK")
