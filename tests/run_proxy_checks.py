"""Behind a reverse proxy (--behind-proxy, listening on loopback): every
browser signs in separately (not one shared account), the Host check uses the
name the proxy forwards, and cookies are Secure when the proxy speaks HTTPS."""
import os
import sys
import tempfile

HOME = tempfile.mkdtemp()
os.environ["HOME"] = HOME
os.environ["USERPROFILE"] = HOME
os.environ.setdefault("IPATOOL_NO_VAULT_OFFER", "1")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import app as appmod  # noqa: E402


def mkapp(*argv):
    return appmod.build_app(appmod.parse_args(list(argv)))


assert mkapp("--host", "127.0.0.1").config["SESSION_MODE"] == "local"
app = mkapp("--host", "127.0.0.1", "--behind-proxy", "--trusted-host", "ipa.example.org")
assert app.config["SESSION_MODE"] == "browser"
from flask import jsonify, request  # noqa: E402


@app.get("/_proxy_probe")
def _proxy_probe():
    return jsonify({"secure": request.is_secure, "host": request.host, "ip": request.remote_addr})


client = app.test_client()
proxied = {"Host": "127.0.0.1:5002", "X-Forwarded-Host": "ipa.example.org", "X-Forwarded-Proto": "https",
           "X-Forwarded-For": "203.0.113.7"}
assert client.get("/", headers=proxied).status_code == 200
assert client.get("/", headers={**proxied, "X-Forwarded-Host": "evil.example"}).status_code == 400
probe = client.get("/_proxy_probe", headers=proxied).get_json()
assert probe == {"secure": True, "host": "ipa.example.org", "ip": "203.0.113.7"}, probe
# Plain HTTP at the proxy: pages are redirected to HTTPS, data is refused, HTTPS gets HSTS.
plain = {**proxied, "X-Forwarded-Proto": "http"}
r = client.get("/?x=1", headers=plain)
assert r.status_code == 301 and r.headers["Location"] == "https://ipa.example.org/?x=1", r.headers.get("Location")
assert client.post("/api/auth/login", json={"email": "a", "password": "b"}, headers=plain).status_code == 403
assert "max-age" in client.get("/", headers=proxied).headers.get("Strict-Transport-Security", "")
open_app = mkapp("--host", "127.0.0.1", "--behind-proxy", "--allow-http")
assert open_app.test_client().get("/", headers={"Host": "127.0.0.1", "X-Forwarded-Proto": "http"}).status_code == 200
# Under a path on a shared domain (nginx: location /ipa/ + X-Forwarded-Prefix /ipa)
prefixed = {**proxied, "X-Forwarded-Prefix": "/ipa"}
page = client.get("/", headers=prefixed).get_data(as_text=True)
assert 'window.APP_BASE_URL = "/ipa"' in page and 'href="/ipa/static/' in page.replace("legacy", ""), page[:600]
assert 'href="/ipa/source"' in page
r = client.get("/?x=1", headers={**prefixed, "X-Forwarded-Proto": "http"})
assert r.headers["Location"] == "https://ipa.example.org/ipa/?x=1", r.headers["Location"]
# The real server (waitress) must pass the proxy's X-Forwarded-* headers on
# (it strips them by default) - otherwise every page would bounce to HTTPS.
import socket  # noqa: E402
import subprocess  # noqa: E402
import time  # noqa: E402
import urllib.request  # noqa: E402

sock = socket.socket()
sock.bind(("127.0.0.1", 0))
port = sock.getsockname()[1]
sock.close()
env = dict(os.environ, HOME=tempfile.mkdtemp(), IPATOOL_NO_VAULT_OFFER="1", NO_PROXY="*", no_proxy="*")
root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
server = subprocess.Popen([sys.executable, "app.py", "--host", "127.0.0.1", "--port", str(port), "--behind-proxy",
                           "--trusted-host", "ipa.example.org", "--server", "waitress"], cwd=root, env=env,
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


opener.add_handler(NoRedirect())
try:
    for _ in range(60):
        try:
            probe_request = urllib.request.Request(f"http://127.0.0.1:{port}/source", headers={
                "Host": "ipa.example.org", "X-Forwarded-Proto": "https", "X-Forwarded-For": "203.0.113.9"})
            status = opener.open(probe_request, timeout=5).status
            break
        except urllib.error.HTTPError as exc:
            status = exc.code
            break
        except OSError:
            time.sleep(0.5)
    assert status == 200, f"waitress dropped X-Forwarded-Proto (got {status})"
finally:
    server.terminate()
    server.wait(10)
print("PROXY OK")
