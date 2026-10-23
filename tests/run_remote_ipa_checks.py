"""Minimum OS from a remote IPA via range requests. Run: python tests/run_remote_ipa_checks.py"""
import io, os, plistlib, sys, zipfile, threading, re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from ipatool_api.services import remote_ipa

def ipa(min_os, zip64=False, stored=False, ext_first=True, big=0, platforms=("iPhoneOS",)):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED if stored else zipfile.ZIP_DEFLATED) as z:
        if ext_first:
            z.writestr("Payload/A.app/PlugIns/W.appex/Info.plist", plistlib.dumps({"MinimumOSVersion": "99.0"}))
        if big:
            z.writestr("Payload/A.app/blob.bin", os.urandom(big))
        info = {"CFBundleIdentifier": "x", "MinimumOSVersion": min_os, "CFBundleSupportedPlatforms": list(platforms)}
        with z.open("Payload/A.app/Info.plist", "w", force_zip64=zip64) as f:
            f.write(plistlib.dumps(info))
        for i in range(300):
            z.writestr(f"Payload/A.app/r/{i}.png", b"x" * 10)
    return buf.getvalue()

calls = []
def fetcher(data):
    def fetch(a, b):
        calls.append((a, b))
        return data[a:] if a < 0 else data[a:b + 1]
    return fetch

for args, want in [(("12.0",), ("iOS", "12.0")), (("15.4", True), ("iOS", "15.4")), (("9.0", False, True), ("iOS", "9.0")),
                   (("14.0", False, False, False, 300000), ("iOS", "14.0")), (("17.0",), ("iOS", "17.0"))]:
    calls.clear()
    got = remote_ipa.minimum_os(remote_ipa.read_info_plist(fetcher(ipa(*args))))
    assert got == want, (args, got); print("ok", args[:2], got, "requests:", len(calls))
print(remote_ipa.minimum_os({"CFBundleSupportedPlatforms": ["AppleTVOS"], "MinimumOSVersion": "16.0"}))

# through the real service path with a Range-capable server and one that ignores Range
DATA = {"/r.ipa": ipa("13.2"), "/norange.ipa": ipa("13.2")}
class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        body = DATA[self.path]; rng = self.headers.get("Range")
        if rng and rng.startswith("bytes=-"):  # like Apple's CDN: no suffix ranges
            self.send_response(501); self.send_header("Content-Length", "0"); self.end_headers(); return
        if rng and self.path == "/r.ipa":
            m = re.match(r"bytes=(\d+)-(\d+)", rng); a, b = int(m.group(1)), int(m.group(2))
            part = body[a:b + 1]
            self.send_response(206); self.send_header("Content-Length", str(len(part)))
            self.send_header("Content-Range", f"bytes {a}-{a + len(part) - 1}/{len(body)}"); self.end_headers(); self.wfile.write(part)
        else:
            self.send_response(200); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
srv = ThreadingHTTPServer(("127.0.0.1", 0), H); threading.Thread(target=srv.serve_forever, daemon=True).start()
port = srv.server_address[1]
import tempfile
os.environ["HOME"] = tempfile.mkdtemp(); os.environ["USERPROFILE"] = os.environ["HOME"]
from ipatool_api.services.models import App
import app as appmod
sys.argv = ["x"]
flask_app = appmod.build_app(appmod.parse_args(["--host", "127.0.0.1"]))
with flask_app.test_request_context():
    flask_app.preprocess_request()
    from ipatool_api.routes.api import _service
    svc = _service()
    a = App(id=1, bundle_id="x", name="x", version="1", price=0) if "price" in App.__dataclass_fields__ else App(id=1, bundle_id="x")
    print("range server:", svc._minimum_os(a, "100", f"http://127.0.0.1:{port}/r.ipa"))
    print("cached:", svc._minimum_os(a, "100", None))
    print("size known:", svc._minimum_os(a, "102", f"http://127.0.0.1:{port}/r.ipa", len(DATA["/r.ipa"])))
    assert svc._minimum_os(a, "102", None) == ("iOS", "13.2")
    print("no-range server:", svc._minimum_os(a, "101", f"http://127.0.0.1:{port}/norange.ipa"))
print("REMOTE IPA OK")
