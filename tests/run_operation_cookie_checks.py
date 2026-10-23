"""Every Apple operation starts without session cookies (both session modes),
persistent ones stay. Run: python tests/run_operation_cookie_checks.py"""
import os
import sys
import tempfile
import time

HOME = tempfile.mkdtemp()
os.environ["HOME"] = HOME
os.environ["USERPROFILE"] = HOME
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from requests.cookies import create_cookie  # noqa: E402

sys.argv = ["x"]
import app as appmod  # noqa: E402

for host, label in (("127.0.0.1", "local"), ("0.0.0.0", "browser")):
    flask_app = appmod.build_app(appmod.parse_args(["--host", host]))
    with flask_app.test_request_context("/api/versions"):
        flask_app.preprocess_request()
        from ipatool_api.routes.api import _service

        svc = _service()
        jar = svc._http.session.cookies
        jar.set_cookie(create_cookie("keep", "1", domain=".apple.com", path="/", expires=int(time.time()) + 3600))
        jar.set_cookie(create_cookie("hsaccnt", "1", domain=".apple.com", path="/"))  # session cookie
        svc._start_operation()
        names = {c.name for c in jar}
        assert names == {"keep"}, (label, names)
        print("cookies ok:", label)
print("OPERATION COOKIES OK")
