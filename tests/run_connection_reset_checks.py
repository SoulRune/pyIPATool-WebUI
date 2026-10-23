"""A dropped / refused connection: the kept-alive connections are thrown away
and the request is tried once more on new ones (as after a restart); a read
timeout isn't resent; after a long pause the connections are renewed first."""
import os
import sys
import tempfile

os.environ["HOME"] = tempfile.mkdtemp()
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import requests  # noqa: E402

from ipatool_api.services import constants, http_client  # noqa: E402
from ipatool_api.services.cookie_store import CookieStore  # noqa: E402

client = http_client.HTTPClient(CookieStore(os.path.join(os.environ["HOME"], "c.lwp")))
resets = []
real_reset = client.reset_connections
client.reset_connections = lambda reason="": (resets.append(reason), real_reset(reason))
plan = []


class Response:
    status_code = 200
    headers = {}
    content = b'{"ok": true}'

    def json(self):
        return {"ok": True}


def fake_request(**_kw):
    step = plan.pop(0)
    if step == "ok":
        return Response()
    raise step


client.session.request = fake_request
client.signed_session.request = fake_request
request = http_client.HTTPRequest(method="GET", url="https://example.com/x", headers={}, payload=None,
                                  response_format=constants.ResponseFormatJSON)

plan[:] = [requests.ConnectionError("reset"), "ok"]
assert client.send(request).data == {"ok": True} and resets == ["connection error"] and not plan
resets.clear()
plan[:] = [requests.ConnectTimeout("connect timeout"), "ok"]
assert client.send(request).data == {"ok": True} and resets == ["connection error"]
resets.clear()
plan[:] = [requests.ConnectionError("a"), requests.ConnectionError("b")]
try:
    client.send(request)
    raise AssertionError("expected an error")
except requests.ConnectionError:
    assert resets == ["connection error", "connection error"]
resets.clear()
plan[:] = [requests.ReadTimeout("slow"), "ok"]
try:
    client.send(request)
    raise AssertionError("a read timeout isn't resent")
except requests.ReadTimeout:
    assert resets == ["timeout"] and plan == ["ok"]
# signed: not resent here (the caller re-signs and retries)
resets.clear()
signed = http_client.HTTPRequest(method="POST", url="https://example.com/s", headers={}, payload=None,
                                 response_format=constants.ResponseFormatJSON, signer=lambda body: b"sig")
plan[:] = [requests.ConnectionError("reset"), "ok"]
try:
    client.send(signed)
    raise AssertionError("expected an error")
except requests.ConnectionError:
    assert resets == ["connection error"] and plan == ["ok"]
# idle: renewed before the next request
plan[:] = ["ok"]
resets.clear()
client._last_used -= http_client.IDLE_RESET_SECONDS + 1
client.send(request)
assert resets == [""], resets
print("CONNECTION RESET OK")
