"""Sign-in signature setup: a momentary network failure is retried; a lasting
one names the host in the error."""
import os
import sys
import tempfile
import types

os.environ["HOME"] = tempfile.mkdtemp()
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import requests  # noqa: E402

from ipatool_api.services import appstore, sap  # noqa: E402
from ipatool_api.services.errors import AppStoreError  # noqa: E402

appstore.time.sleep = lambda _s: None
attempts = []


def failing(times):
    def make(config, cache_dir=None, verify=True):
        attempts.append(1)
        if len(attempts) <= times:
            request = requests.Request("POST", "https://play.itunes.apple.com/WebObjects/x?secret=1").prepare()
            raise requests.ConnectTimeout("timed out", request=request)
        return "signer"
    return make


service = appstore.AppStoreService.__new__(appstore.AppStoreService)
service._storage_dir = __import__("pathlib").Path(os.environ["HOME"]) / ".ipatool"
service._verify = True
config = types.SimpleNamespace(setup_url="https://a", certificate_url="https://b", version=200)

sap.Signer = failing(2)
assert service._create_signer(config, b"x" * 6) == "signer" and len(attempts) == 3
attempts.clear()
sap.Signer = failing(5)
try:
    service._create_signer(config, b"x" * 6)
    raise AssertionError("expected an error")
except AppStoreError as exc:
    text = str(exc)
    assert "ConnectTimeout" in text and "play.itunes.apple.com" in text and "secret" not in text, text
assert len(attempts) == 3
print("SAP RETRY OK")
