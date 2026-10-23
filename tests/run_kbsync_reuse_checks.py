"""ent/download: when Apple answers about the app (no license, version not
served, subscription), the kbsync blob worked - it's kept, not regenerated for
every version; a blob refused with 401/403 or an unknown failure is replaced."""
import os
import sys
import tempfile

os.environ["HOME"] = tempfile.mkdtemp()
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ipatool_api.services import appstore  # noqa: E402
from ipatool_api.services.errors import AppStoreError, VersionNotServedError  # noqa: E402
from ipatool_api.services.models import Account, App  # noqa: E402

generated = []
answers = []


class Service(appstore.AppStoreService):
    def __init__(self):
        pass

    def _generate_kbsync(self, hardware_id, dsid):
        generated.append(1)
        return f"blob{len(generated)}"

    def _ent_download_request(self, endpoint, account, app, guid, version_id, hardware_id, blob):
        kind = answers.pop(0)
        if kind == "ok":
            return "result"
        if kind == "9610":
            raise AppStoreError("received ent/download error: 9610", metadata={"failureType": "9610"})
        if kind == "sub":
            raise AppStoreError("x", metadata={"customerMessage": "Subscription Required"})
        if kind == "other-version":
            raise VersionNotServedError("Apple served another version")
        if kind == "401":
            raise AppStoreError("refused", metadata={"status": 401})
        if kind == "500":
            raise AppStoreError("unexpected response from Apple (HTTP 500)", metadata={"status": 500})
        if kind == "5002":
            raise AppStoreError("received ent/download error: 5002", metadata={"failureType": "5002"})
        raise AssertionError(kind)


account = Account(email="a@b.c", password_token="t", directory_services_id="42", name="A", store_front="143441-1,34")
app = App(id=1, bundle_id="x", name="G")
service = Service()
guid = "a1b2c3d4e5f6"


def call(*kinds):
    answers[:] = list(kinds)
    try:
        return service._send_ent_download("https://e", account, app, guid, "1")
    except AppStoreError as exc:
        return exc


# Apple's answers about the app: one blob for all of them.
for kind in ("9610", "other-version", "sub", "9610"):
    assert isinstance(call(kind), AppStoreError)
assert len(generated) == 1, generated
assert call("ok") == "result" and len(generated) == 1
# The blob refused (401): a fresh one is made and tried.
assert call("401", "ok") == "result" and len(generated) == 2
# An unknown failure may be the blob's fault: also replaced.
assert isinstance(call("5002", "5002"), AppStoreError) and len(generated) == 3
assert call("ok", ) == "result" and len(generated) == 4  # the 5002 blob wasn't kept
# Apple's HTTP 500 for one version while the blob served others just now: kept.
n = len(generated)
assert isinstance(call("500"), AppStoreError) and len(generated) == n
assert call("ok") == "result" and len(generated) == n
# ... but a blob that hasn't served anything for a long time is replaced.
key = (42, guid)
blob, _ = appstore._KBSYNC_CACHE[key]
appstore._KBSYNC_CACHE[key] = (blob, appstore.time.monotonic() - appstore._KBSYNC_TRUSTED_SECONDS - 1)
assert call("500", "ok") == "result" and len(generated) == n + 1

# Parallel requests without a blob: one generation, the others wait and reuse it.
import threading  # noqa: E402
import time  # noqa: E402

appstore._KBSYNC_CACHE.clear()
generated.clear()
real = Service._generate_kbsync


def slow(self, hardware_id, dsid):
    time.sleep(0.3)
    return real(self, hardware_id, dsid)


Service._generate_kbsync = slow
Service._ent_download_request = lambda self, *a: "result"
results = []
threads = [threading.Thread(target=lambda: results.append(service._send_ent_download("https://e", account, app, guid, "1")))
           for _ in range(4)]
for t in threads:
    t.start()
for t in threads:
    t.join()
assert results == ["result"] * 4 and len(generated) == 1, (results, generated)
print("KBSYNC REUSE OK")
