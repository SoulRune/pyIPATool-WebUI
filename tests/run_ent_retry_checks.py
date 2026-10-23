"""ent/download: one 401/403 is retried at once; only two refusals in a row
block it (5 min, per sign-in). Run: python tests/run_ent_retry_checks.py"""
import os
import sys
import tempfile

HOME = tempfile.mkdtemp()
os.environ["HOME"] = HOME
os.environ["USERPROFILE"] = HOME
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from ipatool_api.services import appstore as appstore_mod  # noqa: E402
from ipatool_api.services import sap  # noqa: E402
from ipatool_api.services.appstore import AppStoreService  # noqa: E402
from ipatool_api.services.errors import AppStoreError  # noqa: E402
from ipatool_api.services.models import Account, App  # noqa: E402

import ipatool_api.services.sap.signer as signer  # noqa: E402

signer.unicorn_available = lambda: True
sap.unicorn_available = lambda: True
ENDPOINT = "https://downloaddispatch.itunes.apple.com" + appstore_mod._ENT_DOWNLOAD_PATH
AppStoreService._fetch_url_bag = lambda self, guid: {"volumeStoreDownloadProduct": ENDPOINT}
script = []
sent = []


def fake_send(self, endpoint, account, app, guid, version_id):
    sent.append(version_id)
    answer = script.pop(0)
    if answer == "ok":
        return "RESULT"
    if answer == "net":
        raise ConnectionError("connection reset")
    if isinstance(answer, dict):
        raise AppStoreError("ent/download error", metadata=answer)
    raise AppStoreError("refused", metadata={"status": answer})


AppStoreService._send_ent_download = fake_send

sys.argv = ["x"]
import app as appmod  # noqa: E402

flask_app = appmod.build_app(appmod.parse_args(["--host", "127.0.0.1"]))
acct = Account(email="a@b.c", password_token="tok1", directory_services_id="1", name="A", store_front="143441-1,34", password="")
app = App(id=5, bundle_id="com.x")
with flask_app.test_request_context():
    flask_app.preprocess_request()
    from ipatool_api.routes.api import _service

    svc = _service()
    guid = "00AABBCCDDEE"
    script[:] = [401, "ok"]
    assert svc._try_ent_download(acct, app, guid, "77", "iphone") == "RESULT" and len(sent) == 2
    sent.clear(); script[:] = ["ok"]
    assert svc._try_ent_download(acct, app, guid, "77", "iphone") == "RESULT", "one refusal doesn't block"
    sent.clear(); script[:] = [403, 401]
    assert svc._try_ent_download(acct, app, guid, "77", "iphone") is None and len(sent) == 2
    sent.clear(); script[:] = ["ok"]
    assert svc._try_ent_download(acct, app, guid, "77", "iphone") is None and not sent, "blocked after two"
    relogged = Account(**{**acct.__dict__, "password_token": "tok2"})
    assert svc._try_ent_download(relogged, app, guid, "77", "iphone") == "RESULT", "new sign-in lifts the block"
    sent.clear(); script[:] = [500]
    assert svc._try_ent_download(relogged, app, guid, "77", "iphone") is None and len(sent) == 1, "no retry for non-401/403"

# Legacy answers after ent/download gave no answer: marked "not_checked";
# after Apple answered about the version on ent/download: not marked.
from ipatool_api.services.errors import SubscriptionRequiredError, VersionNotServedError  # noqa: E402

AppStoreService._download_product_chain = lambda self, *a, **k: (_ for _ in ()).throw(
    SubscriptionRequiredError("Subscription Required"))
appstore_mod._ENT_DOWNLOAD_REFUSED._data.clear()
acct3 = Account(**{**acct.__dict__, "password_token": "tok3"})
with flask_app.test_request_context():
    flask_app.preprocess_request()
    svc = _service()
    svc._guid = lambda: guid

    def outcome(answers):
        appstore_mod._ENT_DOWNLOAD_REFUSED._data.clear()
        script[:] = answers
        try:
            svc.get_version_metadata(acct3, app, "77")
        except SubscriptionRequiredError as exc:
            return getattr(exc, "not_checked", "")
        raise AssertionError("expected an error")

    assert "ent/download failed" in outcome([401, 401])                   # refused twice -> not checked
    assert "ent/download failed" in outcome(["net"])                       # network / emulator -> not checked
    assert outcome([{"failureType": "2059"}]) == ""                       # Apple's answer -> definitive
    script[:] = []

    def fake_send2(self, endpoint, account, app, guid, version_id):
        raise VersionNotServedError("other version", metadata={"returnedVersionId": "1"})
    AppStoreService._send_ent_download = fake_send2
    try:
        svc.get_version_metadata(acct3, app, "77")
    except SubscriptionRequiredError as exc:
        assert not getattr(exc, "not_checked", ""), exc.not_checked      # "another version" is an answer
    signer.unicorn_available = lambda: False
    sap.unicorn_available = lambda: False
    try:
        svc.get_version_metadata(acct3, app, "77")
    except SubscriptionRequiredError as exc:
        assert "emulator" in exc.not_checked, exc.not_checked
print("ENT RETRY OK")
