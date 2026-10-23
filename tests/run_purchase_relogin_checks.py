"""Download with "get the app if needed": when getting it answers "password
token expired", sign in again silently and continue with the new session."""
import os
import sys
import tempfile
from pathlib import Path

os.environ["HOME"] = tempfile.mkdtemp()
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ipatool_api.routes import api  # noqa: E402
from ipatool_api.services.errors import LicenseRequiredError, PasswordTokenExpiredError  # noqa: E402
from ipatool_api.services.models import Account, App  # noqa: E402

owned = set()
calls = []


def account(token):
    return Account(email="a@b.c", password_token=token, directory_services_id="1", name="A",
                   store_front="143441-1,34", password="pw")


class Service:
    def download(self, account, app, **_kw):
        calls.append(("download", account.password_token))
        if account.password_token != "new":
            raise PasswordTokenExpiredError("expired") if app.id in owned else LicenseRequiredError("license")
        if app.id not in owned:
            raise LicenseRequiredError("license")
        return "ok"

    def purchase(self, account, app):
        calls.append(("purchase", account.password_token))
        if account.password_token != "new":
            raise PasswordTokenExpiredError("expired")
        owned.add(app.id)

    def login(self, email, password, auth_code=None, rotate_session=True):
        calls.append(("login", password, rotate_session))
        return account("new")


result, used = api._download_with_retries(Service(), account("old"), App(id=1, bundle_id="x", name="G"),
                                          Path(tempfile.mkdtemp()), None, True)
assert result == "ok" and used.password_token == "new", (result, calls)
assert calls == [("download", "old"), ("purchase", "old"), ("login", "pw", False), ("purchase", "new"),
                 ("download", "new")], calls
print("PURCHASE RELOGIN OK")
