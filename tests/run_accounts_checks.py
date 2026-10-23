"""Several saved sign-ins (account switcher), both session modes, with a
faked Apple sign-in. Run: python tests/run_accounts_checks.py  (prints ACCOUNTS OK)
"""
import os
import sys
import tempfile
import time

HOME = tempfile.mkdtemp()
os.environ["HOME"] = HOME
os.environ["USERPROFILE"] = HOME
os.environ.pop("IPATOOL_DEVICE_GUID", None)
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from requests.cookies import create_cookie  # noqa: E402

from ipatool_api.services.appstore import AppStoreService  # noqa: E402
from ipatool_api.services.models import Account  # noqa: E402

DSIDS = {"ann@example.com": "1001", "bob@example.com": "2002", "cid@example.com": "3003"}


def fake_login(self, email, password, auth_code=None, rotate_session=True):
    account = Account(email=email, password_token="TOK-" + email, directory_services_id=DSIDS[email],
                      name=email.split("@")[0].title(), store_front="143441-1,34", password=password)
    if rotate_session:
        self._state.on_login()
    self._persist_account(account)
    jar = self._http.session.cookies
    jar.set_cookie(create_cookie("mz_at_ssl-" + DSIDS[email], "C-" + email, domain=".apple.com", path="/",
                                 expires=int(time.time()) + 86400))
    jar.set_cookie(create_cookie("hsaccnt", "1", domain=".apple.com", path="/WebObjects"))  # session cookie
    self._http._cookie_store.save()
    from ipatool_api.services.state import account_slot_id

    self._state.forget_account(account_slot_id(account.to_dict()))
    return account


AppStoreService.login = fake_login

sys.argv = ["x"]
import app as appmod  # noqa: E402


def mkapp(*argv):
    return appmod.build_app(appmod.parse_args(list(argv)))


def names(client):
    return [(a["email"], a["active"]) for a in client.get("/api/accounts").get_json()["accounts"]]


def check(app, label):
    c = app.test_client()
    assert c.get("/api/accounts").get_json()["accounts"] == []
    assert c.post("/api/auth/login", json={"email": "ann@example.com", "password": "pw"}).status_code == 200
    assert names(c) == [("ann@example.com", True)], names(c)
    # add another: Ann is kept, nobody active until Bob signs in
    assert c.post("/api/accounts/add", json={}).status_code == 200
    assert c.get("/api/account").get_json()["account"] is None
    assert names(c) == [("ann@example.com", False)], names(c)
    c.post("/api/auth/login", json={"email": "bob@example.com", "password": "pw"})
    assert names(c) == [("bob@example.com", True), ("ann@example.com", False)], names(c)
    ann_id = [a["id"] for a in c.get("/api/accounts").get_json()["accounts"] if a["email"] == "ann@example.com"][0]
    # no secrets in the list
    raw = c.get("/api/accounts").get_data(as_text=True)
    assert "TOK-" not in raw and "1001" not in raw and "pw" not in raw, raw
    # switch back to Ann: her token and her persistent cookie come back, no session cookie
    r = c.post("/api/accounts/switch", json={"id": ann_id})
    assert r.status_code == 200 and r.get_json()["account"]["email"] == "ann@example.com", r.get_json()
    assert names(c) == [("ann@example.com", True), ("bob@example.com", False)], names(c)
    with app.test_request_context(headers={"Cookie": "; ".join(f"{k.key}={k.value}" for k in c._cookies.values())}):
        from flask import g

        app.preprocess_request()
        state = g.session_state
        assert state.load_account().password_token == "TOK-ann@example.com"
        cookies = {k.name: k.value for k in state.cookies.jar}
        assert cookies.get("mz_at_ssl-1001") == "C-ann@example.com", cookies
        assert "mz_at_ssl-2002" not in cookies and "hsaccnt" not in cookies, cookies
        ann_guid = state.device_guid()
    # Bob kept his own device GUID; switching does not mix them
    bob_id = [a["id"] for a in c.get("/api/accounts").get_json()["accounts"] if a["email"] == "bob@example.com"][0]
    c.post("/api/accounts/switch", json={"id": bob_id})
    with app.test_request_context(headers={"Cookie": "; ".join(f"{k.key}={k.value}" for k in c._cookies.values())}):
        from flask import g

        app.preprocess_request()
        assert g.session_state.load_account().password_token == "TOK-bob@example.com"
        assert g.session_state.device_guid() != ann_guid
    # signing in again as a saved account replaces it (no duplicate)
    c.post("/api/accounts/add", json={})
    c.post("/api/auth/login", json={"email": "ann@example.com", "password": "pw2"})
    assert sorted(names(c)) == [("ann@example.com", True), ("bob@example.com", False)], names(c)
    # forget Bob; logout signs out only the active one
    c.post("/api/accounts/forget", json={"id": bob_id})
    assert names(c) == [("ann@example.com", True)], names(c)
    c.post("/api/accounts/add", json={})
    c.post("/api/auth/login", json={"email": "cid@example.com", "password": "pw"})
    c.post("/api/auth/logout", json={})
    assert names(c) == [("ann@example.com", False)], names(c)
    # bad ids
    assert c.post("/api/accounts/switch", json={"id": "../x"}).status_code == 400
    assert c.post("/api/accounts/switch", json={"id": "deadbeef0000"}).status_code >= 400
    print("accounts ok:", label)


check(mkapp("--host", "0.0.0.0"), "browser sessions")
check(mkapp("--host", "127.0.0.1"), "local")
print("ACCOUNTS OK")
