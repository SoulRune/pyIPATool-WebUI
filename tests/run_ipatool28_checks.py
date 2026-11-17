"""ipatool 2.8 follow-ups: sign-in storefront / account id fallbacks, Apple's
sign-in dialogs and machine-verification requests, download failures that
mean an expired sign-in.
Run: python tests/run_ipatool28_checks.py  (prints IPATOOL 2.8 OK)
"""
import os
import sys
import tempfile

os.environ["HOME"] = tempfile.mkdtemp()
os.environ.setdefault("IPATOOL_NO_VAULT_OFFER", "1")
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from ipatool_api.services import constants  # noqa: E402
from ipatool_api.services.appstore import (  # noqa: E402
    AppStoreService, _dialog_text, _dsid_from_headers, _normalize_download_failure)
from ipatool_api.services.appstore import (  # noqa: E402
    _is_store_amd_commerce_url, validate_authentication_endpoint)
from ipatool_api.services.errors import AppStoreError, MachineActionError  # noqa: E402
from ipatool_api.services.models import Account  # noqa: E402
from ipatool_api.services.storeauth import AnisetteState, identity_headers  # noqa: E402
from ipatool_api.services.store_emulator.gotypes import go_float  # noqa: E402
from ipatool_api.services.http_client import HTTPResult  # noqa: E402

# account id from headers
assert _dsid_from_headers({"x-dsid": " 123 "}) == "123"
assert _dsid_from_headers({"Set-Cookie": "a=1; Path=/, mz_at_ssl-98765=xyz; Path=/"}) == "98765"
assert _dsid_from_headers({"Set-Cookie": "mz_at0-555=abc"}) == "555"
assert _dsid_from_headers({}) == ""

# dialogs: text, and the button link only to apple.com over https
d = {"dialog": {"message": "Review your account", "explanation": "Sign in at the site.",
                "okButtonString": "Review", "okButtonAction": {"kind": "OpenURL", "url": "https://appleid.apple.com/x"}}}
assert _dialog_text(d) == "Review your account: Sign in at the site. (Review: https://appleid.apple.com/x)", _dialog_text(d)
d["dialog"]["okButtonAction"]["url"] = "https://evil.example/apple.com"
assert _dialog_text(d) == "Review your account: Sign in at the site."
assert _dialog_text({"dialog": {"message": "Same", "explanation": "Same"}}) == "Same"
assert _dialog_text({}) == "" and _dialog_text({"dialog": {}}) == ""

# download failures
x = _normalize_download_failure({"metrics": {"messageCode": 2042}})
assert x["failureType"] == constants.FAILURE_PASSWORD_TOKEN_EXPIRED
assert _normalize_download_failure({"failureType": "1008"})["failureType"] == constants.FAILURE_PASSWORD_TOKEN_EXPIRED
assert _normalize_download_failure({"customerMessage": "Sign in to the  iTunes Store"})["failureType"] == "2034"
assert _normalize_download_failure({"metrics": {"messageCode": 9610}})["failureType"] == "9610"
assert "failureType" not in _normalize_download_failure({"songList": [{}], "customerMessage": "Sign-in required"})

# login parsing: machine action / dialog first; storefront and account id fallbacks
service = AppStoreService.__new__(AppStoreService)
try:
    service._parse_login_response(HTTPResult(200, {"X-Apple-AMD-Action": "SP", "X-Apple-AMD-Data": " abc "}, {}),
                                  1, "", "https://x")
    raise SystemExit("no error for a machine action")
except MachineActionError as exc:
    assert exc.action == "SP" and exc.data == "abc" and "machine verification" in str(exc)
try:
    service._parse_login_response(HTTPResult(200, {}, {"dialog": {"message": "Agree to terms"}}), 1, "", "https://x")
    raise SystemExit("no error for a dialog")
except AppStoreError as exc:
    assert str(exc) == "Agree to terms"
# a token without dsPersonId in the body is fine now (the id comes from headers)
assert service._parse_login_response(HTTPResult(200, {}, {"passwordToken": "t"}), 1, "", "https://x") == (False, None)

sent = []
service._send_authentication_request = lambda request, stage: HTTPResult(
    200, {"X-Apple-Request-Store-Front": "143469-16,32", "X-Dsid": "42"}, {"passwordToken": "tok"})
acc = service._login("me@example.com", "pw", "", "aabbccddeeff", "https://buy.itunes.apple.com/auth", lambda b: b"")
assert acc.store_front == "143469-16,32" and acc.directory_services_id == "42" and acc.email == "me@example.com"
service._send_authentication_request = lambda request, stage: HTTPResult(
    200, {"X-Set-Apple-Store-Front": "143441-1,32"}, {"passwordToken": "tok"})
try:
    service._login("me@example.com", "pw", "", "aabbccddeeff", "https://buy.itunes.apple.com/auth", lambda b: b"")
    raise SystemExit("no error without an account id")
except AppStoreError as exc:
    assert "account id" in str(exc)
assert constants.DEFAULT_USER_AGENT.startswith("Configurator/2.21 ")

# native sign-in endpoint (ipatool 001d889)
for ok in ("https://auth.itunes.apple.com/auth/v1/native", "https://auth.itunes.apple.com/auth/v1/native/fast"):
    assert validate_authentication_endpoint(ok) == ok
for bad in ("https://auth.itunes.apple.com/auth/v1/other", "https://auth.itunes.apple.com:8443/auth/v1/native"):
    try:
        validate_authentication_endpoint(bad)
        raise SystemExit("accepted " + bad)
    except AppStoreError:
        pass

# endpoints the AppleMediaServices proof is made for
for ok in ("https://downloaddispatch.itunes.apple.com/WebObjects/DownloadDispatch.woa/wa/ent/download?guid=AA",
           "https://downloaddispatch.itunes.apple.com/r/redownload?guid=AA",
           "https://p25-buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/volumeStoreDownloadProduct?guid=AA",
           "https://buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/volumeStoreDownloadProduct?guid=AA"):
    assert _is_store_amd_commerce_url(ok), ok
for bad in ("https://downloaddispatch.itunes.apple.com/r/redownload?guid=AA&guid=AA",
            "https://downloaddispatch.itunes.apple.com/r/redownload",
            "https://evil.example/r/redownload?guid=AA",
            "https://px-buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/volumeStoreDownloadProduct?guid=AA",
            "https://buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/buyProduct?guid=AA",
            "http://downloaddispatch.itunes.apple.com/r/redownload?guid=AA"):
    assert not _is_store_amd_commerce_url(bad), bad

# anisette state: ipatool's JSON, random identity when empty, kept with the account
fresh = AnisetteState.decode(None)
assert len(fresh.identifier) == 16 and fresh.provisioning == b""
state = AnisetteState(bytes(range(16)), b"adi", 17)
again = AnisetteState.decode(state.encode())
assert (again.identifier, again.provisioning, again.routing_info) == (bytes(range(16)), b"adi", 17)
assert identity_headers(bytes(range(16)))[1] == "00010203-0405-0607-0809-0a0b0c0d0e0f"
for broken in (b"{", b'{"Identifier":"AAAA"}'):
    try:
        AnisetteState.decode(broken)
        raise SystemExit("accepted a broken state")
    except AppStoreError:
        pass
account = Account.from_dict({"email": "a", "passwordToken": "t", "directoryServicesIdentifier": "1",
                             "name": "n", "storeFront": "s", "anisette": state.encode().decode()})
assert Account.from_dict(account.to_dict()).anisette == account.anisette
assert "anisette" not in account.to_public_dict()

# fmt %v of floats, as the emulated Foundation formats them
assert [go_float(v) for v in (1.0, 1e6, 123456.0, 0.1, 1e-5, -2.5)] == ["1", "1e+06", "123456", "0.1", "1e-05", "-2.5"]
# the AppleMediaServices proof: once per identity and 30-second window
import threading  # noqa: E402
from ipatool_api.services import appstore as appstore_module, storeauth as storeauth_module  # noqa: E402

made = []


def fake_proof(_bundle, state, _url, _hardware):
    made.append(state)
    return {"X-Apple-AMD": f"proof{len(made)}", "X-Apple-AMD-M": "m"}, state


real_proof, real_bundle = storeauth_module.store_amd_headers, service._sap_bundle
storeauth_module.store_amd_headers, service._sap_bundle = fake_proof, lambda: None
real_time = appstore_module.time.time
try:
    now = [1_800_000_010.0]
    appstore_module.time.time = lambda: now[0]
    signed = Account.from_dict({"email": "a", "passwordToken": "t", "directoryServicesIdentifier": "1", "name": "n",
                                "storeFront": "s", "anisette": state.encode().decode()})
    url = "https://downloaddispatch.itunes.apple.com/r/redownload?guid=02FC00000001"
    results = []
    workers = [threading.Thread(target=lambda: results.append(service._store_amd_proof(signed, url, "02FC00000001")))
               for _ in range(8)]
    [worker.start() for worker in workers]
    [worker.join() for worker in workers]
    assert len(made) == 1 and all(r["X-Apple-AMD"] == "proof1" for r in results)
    now[0] += 30
    assert service._store_amd_proof(signed, url, "02FC00000001")["X-Apple-AMD"] == "proof2" and len(made) == 2
    assert service._store_amd_proof(account_without := Account.from_dict(
        {"email": "b", "passwordToken": "t", "directoryServicesIdentifier": "1", "name": "n", "storeFront": "s"}),
        url, "02FC00000001") == {} and account_without.anisette is None
finally:
    storeauth_module.store_amd_headers, service._sap_bundle = real_proof, real_bundle
    appstore_module.time.time = real_time
print("IPATOOL 2.8 OK")
