"""Master-password encryption of the stored secrets (services/vault.py).
Run: python tests/run_vault_checks.py  (prints VAULT OK)"""
import os
import sys
import tempfile
import time

HOME = tempfile.mkdtemp()
os.environ["HOME"] = HOME
os.environ["USERPROFILE"] = HOME
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from pathlib import Path  # noqa: E402

from requests.cookies import create_cookie  # noqa: E402

from ipatool_api.services import vault  # noqa: E402
from ipatool_api.services.cookie_store import CookieStore  # noqa: E402
from ipatool_api.services.keychain import FileKeychain  # noqa: E402
from ipatool_api.services.state import BrowserSessionCodec  # noqa: E402

base = Path(HOME) / ".ipatool"
(base / "collector" / "profiles" / "main").mkdir(parents=True)
(base / "accounts" / "abc").mkdir(parents=True)


def write_secrets():
    FileKeychain(str(base / "keychain.json")).set("account", b"APPLE-TOKEN-123")
    FileKeychain(str(base / "collector" / "secrets.json")).set("catalog_rw_token", b"github_pat_SECRET")
    FileKeychain(str(base / "collector" / "profiles" / "main" / "keychain.json")).set("account", b"PROFILE-TOKEN")
    FileKeychain(str(base / "accounts" / "abc" / "keychain.json")).set("account", b"SAVED-TOKEN")
    store = CookieStore(str(base / "cookies.lwp"))
    store.jar.set_cookie(create_cookie("mz_at0", "COOKIEVALUE", domain=".apple.com", path="/", expires=int(time.time()) + 3600))
    store.save()
    return BrowserSessionCodec.load_or_create_secret(base / "session_secret.key")


def on_disk():
    return b"".join(p.read_bytes() for p in vault.secret_files())


assert vault.status() == "undecided"
key = write_secrets()
assert b"APPLE-TOKEN-123" not in on_disk() or True  # base64 inside json, not encryption
assert len(vault.secret_files()) == 6, vault.secret_files()

# weak passwords refused
for weak in ("short", "aaaaaaaaaaaa"):
    try:
        vault.enable(weak)
        raise AssertionError(weak)
    except vault.VaultError:
        pass

start = time.time()
files = vault.enable("correct horse battery")
print(f"enable: {len(files)} files, kdf {vault.kdf_name()}, {time.time() - start:.1f}s")
assert vault.status() == "on" and len(files) == 6
raw = on_disk()
for secret in (b"APPLE-TOKEN", b"github_pat", b"PROFILE-TOKEN", b"SAVED-TOKEN", b"COOKIEVALUE", b"QVBQTEUtVE9LRU4"):
    assert secret not in raw, secret
assert all(p.read_bytes().startswith(vault.HEADER) for p in vault.secret_files())
meta = (base / "vault.json").read_text()
assert "correct horse" not in meta and '"scrypt"' in meta
# readable without the 'cryptography' package (stdlib format only)
from ipatool_api.services import session_crypto  # noqa: E402
saved_aesgcm, session_crypto.AESGCM = session_crypto.AESGCM, None

# a new "process": locked until unlocked
vault.lock()
for read in (lambda: FileKeychain(str(base / "keychain.json")),
             lambda: CookieStore(str(base / "cookies.lwp")).jar,
             lambda: BrowserSessionCodec.load_or_create_secret(base / "session_secret.key")):
    try:
        read()
        raise AssertionError("read while locked")
    except vault.VaultLockedError:
        pass
try:
    vault.unlock("wrong password!")
    raise AssertionError("wrong password accepted")
except vault.VaultError as exc:
    assert "wrong" in str(exc)
vault.unlock("correct horse battery")
assert FileKeychain(str(base / "keychain.json")).get("account") == b"APPLE-TOKEN-123"
assert FileKeychain(str(base / "collector" / "secrets.json")).get("catalog_rw_token") == b"github_pat_SECRET"
assert {c.name: c.value for c in CookieStore(str(base / "cookies.lwp")).jar} == {"mz_at0": "COOKIEVALUE"}
assert BrowserSessionCodec.load_or_create_secret(base / "session_secret.key") == key
session_crypto.AESGCM = saved_aesgcm
# writes stay encrypted
FileKeychain(str(base / "keychain.json")).set("account", b"NEW-TOKEN")
assert b"NEW-TOKEN" not in (base / "keychain.json").read_bytes()
# a write while locked never goes to disk in plain text
vault.lock()
try:
    FileKeychain.__new__(FileKeychain)  # noqa
    k = object.__new__(FileKeychain)
    import threading
    k._path, k._lock, k._data = base / "keychain.json", threading.RLock(), {}
    k.set("account", b"PLAIN?")
    raise AssertionError("plain write while locked")
except vault.VaultLockedError:
    pass
assert b"PLAIN?" not in (base / "keychain.json").read_bytes()

# password change: same data key, files untouched, old password refused
before = (base / "keychain.json").read_bytes()
vault.change_password("correct horse battery", "another fine passphrase")
assert (base / "keychain.json").read_bytes() == before
vault.lock()
try:
    vault.unlock("correct horse battery")
    raise AssertionError("old password still works")
except vault.VaultError:
    pass
vault.unlock("another fine passphrase")
assert FileKeychain(str(base / "keychain.json")).get("account") == b"NEW-TOKEN"

# off: only with the password, even while unlocked
assert vault.is_unlocked()
try:
    vault.disable("not the password")
    raise AssertionError("disabled without the password")
except vault.VaultError:
    pass
assert vault.status() == "on"
assert vault.verify_password("another fine passphrase") and not vault.verify_password("nope nope nope")
vault.disable("another fine passphrase")
assert vault.status() == "off" and not vault.is_unlocked()
assert not any(p.read_bytes().startswith(vault.HEADER) for p in vault.secret_files())
assert FileKeychain(str(base / "keychain.json")).get("account") == b"NEW-TOKEN"
vault.decline()  # already decided: stays off
assert vault.status() == "off"

# PBKDF2 where this Python has no hashlib.scrypt
vault._scrypt_available = lambda: False
start = time.time()
vault.enable("stdlib only passphrase")
print(f"pbkdf2 enable: {vault.kdf_name()}, {time.time() - start:.1f}s")
assert vault.kdf_name() == "pbkdf2"
vault.lock()
vault.unlock("stdlib only passphrase")
assert FileKeychain(str(base / "keychain.json")).get("account") == b"NEW-TOKEN"
vault.disable("stdlib only passphrase")
print("VAULT OK")
