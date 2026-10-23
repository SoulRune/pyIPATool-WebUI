"""Where an Apple ID session lives.

``LocalState``: one user, stored in ~/.ipatool (keychain.json, cookies.lwp,
device_guid.txt); for a server only reachable from this machine.

``BrowserState``: nothing per user on the server; account, cookies and device
GUID are encrypted into an HttpOnly cookie of each browser.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import logging
import secrets
import shutil
import threading
import time
from http.cookiejar import Cookie, CookieJar
from pathlib import Path
from typing import Any, Dict, List, Optional

from .cookie_store import CookieStore
from .errors import AppStoreError
from .keychain import FileKeychain
from .machine import Machine
from .models import Account
from .securefile import atomic_write_bytes, atomic_write_text, make_private
from .session_crypto import SessionCipher, SessionDecryptError

logger = logging.getLogger(__name__)


class SessionState:
    """Interface used by AppStoreService - see the two implementations below."""

    #: Identifies who owns background download jobs started from this state.
    owner_id: str = ""

    @property
    def cookies(self):  # -> object with ``.jar`` and ``.save()``
        raise NotImplementedError

    def load_account(self) -> Account:
        raise NotImplementedError

    def save_account(self, account: Account) -> None:
        raise NotImplementedError

    def clear(self) -> None:
        raise NotImplementedError

    def device_guid(self) -> str:
        raise NotImplementedError

    def on_login(self) -> None:
        """Hook called after a successful login."""

    # -- saved sign-ins: account, cookies and device GUID per slot, so switching
    # back needs no new 2FA code.

    MAX_SAVED = 5

    def list_accounts(self) -> List[Dict[str, Any]]:
        """Public info of the active and the saved sign-ins (no secrets)."""
        raise NotImplementedError

    def park_active(self) -> None:
        """Keep the active sign-in as a saved one and leave none active (to
        sign in with another Apple ID)."""
        raise NotImplementedError

    def switch_account(self, slot_id: str) -> Account:
        """Make a saved sign-in the active one (the active one is saved)."""
        raise NotImplementedError

    def forget_account(self, slot_id: str) -> None:
        """Drop a saved sign-in (not the active one)."""
        raise NotImplementedError


def _new_guid() -> str:
    return secrets.token_hex(6).upper()


def account_slot_id(account: Dict[str, Any]) -> str:
    """Stable id of a sign-in in the API (not the DSID itself)."""
    key = str(account.get("directoryServicesIdentifier") or account.get("email") or "").lower()
    return hashlib.sha256(("pyipatool-slot:" + key).encode("utf-8")).hexdigest()[:12]


def _public_account(account: Dict[str, Any], active: bool) -> Dict[str, Any]:
    return {
        "id": account_slot_id(account),
        "email": account.get("email", ""),
        "name": account.get("name", ""),
        "storeFront": account.get("storeFront", ""),
        "active": active,
    }


# ---------------------------------------------------------------------------
# Local (single-user, file-backed)
# ---------------------------------------------------------------------------


class LocalState(SessionState):
    owner_id = "local"

    def __init__(self, keychain: FileKeychain, cookie_store: CookieStore, machine: Machine,
                 accounts_dir: Optional[Path] = None) -> None:
        self._keychain = keychain
        self._cookie_store = cookie_store
        self._machine = machine
        # Saved sign-ins: <accounts_dir>/<id>/{keychain.json, cookies.lwp, guid.txt}
        self._accounts_dir = Path(accounts_dir) if accounts_dir else None
        self._slots_lock = threading.RLock()

    @property
    def cookies(self) -> CookieStore:
        return self._cookie_store

    def load_account(self) -> Account:
        try:
            data = self._keychain.get("account")
        except KeyError as exc:
            raise AppStoreError("no active account") from exc
        return Account.from_dict(json.loads(data.decode("utf-8")))

    def save_account(self, account: Account) -> None:
        self._keychain.set("account", json.dumps(account.to_dict(), indent=2).encode("utf-8"))

    def clear(self) -> None:
        # A new GUID too: only that forces a full 2FA sign-in next time.
        self._keychain.remove("account")
        try:
            self._cookie_store.clear()
        except Exception:  # pragma: no cover
            logger.exception("failed to clear cookie store")
        try:
            self._machine.reset_device_guid()
        except Exception:  # pragma: no cover
            logger.exception("failed to reset device guid")

    def device_guid(self) -> str:
        return self._machine.device_guid()

    # -- several saved sign-ins ---------------------------------------------

    def _active_dict(self) -> Optional[Dict[str, Any]]:
        try:
            return json.loads(self._keychain.get("account").decode("utf-8"))
        except (KeyError, ValueError):
            return None

    def _slots(self) -> List[Path]:
        if self._accounts_dir is None or not self._accounts_dir.is_dir():
            return []
        slots = [p for p in self._accounts_dir.iterdir() if (p / "keychain.json").exists()]
        return sorted(slots, key=lambda p: p.stat().st_mtime)

    @staticmethod
    def _slot_account(slot: Path) -> Optional[Dict[str, Any]]:
        try:
            return json.loads(FileKeychain(str(slot / "keychain.json")).get("account").decode("utf-8"))
        except (KeyError, ValueError, OSError):
            return None

    def list_accounts(self) -> List[Dict[str, Any]]:
        with self._slots_lock:
            result = []
            active = self._active_dict()
            if active:
                result.append(_public_account(active, True))
            for slot in self._slots():
                saved = self._slot_account(slot)
                if saved and (not active or account_slot_id(saved) != account_slot_id(active)):
                    result.append(_public_account(saved, False))
            return result

    def park_active(self) -> None:
        if self._accounts_dir is None:
            raise AppStoreError("saving several sign-ins is not available here")
        with self._slots_lock:
            active = self._active_dict()
            if not active:
                return
            slot = self._accounts_dir / account_slot_id(active)
            if slot.exists():
                shutil.rmtree(slot, ignore_errors=True)
            slot.mkdir(parents=True, exist_ok=True)
            FileKeychain(str(slot / "keychain.json")).set("account", json.dumps(active, indent=2).encode("utf-8"))
            with self._cookie_store._lock:
                self._cookie_store.jar.save(str(slot / "cookies.lwp"))
            atomic_write_text(slot / "guid.txt", self._machine.device_guid(), private=True)
            # Leave nothing active: the next sign-in gets its own cookies and
            # device GUID.
            self._keychain.remove("account")
            self._cookie_store.clear()
            self._machine.reset_device_guid()
            while len(self._slots()) > self.MAX_SAVED:
                shutil.rmtree(self._slots()[0], ignore_errors=True)

    def switch_account(self, slot_id: str) -> Account:
        if self._accounts_dir is None:
            raise AppStoreError("saving several sign-ins is not available here")
        with self._slots_lock:
            target = self._accounts_dir / slot_id
            saved = self._slot_account(target) if slot_id.isalnum() else None
            if not saved:
                raise AppStoreError("no such saved sign-in")
            active = self._active_dict()
            if active and account_slot_id(active) == slot_id:
                return Account.from_dict(active)
            # Read the target before parking the active one (same folder
            # names can't clash: ids differ).
            from .cookie_store import PersistentCookieJar

            cookies = list(PersistentCookieJar(str(target / "cookies.lwp"))) if (target / "cookies.lwp").exists() else []
            try:
                guid = (target / "guid.txt").read_text(encoding="utf-8").strip()
            except OSError:
                guid = ""
            self.park_active()
            self._keychain.set("account", json.dumps(saved, indent=2).encode("utf-8"))
            with self._cookie_store._lock:
                jar = self._cookie_store.jar
                for cookie in cookies:
                    jar.set_cookie(cookie)
                jar.save()
            if guid:
                atomic_write_text(Path(self._machine.config_path("device_guid.txt")), guid, private=True)
            shutil.rmtree(target, ignore_errors=True)
            return Account.from_dict(saved)

    def forget_account(self, slot_id: str) -> None:
        if self._accounts_dir is None or not slot_id.isalnum():
            return
        with self._slots_lock:
            target = self._accounts_dir / slot_id
            if target.is_dir():
                shutil.rmtree(target, ignore_errors=True)


# ---------------------------------------------------------------------------
# Per-browser (encrypted cookie)
# ---------------------------------------------------------------------------

_APPLE_COOKIE_DOMAINS = ("apple.com", "itunes.com", "mzstatic.com")


def _cookie_to_dict(c: Cookie) -> Dict[str, Any]:
    return {
        "n": c.name,
        "v": c.value,
        "d": c.domain,
        "p": c.path,
        "s": c.secure,
        "e": c.expires,
        "ds": c.domain_specified,
        "di": c.domain_initial_dot,
        "ps": c.path_specified,
        "po": c.port,
        "pos": c.port_specified,
        "ver": c.version,
        "dc": c.discard,
        "r": dict(getattr(c, "_rest", {}) or {}),
    }


def _cookie_from_dict(d: Dict[str, Any]) -> Cookie:
    return Cookie(
        version=d.get("ver") or 0,
        name=d["n"],
        value=d.get("v"),
        port=d.get("po"),
        port_specified=bool(d.get("pos")),
        domain=d.get("d", ""),
        domain_specified=bool(d.get("ds")),
        domain_initial_dot=bool(d.get("di")),
        path=d.get("p", "/"),
        path_specified=bool(d.get("ps")),
        secure=bool(d.get("s")),
        expires=d.get("e"),
        discard=bool(d.get("dc")),
        comment=None,
        comment_url=None,
        rest=d.get("r") or {},
    )


class _BrowserCookieContainer:
    """Duck-types CookieStore (``.jar`` / ``.save()`` / ``.clear()``) for HTTPClient."""

    def __init__(self, state: "BrowserState", jar: CookieJar) -> None:
        self._state = state
        self.jar = jar

    def attach_to(self, session) -> None:
        session.cookies = self.jar

    def save(self) -> None:
        self._state.dirty = True

    def drop_session_cookies(self) -> None:
        # Not stored in the cookie; drops those set earlier in this request.
        from .cookie_store import drop_session_cookies

        drop_session_cookies(self.jar)

    def clear(self) -> None:
        self.jar.clear()
        self._state.dirty = True


class BrowserState(SessionState):
    def __init__(
        self,
        sid: Optional[str] = None,
        issued_at: Optional[float] = None,
        guid: Optional[str] = None,
        account: Optional[Dict[str, Any]] = None,
        cookies: Optional[List[Dict[str, Any]]] = None,
        saved: Optional[List[Dict[str, Any]]] = None,
    ) -> None:
        # Other sign-ins of this browser: [{"account", "cookies", "guid"}]
        self._saved: List[Dict[str, Any]] = [s for s in (saved or []) if isinstance(s, dict) and s.get("account")]
        self.sid = sid or secrets.token_urlsafe(16)
        self.issued_at = issued_at or time.time()
        self._guid = guid
        self._account = account
        jar = CookieJar()
        for raw in cookies or []:
            try:
                jar.set_cookie(_cookie_from_dict(raw))
            except Exception:  # noqa: BLE001 - skip a malformed entry, keep the rest
                continue
        self._cookies = _BrowserCookieContainer(self, jar)
        self.dirty = False
        self.cleared = False

    # -- SessionState -----------------------------------------------------

    @property
    def owner_id(self) -> str:  # type: ignore[override]
        return f"s:{self.sid}"

    @property
    def cookies(self) -> _BrowserCookieContainer:
        return self._cookies

    def load_account(self) -> Account:
        if not self._account:
            raise AppStoreError("no active account")
        return Account.from_dict(self._account)

    def save_account(self, account: Account) -> None:
        self._account = account.to_dict()
        self.dirty = True

    def clear(self) -> None:
        self._account = None
        self._guid = None
        self._cookies.jar.clear()
        self.cleared = True
        self.dirty = True

    def device_guid(self) -> str:
        if not self._guid:
            self._guid = _new_guid()
            self.dirty = True
        return self._guid

    def on_login(self) -> None:
        # New session id on every successful sign-in (no session fixation;
        # also orphans any download jobs tied to a previous identity).
        self.sid = secrets.token_urlsafe(16)
        self.issued_at = time.time()
        self.cleared = False
        self.dirty = True

    # -- serialisation ----------------------------------------------------

    def to_payload(self) -> Dict[str, Any]:
        cookies = []
        now = time.time()
        for cookie in self._cookies.jar:
            if cookie.is_expired(now) or cookie.expires is None:
                # Session cookies don't outlive the request (see
                # cookie_store.drop_session_cookies).
                continue
            domain = (cookie.domain or "").lstrip(".").lower()
            if not domain.endswith(_APPLE_COOKIE_DOMAINS):
                continue
            cookies.append(_cookie_to_dict(cookie))
        return {
            "v": 1,
            "sid": self.sid,
            "iat": self.issued_at,
            "guid": self._guid,
            "account": self._account,
            "cookies": cookies,
            "saved": self._saved,
        }

    @classmethod
    def from_payload(cls, payload: Dict[str, Any]) -> "BrowserState":
        return cls(
            sid=payload.get("sid"),
            issued_at=payload.get("iat"),
            guid=payload.get("guid"),
            account=payload.get("account"),
            cookies=payload.get("cookies"),
            saved=payload.get("saved"),
        )

    # -- several saved sign-ins ---------------------------------------------

    def _persistent_cookies(self) -> List[Dict[str, Any]]:
        now = time.time()
        return [
            _cookie_to_dict(c) for c in self._cookies.jar
            if not c.is_expired(now) and c.expires is not None
            and (c.domain or "").lstrip(".").lower().endswith(_APPLE_COOKIE_DOMAINS)
        ]

    def list_accounts(self) -> List[Dict[str, Any]]:
        result = [_public_account(self._account, True)] if self._account else []
        active_id = account_slot_id(self._account) if self._account else None
        for slot in self._saved:
            if account_slot_id(slot["account"]) != active_id:
                result.append(_public_account(slot["account"], False))
        return result

    def park_active(self) -> None:
        if not self._account:
            return
        slot_id = account_slot_id(self._account)
        self._saved = [s for s in self._saved if account_slot_id(s["account"]) != slot_id]
        self._saved.append({"account": self._account, "cookies": self._persistent_cookies(), "guid": self._guid})
        self._saved = self._saved[-self.MAX_SAVED:]
        self._account = None
        self._guid = None
        self._cookies.jar.clear()
        self.dirty = True

    def switch_account(self, slot_id: str) -> Account:
        slot = next((s for s in self._saved if account_slot_id(s["account"]) == slot_id), None)
        if slot is None:
            if self._account and account_slot_id(self._account) == slot_id:
                return Account.from_dict(self._account)
            raise AppStoreError("no such saved sign-in")
        self._saved = [s for s in self._saved if s is not slot]
        self.park_active()
        self._account = slot["account"]
        self._guid = slot.get("guid")
        for raw in slot.get("cookies") or []:
            try:
                self._cookies.jar.set_cookie(_cookie_from_dict(raw))
            except Exception:  # noqa: BLE001
                continue
        self.cleared = False
        self.dirty = True
        return Account.from_dict(self._account)

    def forget_account(self, slot_id: str) -> None:
        before = len(self._saved)
        self._saved = [s for s in self._saved if account_slot_id(s["account"]) != slot_id]
        if len(self._saved) != before:
            self.dirty = True


class BrowserSessionCodec:
    """BrowserState in encrypted cookies, split into ``<name>0``, ``<name>1``...
    (~4 KB each); HttpOnly, SameSite=Lax, Secure over HTTPS."""

    CHUNK_SIZE = 3800
    MAX_CHUNKS = 10

    def __init__(self, secret: bytes, cookie_name: str = "ipatool_s", max_age_days: int = 30) -> None:
        self._cipher = SessionCipher(secret)
        self._name = cookie_name
        self._max_age = int(max_age_days * 86400)

    @property
    def backend(self) -> str:
        return self._cipher.backend

    # -- secret -----------------------------------------------------------

    @staticmethod
    def load_or_create_secret(path: Path) -> bytes:
        """32-byte server key. On Windows it's stored DPAPI-protected (bound
        to this user and machine); elsewhere owner-only (0600)."""
        from . import dpapi, vault

        header = b"DPAPI1"
        if path.exists():
            data = vault.unwrap(path.read_bytes())
            if data.startswith(header):
                try:
                    secret = dpapi.unprotect(data[len(header):])
                    if len(secret) >= 32:
                        return secret
                except Exception as exc:  # noqa: BLE001 - other user/machine
                    logger.warning("%s can't be decrypted here (%s); creating a new key - browsers sign in again", path.name, exc)
            elif len(data) >= 32:
                make_private(path)
                if dpapi.available():  # migrate a plain key file
                    try:
                        atomic_write_bytes(path, vault.wrap(header + dpapi.protect(data)), private=True)
                    except Exception as exc:  # noqa: BLE001
                        logger.warning("could not protect %s with DPAPI: %s", path.name, exc)
                return data
        secret = secrets.token_bytes(32)
        stored = header + dpapi.protect(secret) if dpapi.available() else secret
        atomic_write_bytes(path, vault.wrap(stored), private=True)
        return secret

    # -- request/response -------------------------------------------------

    def _existing_chunk_names(self, request_cookies) -> List[str]:
        return [name for name in request_cookies.keys() if name.startswith(self._name) and name[len(self._name):].isdigit()]

    def load(self, request_cookies) -> BrowserState:
        parts = []
        for index in range(self.MAX_CHUNKS):
            part = request_cookies.get(f"{self._name}{index}")
            if part is None:
                break
            parts.append(part)
        if not parts:
            return BrowserState()

        try:
            encoded = "".join(parts)
            blob = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
            payload = json.loads(self._cipher.open(blob).decode("utf-8"))
        except (SessionDecryptError, ValueError, binascii.Error, UnicodeDecodeError) as exc:
            # Tampered, from a different server secret, or truncated by the
            # browser. Start fresh and overwrite the bad cookie.
            logger.info("discarding unreadable session cookie: %s", exc)
            state = BrowserState()
            state.dirty = True
            state.cleared = True
            return state

        state = BrowserState.from_payload(payload)
        if time.time() - state.issued_at > self._max_age:
            logger.info("session expired")
            state = BrowserState()
            state.dirty = True
            state.cleared = True
        return state

    def store(self, state: BrowserState, request, response) -> None:
        if not state.dirty:
            return

        existing = self._existing_chunk_names(request.cookies)
        secure = bool(request.is_secure)
        path = request.script_root or "/"

        if state.cleared and not state._account and not state._guid and not len(state.cookies.jar) and not state._saved:
            for name in existing:
                response.delete_cookie(name, path=path, secure=secure, httponly=True, samesite="Lax")
            return

        blob = self._cipher.seal(json.dumps(state.to_payload(), separators=(",", ":")).encode("utf-8"))
        encoded = base64.urlsafe_b64encode(blob).decode("ascii").rstrip("=")
        chunks = [encoded[i : i + self.CHUNK_SIZE] for i in range(0, len(encoded), self.CHUNK_SIZE)]
        if len(chunks) > self.MAX_CHUNKS:
            # Too big (shouldn't happen): keep the account, drop Apple's cookies.
            logger.warning("session too large (%d chunks), dropping Apple cookies", len(chunks))
            for slot in state._saved:  # saved sign-ins first (they keep account and GUID)
                slot["cookies"] = []
            state.cookies.jar.clear()
            blob = self._cipher.seal(json.dumps(state.to_payload(), separators=(",", ":")).encode("utf-8"))
            encoded = base64.urlsafe_b64encode(blob).decode("ascii").rstrip("=")
            chunks = [encoded[i : i + self.CHUNK_SIZE] for i in range(0, len(encoded), self.CHUNK_SIZE)]

        remaining = max(60, int(self._max_age - (time.time() - state.issued_at)))
        written = set()
        for index, chunk in enumerate(chunks):
            name = f"{self._name}{index}"
            written.add(name)
            response.set_cookie(
                name,
                chunk,
                max_age=remaining,
                path=path,
                secure=secure,
                httponly=True,
                samesite="Lax",
            )
        for name in existing:
            if name not in written:
                response.delete_cookie(name, path=path, secure=secure, httponly=True, samesite="Lax")
