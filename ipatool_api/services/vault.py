"""Optional master-password encryption of the secrets in ~/.ipatool (sign-ins,
cookies, saved accounts, session key, the collector's token and profiles).

A random 256-bit data key encrypts the files (HMAC-SHA256 CTR + HMAC tag); it
is stored only wrapped with a key derived from the password (scrypt N=2^17,
r=8, p=1; PBKDF2-SHA512 600k where Python lacks scrypt). Standard library
only, the same on every platform. Server and collector share the vault.
Writing while it is on but locked raises VaultLockedError.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import threading
import unicodedata
from pathlib import Path
from typing import Dict, List, Optional

from .securefile import atomic_write_bytes, atomic_write_text
from .session_crypto import SessionCipher, SessionDecryptError

HEADER = b"PYIPATOOL-VAULT1\n"
ENV_PASSWORD = "IPATOOL_MASTER_PASSWORD"
MIN_PASSWORD_LENGTH = 8

# Secret files, relative to ~/.ipatool (server local mode, browser-session
# key, saved accounts, collector token and profiles).
SECRET_FILES = (
    "keychain.json", "cookies.lwp", "session_secret.key",
    "accounts/*/keychain.json", "accounts/*/cookies.lwp",
    "collector/secrets.json",
    "collector/profiles/*/keychain.json", "collector/profiles/*/cookies.lwp",
    "collector/*/keychain.json", "collector/*/cookies.lwp",
)

_SCRYPT = {"n": 1 << 17, "r": 8, "p": 1}
_PBKDF2 = {"hash": "sha512", "iterations": 600_000}

_lock = threading.RLock()
_data_key: Optional[bytes] = None
_cipher: Optional[SessionCipher] = None


class VaultError(Exception):
    pass


class VaultLockedError(VaultError):
    """The vault is on but not unlocked in this process."""


def home() -> Path:
    return Path.home() / ".ipatool"


def vault_path() -> Path:
    return home() / "vault.json"


# -- state -----------------------------------------------------------------------


def _read_meta() -> Optional[Dict]:
    try:
        meta = json.loads(vault_path().read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except (OSError, ValueError) as exc:
        raise VaultError(f"{vault_path()} is unreadable: {exc}") from exc
    return meta if isinstance(meta, dict) else None


def status() -> str:
    """"on", "off" (turned off or declined) or "undecided" (never asked)."""
    meta = _read_meta()
    if meta is None:
        return "undecided"
    return "on" if meta.get("enabled") else "off"


def is_unlocked() -> bool:
    return _cipher is not None


def kdf_name() -> str:
    meta = _read_meta() or {}
    return str((meta.get("kdf") or {}).get("name") or "")


# -- key derivation ----------------------------------------------------------------


def _scrypt_available() -> bool:
    return hasattr(hashlib, "scrypt")


def _normalize(password: str) -> bytes:
    return unicodedata.normalize("NFC", password).encode("utf-8")


def _derive(password: str, kdf: Dict) -> bytes:
    salt = base64.b64decode(kdf["salt"])
    if kdf["name"] == "scrypt":
        if not _scrypt_available():
            raise VaultError("this Python has no scrypt (hashlib) - the vault was made where it had")
        n, r, p = int(kdf["n"]), int(kdf["r"]), int(kdf["p"])
        return hashlib.scrypt(_normalize(password), salt=salt, n=n, r=r, p=p, dklen=32,
                              maxmem=256 * r * n + (64 << 20))
    if kdf["name"] == "pbkdf2":
        return hashlib.pbkdf2_hmac(kdf["hash"], _normalize(password), salt, int(kdf["iterations"]), 32)
    raise VaultError(f"unknown key derivation {kdf['name']!r}")


def _new_kdf() -> Dict:
    salt = base64.b64encode(secrets.token_bytes(16)).decode("ascii")
    if _scrypt_available():
        return {"name": "scrypt", "salt": salt, **_SCRYPT}
    return {"name": "pbkdf2", "salt": salt, **_PBKDF2}


def _wrap_key(password: str, data_key: bytes) -> Dict:
    kdf = _new_kdf()
    sealed = SessionCipher(_derive(password, kdf), stdlib_only=True).seal(data_key)
    return {"kdf": kdf, "key": base64.b64encode(sealed).decode("ascii")}


def _unwrap_key(password: str, meta: Dict) -> bytes:
    try:
        key = SessionCipher(_derive(password, meta["kdf"]), stdlib_only=True).open(base64.b64decode(meta["key"]))
    except SessionDecryptError as exc:
        raise VaultError("wrong master password") from exc
    except (KeyError, TypeError, ValueError) as exc:
        raise VaultError(f"{vault_path()} is damaged") from exc
    if len(key) != 32:
        raise VaultError(f"{vault_path()} is damaged")
    return key


def _set_key(key: Optional[bytes]) -> None:
    global _data_key, _cipher
    _data_key = key
    _cipher = SessionCipher(key, stdlib_only=True) if key else None


def check_password_strength(password: str) -> Optional[str]:
    """A reason the password is too weak, or None."""
    if len(password) < MIN_PASSWORD_LENGTH:
        return f"не короче {MIN_PASSWORD_LENGTH} символов"
    if len(set(password)) < 4:
        return "слишком однообразный"
    return None


# -- unlocking / turning on and off ------------------------------------------------


def unlock(password: str) -> None:
    """Raises VaultError("wrong master password") on a wrong password."""
    with _lock:
        meta = _read_meta()
        if not meta or not meta.get("enabled"):
            raise VaultError("encryption is off")
        _set_key(_unwrap_key(password, meta))


def verify_password(password: str) -> bool:
    """Is this the master password? (Checks it the full, slow way; doesn't
    change anything - for confirming risky actions in an unlocked program.)"""
    with _lock:
        meta = _read_meta()
        if not meta or not meta.get("enabled"):
            return False
        try:
            _unwrap_key(password, meta)
        except VaultError:
            return False
        return True


def lock() -> None:
    with _lock:
        _set_key(None)


def decline() -> None:
    """"Not now" at the first start: don't ask again (can be turned on later)."""
    with _lock:
        if _read_meta() is None:
            _write_meta({"version": 1, "enabled": False})


def enable(password: str) -> List[Path]:
    """Turn encryption on with this password and encrypt the existing secret
    files. Returns the files encrypted."""
    weak = check_password_strength(password)
    if weak:
        raise VaultError(f"master password is too weak: {weak}")
    with _lock:
        if status() == "on":
            raise VaultError("encryption is already on")
        key = secrets.token_bytes(32)
        _set_key(key)
        _write_meta({"version": 1, "enabled": True, **_wrap_key(password, key)})
        return _convert(encrypt=True)


def disable(password: str) -> List[Path]:
    """Turn encryption off - only with the master password (also when the
    vault is already unlocked): the files are decrypted back."""
    with _lock:
        if status() != "on":
            raise VaultError("encryption is off")
        meta = _read_meta() or {}
        _set_key(_unwrap_key(password, meta))  # raises "wrong master password"
        done = _convert(encrypt=False)
        _write_meta({"version": 1, "enabled": False})
        _set_key(None)
        return done


def change_password(old: str, new: str) -> None:
    weak = check_password_strength(new)
    if weak:
        raise VaultError(f"master password is too weak: {weak}")
    with _lock:
        meta = _read_meta()
        if not meta or not meta.get("enabled"):
            raise VaultError("encryption is off")
        key = _unwrap_key(old, meta)
        _set_key(key)
        _write_meta({"version": 1, "enabled": True, **_wrap_key(new, key)})


def reset() -> List[Path]:
    """Forgotten password: delete the encrypted secret files and the vault -
    there is no other way back (sign in again, save the token again). Plain
    files are kept. Returns the files deleted."""
    with _lock:
        deleted = []
        for path in secret_files():
            try:
                if path.read_bytes().startswith(HEADER):
                    path.unlink()
                    deleted.append(path)
            except OSError:
                continue
        try:
            vault_path().unlink()
        except FileNotFoundError:
            pass
        _set_key(None)
        return deleted


def _write_meta(meta: Dict) -> None:
    atomic_write_text(vault_path(), json.dumps(meta, indent=1), private=True)


def secret_files() -> List[Path]:
    base = home()
    found: List[Path] = []
    for pattern in SECRET_FILES:
        for path in sorted(base.glob(pattern)):
            if path.is_file() and path not in found:
                found.append(path)
    return found


def _convert(encrypt: bool) -> List[Path]:
    done = []
    for path in secret_files():
        try:
            raw = path.read_bytes()
        except OSError:
            continue
        if raw.startswith(HEADER) == encrypt:
            continue  # already as wanted
        data = seal(raw) if encrypt else open_bytes(raw)
        atomic_write_bytes(path, data, private=True)
        done.append(path)
    return done


# -- the file layer ------------------------------------------------------------------


def seal(data: bytes) -> bytes:
    with _lock:
        if _cipher is None:
            raise VaultLockedError("encryption is on but the vault is locked")
        return HEADER + base64.b64encode(_cipher.seal(data)) + b"\n"


def open_bytes(raw: bytes) -> bytes:
    with _lock:
        if _cipher is None:
            raise VaultLockedError("this file is encrypted with the master password - unlock first")
        try:
            return _cipher.open(base64.b64decode(raw[len(HEADER):].strip()))
        except (SessionDecryptError, ValueError) as exc:
            raise VaultError("encrypted file is damaged or from another vault") from exc


def wrap(data: bytes) -> bytes:
    """What to write to disk: encrypted when the vault is on (raises
    VaultLockedError if it's on but locked), unchanged when it's off."""
    if status() == "on":
        return seal(data)
    return data


def unwrap(raw: bytes) -> bytes:
    """File contents as read from disk -> the plain contents."""
    if raw.startswith(HEADER):
        return open_bytes(raw)
    return raw


def password_from_environment() -> Optional[str]:
    value = os.environ.get(ENV_PASSWORD)
    return value if value else None
