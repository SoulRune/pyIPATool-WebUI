"""Persistent cookie storage compatible with ``requests`` sessions."""
from __future__ import annotations

import base64
import io
import os
import tempfile
import threading
from http.cookiejar import LWPCookieJar
from pathlib import Path
from typing import Optional

from . import dpapi, vault
from .securefile import make_private, replace_with_retry

# Header of a jar encrypted with Windows DPAPI.
_DPAPI_HEADER = b"#pyIPATool-DPAPI-v1\n"


def drop_session_cookies(jar) -> int:
    """Remove cookies without an expiry (Apple's session cookies), as ipatool's
    jar never keeps them; with them ent/download answers 401."""
    stale = [c for c in list(jar) if c.expires is None]
    for cookie in stale:
        try:
            jar.clear(cookie.domain, cookie.path, cookie.name)
        except KeyError:
            pass
    return len(stale)


class PersistentCookieJar(LWPCookieJar):
    """LWPCookieJar with safe (atomic, owner-only) load/save helpers."""

    def __init__(self, filename: str) -> None:
        super().__init__(filename)
        self._path = Path(filename)
        if self._path.exists():
            make_private(self._path)
            try:
                raw = vault.unwrap(self._path.read_bytes())
                if raw.startswith(_DPAPI_HEADER):
                    text = dpapi.unprotect(base64.b64decode(raw[len(_DPAPI_HEADER):])).decode("utf-8")
                    self._really_load(io.StringIO(text), str(self._path), True, True)
                else:
                    self._really_load(io.StringIO(raw.decode("utf-8")), str(self._path), True, True)
                    if dpapi.available() and len(self):
                        self.save()  # migrate a plain-text jar to DPAPI
            except FileNotFoundError:
                pass
            except vault.VaultError:
                raise  # locked / wrong vault: don't silently start without the cookies
            except Exception:
                # Corrupted cookie jar - start fresh but keep the file around.
                self.clear()

    def save(self, filename=None, ignore_discard: bool = True, ignore_expires: bool = True) -> None:
        # Session cookies (no expiry) are not written, as ipatool's
        # persistent-cookiejar; decided by the expiry, not the discard flag.
        persistent = LWPCookieJar()
        for cookie in list(self):
            if cookie.expires is not None:
                cookie.discard = False
                persistent.set_cookie(cookie)
        target = Path(filename) if filename else self._path
        target.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(prefix=f".{target.name}.", suffix=".tmp", dir=str(target.parent))
        os.close(fd)
        try:
            make_private(tmp_name)
            text = "#LWP-Cookies-2.0\n" + persistent.as_lwp_str(ignore_discard=ignore_discard, ignore_expires=ignore_expires)
            data = text.encode("utf-8")
            if dpapi.available():
                data = _DPAPI_HEADER + base64.b64encode(dpapi.protect(data))
            Path(tmp_name).write_bytes(vault.wrap(data))
            replace_with_retry(tmp_name, target)
        except BaseException:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
            raise


class CookieStore:
    """Attaches and saves the cookie jar (saving is locked: requests run in parallel)."""

    def __init__(self, path: str) -> None:
        self._path = Path(path)
        self._jar: Optional[PersistentCookieJar] = None
        self._lock = threading.RLock()

    @property
    def jar(self) -> PersistentCookieJar:
        with self._lock:
            if self._jar is None:
                self._jar = PersistentCookieJar(str(self._path))
            return self._jar

    def attach_to(self, session) -> None:
        session.cookies = self.jar

    def save(self) -> None:
        with self._lock:
            self.jar.save()

    def drop_session_cookies(self) -> None:
        """Start an operation without the previous one's session cookies."""
        with self._lock:
            drop_session_cookies(self.jar)

    def clear(self) -> None:
        """Remove all cookies from both the in-memory jar and the file on disk."""
        with self._lock:
            self.jar.clear()
            try:
                if self._path.exists():
                    self._path.unlink()
            except Exception:  # pragma: no cover
                pass
