"""Lightweight keychain-compatible storage for account credentials."""
from __future__ import annotations

import base64
import json
import logging
import threading
from pathlib import Path
from typing import Dict

from . import dpapi, vault
from .securefile import atomic_write_bytes, make_private

logger = logging.getLogger(__name__)

# On-disk format when the contents are encrypted with Windows DPAPI.
_DPAPI_FORMAT = "dpapi-v1"


class FileKeychain:
    """Stores opaque blobs keyed by string identifiers on disk."""

    def __init__(self, path: str) -> None:
        self._path = Path(path)
        self._lock = threading.RLock()
        self._data: Dict[str, str] = {}
        self._load()

    def _load(self) -> None:
        if not self._path.exists():
            return
        # Older versions created this file world-readable (0644).
        make_private(self._path)
        try:
            raw = vault.unwrap(self._path.read_bytes()).decode("utf-8")
        except vault.VaultError:
            raise  # locked / wrong vault: never treat it as "signed out"
        except Exception:
            return
        if not raw.strip():
            return
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            return
        if isinstance(payload, dict) and payload.get("_format") == _DPAPI_FORMAT:
            try:
                decrypted = dpapi.unprotect(base64.b64decode(str(payload.get("data", ""))))
                payload = json.loads(decrypted.decode("utf-8"))
            except Exception as exc:  # noqa: BLE001 - other user/machine, or not Windows
                logger.warning(
                    "%s is encrypted for another Windows user or machine (%s) - sign in again",
                    self._path.name, exc,
                )
                return
        elif isinstance(payload, dict) and payload and dpapi.available():
            # Written by an older version in plain text: re-save encrypted.
            self._data = {str(k): str(v) for k, v in payload.items()}
            try:
                self._persist()
                logger.info("%s is now encrypted with Windows DPAPI", self._path.name)
            except Exception as exc:  # noqa: BLE001
                logger.warning("could not encrypt %s: %s", self._path.name, exc)
            return
        if isinstance(payload, dict):
            self._data = {str(k): str(v) for k, v in payload.items() if not str(k).startswith("_")}

    def _persist(self) -> None:
        payload = json.dumps(self._data, indent=2, sort_keys=True)
        if dpapi.available():
            # Windows: file permissions don't keep other programs of this user
            # out, so encrypt with DPAPI (bound to this user + machine).
            blob = dpapi.protect(payload.encode("utf-8"))
            payload = json.dumps({"_format": _DPAPI_FORMAT, "data": base64.b64encode(blob).decode("ascii")})
        # Atomic and owner-only.
        atomic_write_bytes(self._path, vault.wrap(payload.encode("utf-8")), private=True)

    def get(self, key: str) -> bytes:
        with self._lock:
            encoded = self._data.get(key)
            if encoded is None:
                raise KeyError(key)
            return base64.b64decode(encoded.encode("ascii"))

    def set(self, key: str, data: bytes) -> None:
        with self._lock:
            self._data[key] = base64.b64encode(data).decode("ascii")
            self._persist()

    def remove(self, key: str) -> None:
        with self._lock:
            if key in self._data:
                del self._data[key]
                self._persist()
