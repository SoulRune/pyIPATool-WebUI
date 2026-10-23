"""Machine-specific helpers used by the App Store client."""
from __future__ import annotations

import os
import secrets
from pathlib import Path

from .securefile import atomic_write_text


class Machine:
    def home_directory(self) -> str:
        return str(Path.home())

    def config_path(self, *parts: str) -> str:
        base = Path(self.home_directory()) / ".ipatool"
        for part in parts:
            base /= part
        base.parent.mkdir(parents=True, exist_ok=True)
        return str(base)

    def device_guid(self) -> str:
        """The persisted device GUID for App Store sign-in (rotated on sign-out)."""
        env_guid = os.getenv("IPATOOL_DEVICE_GUID", "").strip().upper()
        if env_guid:
            return self._normalize_guid(env_guid)

        guid_path = Path(self.config_path("device_guid.txt"))
        if guid_path.exists():
            raw = guid_path.read_text(encoding="utf-8").strip().upper()
            if raw:
                normalized = self._normalize_guid(raw)
                if normalized == raw:
                    return normalized

        guid = self._normalize_guid(secrets.token_hex(6).upper())
        atomic_write_text(guid_path, guid, private=True)
        return guid

    def reset_device_guid(self) -> None:
        guid_path = Path(self.config_path("device_guid.txt"))
        guid_path.unlink(missing_ok=True)

    def _normalize_guid(self, value: str) -> str:
        cleaned = "".join(ch for ch in value if ch.isalnum()).upper()
        if not cleaned:
            raise ValueError("device guid cannot be empty")
        return cleaned[:12]
