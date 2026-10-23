"""Last current version id seen per app (~/.ipatool/known_versions.json): a
fallback for Arcade games when apps.apple.com rate-limits. Public data only."""
from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path
from typing import Dict, Optional, Tuple

_MAX_ENTRIES = 5000


class KnownVersions:
    def __init__(self, path: Path) -> None:
        self._path = Path(path)
        self._lock = threading.Lock()
        self._data: Optional[Dict[str, Dict[str, object]]] = None

    def _load(self) -> Dict[str, Dict[str, object]]:
        if self._data is None:
            try:
                raw = json.loads(self._path.read_text(encoding="utf-8"))
                self._data = raw if isinstance(raw, dict) else {}
            except (OSError, ValueError):
                self._data = {}
        return self._data

    def get(self, app_id) -> Optional[Tuple[str, float]]:
        """(version id, unix time it was seen) or None."""
        with self._lock:
            entry = self._load().get(str(app_id))
        if not isinstance(entry, dict) or not str(entry.get("versionId", "")).isdigit():
            return None
        return str(entry["versionId"]), float(entry.get("seen") or 0)

    def remember(self, app_id, version_id) -> None:
        version_id = str(version_id or "").strip()
        if not version_id.isdigit() or version_id == "0":
            return
        with self._lock:
            data = self._load()
            current = data.get(str(app_id)) or {}
            # Keep the newest id (ids grow with each release).
            if str(current.get("versionId", "")).isdigit() and int(current["versionId"]) > int(version_id):
                return
            data[str(app_id)] = {"versionId": version_id, "seen": int(time.time())}
            if len(data) > _MAX_ENTRIES:
                for key, _ in sorted(data.items(), key=lambda kv: kv[1].get("seen", 0))[: len(data) - _MAX_ENTRIES]:
                    data.pop(key, None)
            try:
                self._path.parent.mkdir(parents=True, exist_ok=True)
                tmp = self._path.with_suffix(".tmp")
                tmp.write_text(json.dumps(data, separators=(",", ":")), encoding="utf-8")
                os.replace(tmp, self._path)
            except OSError:
                pass  # a cache: losing it only costs a lookup
