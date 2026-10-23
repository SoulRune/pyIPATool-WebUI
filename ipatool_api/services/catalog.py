"""Private version catalog kept in a (private) GitHub repository.

One JSON file per app, ``<prefix>/<appId>.json`` (default prefix ``apps``)::

    {
      "schema": 1,
      "appId": 1098342019,
      "bundleId": "com.rac7.SneakySasquatch",
      "name": "Sneaky Sasquatch",
      "arcade": true,
      "updatedAt": "2026-10-15T12:00:00Z",
      "latestExternalVersionId": "891379731",
      "versions": {
        "848173393": {"status": "ok", "version": "1.0.6", "build": "...",
                      "releaseDate": "...", "size": 196385412,
                      "minimumOs": "15.0", "checkedAt": "..."},
        "816904780": {"status": "lost", "error": "Subscription Required",
                      "checkedAt": "..."}
      }
    }

``status``: ``ok`` (Apple served the details), ``lost`` (Apple refused this
version to an entitled account), ``unknown`` (not checked yet). ``ok`` versions
may also carry minimumOs, minimumOsName, releaseDateDisplay, artist, genre,
ageRating, copyright.

The web server only reads; the collector writes through ``GitHubCatalog``.
Tokens are never logged.
"""
from __future__ import annotations

import base64
import json
import logging
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

import requests

logger = logging.getLogger(__name__)

SCHEMA = 1
STATUS_OK = "ok"
STATUS_LOST = "lost"
STATUS_UNKNOWN = "unknown"
_API = "https://api.github.com"
_CACHE_TTL = 10 * 60


class CatalogError(RuntimeError):
    pass


class GitHubCatalog:
    def __init__(self, repo: str, token: str, branch: str = "main", prefix: str = "apps", verify=True) -> None:
        repo = (repo or "").strip().strip("/")
        if repo.count("/") != 1 or not all(repo.split("/")):
            raise CatalogError("catalog repository must be given as owner/name")
        if not token:
            raise CatalogError("a GitHub token is required for the catalog repository")
        self.repo = repo
        self.branch = branch or "main"
        self.prefix = (prefix or "apps").strip("/")
        self._verify = verify
        self._session = requests.Session()
        self._session.headers.update({
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "pyIPATool-catalog",
        })

    def describe(self) -> str:
        return f"github:{self.repo}@{self.branch}/{self.prefix}"

    def check(self) -> Tuple[bool, str]:
        """Is the repository (and branch) reachable with this token?"""
        try:
            response = self._session.get(f"{_API}/repos/{self.repo}/branches/{self.branch}", timeout=20, verify=self._verify)
        except requests.RequestException as exc:
            return False, f"request failed: {exc}"
        if response.status_code == 200:
            return True, "reachable"
        if response.status_code == 404:
            return False, "repository or branch not found (or the token has no access to it)"
        return False, f"HTTP {response.status_code}"

    def _url(self, app_id: int) -> str:
        return self._path_url(f"{self.prefix}/{int(app_id)}.json")

    def _path_url(self, path: str) -> str:
        path = "/".join(part for part in str(path).replace("\\", "/").split("/") if part)
        if not path or ".." in path.split("/"):
            raise CatalogError(f"bad repository path: {path!r}")
        return f"{_API}/repos/{self.repo}/contents/{path}"

    def read(self, app_id: int) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
        """(document, blob sha) - (None, None) if the app isn't in the catalog."""
        return self._read_json(self._url(app_id), f"catalog file for app {app_id}")

    def read_path(self, path: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
        """Any JSON file of the repository: (document, sha), (None, None) if absent."""
        return self._read_json(self._path_url(path), path)

    def _read_json(self, url: str, what: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
        try:
            response = self._session.get(url, params={"ref": self.branch}, timeout=20, verify=self._verify)
        except requests.RequestException as exc:
            raise CatalogError(f"catalog request failed: {exc}") from exc
        if response.status_code == 404:
            return None, None
        if response.status_code in (401, 403):
            raise CatalogError(f"catalog access denied (HTTP {response.status_code}) - check the token and repository")
        if response.status_code != 200:
            raise CatalogError(f"catalog returned HTTP {response.status_code}")
        body = response.json()
        content = body.get("content")
        if body.get("encoding") == "base64" and content is not None:
            raw = base64.b64decode(content)
        else:  # files over 1 MB come without inline content
            raw_response = self._session.get(body.get("download_url") or "", timeout=30, verify=self._verify)
            raw_response.raise_for_status()
            raw = raw_response.content
        try:
            document = json.loads(raw)
        except ValueError as exc:
            raise CatalogError(f"{what} isn't valid JSON") from exc
        return document, body.get("sha")

    def list_app_ids(self) -> List[str]:
        """App ids that have a file in the catalog folder."""
        try:
            response = self._session.get(f"{_API}/repos/{self.repo}/contents/{self.prefix}",
                                         params={"ref": self.branch}, timeout=20, verify=self._verify)
        except requests.RequestException as exc:
            raise CatalogError(f"catalog request failed: {exc}") from exc
        if response.status_code == 404:
            return []
        if response.status_code != 200:
            raise CatalogError(f"catalog returned HTTP {response.status_code}")
        names = [item.get("name", "") for item in response.json() if isinstance(item, dict)]
        return sorted((n[:-5] for n in names if n.endswith(".json") and n[:-5].isdigit()), key=int)

    def write(self, app_id: int, document: Dict[str, Any], sha: Optional[str], message: str) -> str:
        """Create/replace the app's file; returns the new blob sha. Raises
        CatalogError("conflict") if the file changed since ``sha``."""
        return self._write_json(self._url(app_id), document, sha, message)

    def write_path(self, path: str, document: Dict[str, Any], sha: Optional[str], message: str) -> str:
        """Create/replace any JSON file of the repository (same rules as write)."""
        return self._write_json(self._path_url(path), document, sha, message)

    def _write_json(self, url: str, document: Dict[str, Any], sha: Optional[str], message: str) -> str:
        payload = {
            "message": message,
            "content": base64.b64encode(dump(document).encode("utf-8")).decode("ascii"),
            "branch": self.branch,
        }
        if sha:
            payload["sha"] = sha
        try:
            response = self._session.put(url, json=payload, timeout=30, verify=self._verify)
        except requests.RequestException as exc:
            raise CatalogError(f"catalog write failed: {exc}") from exc
        if response.status_code in (409, 422) and sha:
            raise CatalogError("conflict")
        if response.status_code in (401, 403, 404):
            raise CatalogError(f"catalog write denied (HTTP {response.status_code}) - the token needs "
                               "Contents: read and write on this repository")
        if response.status_code not in (200, 201):
            raise CatalogError(f"catalog write returned HTTP {response.status_code}: {response.text[:200]}")
        return response.json().get("content", {}).get("sha", "")


def dump(document: Dict[str, Any]) -> str:
    return json.dumps(document, ensure_ascii=False, indent=1, sort_keys=True) + "\n"


def new_document(app_id: int) -> Dict[str, Any]:
    return {"schema": SCHEMA, "appId": int(app_id), "versions": {}}


def merge_version(document: Dict[str, Any], version_id: str, entry: Dict[str, Any]) -> None:
    """Record a check result without losing what is already known: details
    of a version are kept when a later check fails, and a transient failure
    never downgrades ``ok``/``lost``."""
    versions = document.setdefault("versions", {})
    old = versions.get(version_id, {})
    status = entry.get("status")
    if status == STATUS_UNKNOWN and old.get("status") in (STATUS_OK, STATUS_LOST):
        merged = dict(old)
        merged["lastError"] = entry.get("error")
        merged["lastErrorAt"] = entry.get("checkedAt")
        versions[version_id] = merged
        return
    merged = dict(old)
    merged.update({k: v for k, v in entry.items() if v is not None})
    if status == STATUS_OK:
        merged.pop("error", None)
    versions[version_id] = merged


def sorted_versions(document: Dict[str, Any]) -> List[Tuple[str, Dict[str, Any]]]:
    items = [(vid, info) for vid, info in (document.get("versions") or {}).items() if str(vid).isdigit()]
    return sorted(items, key=lambda item: int(item[0]), reverse=True)


class StaticCatalog:
    """Read-only catalog over plain HTTPS, no token: a public repository via
    raw.githubusercontent.com (CDN, no API rate limit) or any static host
    serving ``<base>/<appId>.json``."""

    def __init__(self, base_url: str, verify=True) -> None:
        base_url = (base_url or "").strip().rstrip("/")
        if not base_url.startswith("https://"):
            raise CatalogError("catalog URL must start with https://")
        self.base_url = base_url
        self._verify = verify
        self._session = requests.Session()
        self._session.headers["User-Agent"] = "pyIPATool-catalog"

    @classmethod
    def for_public_repo(cls, repo: str, branch: str = "main", prefix: str = "apps", verify=True) -> "StaticCatalog":
        repo = (repo or "").strip().strip("/")
        if repo.count("/") != 1 or not all(repo.split("/")):
            raise CatalogError("catalog repository must be given as owner/name")
        return cls(f"https://raw.githubusercontent.com/{repo}/{branch or 'main'}/{(prefix or 'apps').strip('/')}", verify)

    def describe(self) -> str:
        return self.base_url

    def read(self, app_id: int) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
        try:
            response = self._session.get(f"{self.base_url}/{int(app_id)}.json", timeout=20, verify=self._verify)
        except requests.RequestException as exc:
            raise CatalogError(f"catalog request failed: {exc}") from exc
        if response.status_code == 404:
            return None, None
        if response.status_code != 200:
            raise CatalogError(f"catalog returned HTTP {response.status_code}")
        try:
            return response.json(), None
        except ValueError as exc:
            raise CatalogError(f"catalog file for app {app_id} isn't valid JSON") from exc

    def check(self) -> Tuple[bool, str]:
        try:
            self._session.get(f"{self.base_url}/0.json", timeout=20, verify=self._verify)
        except requests.RequestException as exc:
            return False, f"request failed: {exc}"
        return True, "reachable (public, no token)"


# ---------------------------------------------------------------------------
# Read-only access for the web server
# ---------------------------------------------------------------------------

_catalog = None  # GitHubCatalog or StaticCatalog
_cache: Dict[Tuple[str, int], Tuple[float, Optional[Dict[str, Any]]]] = {}
_lock = threading.Lock()


def configure(repo: str, token: str, branch: str = "main", prefix: str = "apps", verify=True) -> None:
    """Private repository with a read token, or - without a token - a public
    repository read through raw.githubusercontent.com."""
    global _catalog
    if token:
        _catalog = GitHubCatalog(repo, token, branch, prefix, verify)
    else:
        _catalog = StaticCatalog.for_public_repo(repo, branch, prefix, verify)
    _cache.clear()


def configure_url(base_url: str, verify=True) -> None:
    global _catalog
    _catalog = StaticCatalog(base_url, verify)
    _cache.clear()


def configured() -> bool:
    return _catalog is not None


def describe() -> Optional[str]:
    return _catalog.describe() if _catalog else None


def _cached_read(source, key: str, app_id: int) -> Optional[Dict[str, Any]]:
    now = time.monotonic()
    cache_key = (key, int(app_id))
    with _lock:
        cached = _cache.get(cache_key)
        if cached and now - cached[0] < _CACHE_TTL:
            return cached[1]
    try:
        document, _sha = source.read(int(app_id))
    except CatalogError as exc:
        logger.warning("version catalog %s unavailable for app %s: %s", key, app_id, exc)
        return None
    with _lock:
        _cache[cache_key] = (now, document)
    return document


def fetch(app_id: int) -> Optional[Dict[str, Any]]:
    """The externally configured catalog's document for the app (cached 10
    min); None if absent, not configured or unreachable (logged)."""
    if _catalog is None or not app_id:
        return None
    return _cached_read(_catalog, "external", app_id)


_builtin = None
_builtin_failed = False


def fetch_builtin(config: Dict[str, Any], app_id: int) -> Optional[Dict[str, Any]]:
    """The built-in catalog (BUILTIN_CATALOG in appstore.py, next to the
    community sources); None if it isn't filled in, absent or unreachable."""
    global _builtin, _builtin_failed
    if not app_id or not (config or {}).get("repo") or _builtin_failed:
        return None
    if _builtin is None:
        try:
            if config.get("token"):
                _builtin = GitHubCatalog(config["repo"], config["token"], config.get("branch", "main"),
                                         config.get("prefix", "apps"))
            else:
                _builtin = StaticCatalog.for_public_repo(config["repo"], config.get("branch", "main"),
                                                         config.get("prefix", "apps"))
        except CatalogError as exc:
            logger.warning("built-in version catalog disabled: %s", exc)
            _builtin_failed = True
            return None
    return _cached_read(_builtin, "built-in", app_id)


def clear_cache() -> int:
    """Forget cached catalog files (the next read fetches them again)."""
    with _lock:
        count = len(_cache)
        _cache.clear()
    return count


def any_configured(builtin_config: Optional[Dict[str, Any]] = None) -> bool:
    """Is a private catalog (built-in or external) set up at all?"""
    return _catalog is not None or bool((builtin_config or {}).get("repo"))


def check_access() -> Tuple[bool, str]:
    """Startup check: can the token read the repository?"""
    if _catalog is None:
        return False, "not configured"
    return _catalog.check()
