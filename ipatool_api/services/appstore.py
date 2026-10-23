"""Re-implementation of the Go App Store client in Python."""
from __future__ import annotations

import hashlib
import logging
import shutil
import struct
import zlib
import base64
import contextlib
import threading
import uuid
import plistlib
import html
import re
import time
from email.utils import parsedate_to_datetime
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple
from zipfile import ZIP_STORED, ZipFile, ZipInfo
from urllib.parse import urljoin, urlparse, urlencode, parse_qs

import requests

from . import constants
from . import platform as platform_module
from . import storefront
from .errors import (
    AppStoreError,
    AuthCodeRequiredError,
    LicenseRequiredError,
    PasswordTokenExpiredError,
    SubscriptionRequiredError,
    TemporarilyUnavailableError,
    AppNotFoundError,
    ArcadeRefusedError,
    ARCADE_NOT_SUBSCRIBED_MESSAGE,
    PlatformLookupEmptyError,
    VersionNotServedError,
)
from .http_client import (
    HTTPClient,
    _normalize_plist_body,
    HTTPClientResponseError,
    HTTPRequest,
    HTTPResult,
    ResponseDecodeError,
    XMLPayload,
)
from . import remote_ipa
from .known_versions import KnownVersions
from . import zipframe
from .machine import Machine
from .models import (
    Account,
    App,
    BagOutput,
    CommunityVersionEntry,
    CommunityVersionsOutput,
    DownloadOutput,
    GetVersionMetadataOutput,
    ListVersionsOutput,
    SAPConfig,
    SearchOutput,
    Sinf,
)
from .redact import redact, redact_text
from .securefile import replace_with_retry
from .state import SessionState

logger = logging.getLogger(__name__)

# Only top-level bundles ("Payload/<Name>.app/Info.plist"), not nested .app ones.
_MAIN_INFO_PLIST_RE = re.compile(r"^Payload/[^/]+\.app/Info\.plist$")
_MAIN_MANIFEST_RE = re.compile(r"^Payload/[^/]+\.app/SC_Info/Manifest\.plist$")
_UNSAFE_FILENAME_CHARS_RE = re.compile(r'[^A-Za-z0-9._\-]+')


class _StorefrontNotFound(AppStoreError):
    pass


_WEB_VERSION_KEY = "\x00externalVersionIdentifier"


def _parse_web_external_version_id(page_html: str, app_id: Any) -> str:
    """The page's own update parameters ("...salableAdamId=<app>&...&appExtVrsId=<N>")
    - matched to this app's id and kept inside one JSON string, because the
    page also carries lockups (with their own version ids) of other apps."""
    match = re.search(
        r"salableAdamId=" + re.escape(str(app_id)) + r"&[^\"\\]*?appExtVrsId=(\d{1,20})(?![0-9])",
        page_html,
    )
    return match.group(1) if match else ""


class _HistoryCache:
    """Process-wide cache of apps.apple.com version histories: 6 h for
    successes, 5 min for failures, one fetch in flight per key."""

    OK_TTL = 6 * 3600
    FAIL_TTL = 5 * 60

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._data: Dict[Tuple[int, str], Tuple[float, Dict[str, str]]] = {}
        self._key_locks: Dict[Tuple[int, str], threading.Lock] = {}

    def get_or_fetch(self, key: Tuple[int, str], fetch: Callable[[], Optional[Dict[str, str]]]) -> Dict[str, str]:
        with self._lock:
            hit = self._data.get(key)
            if hit and hit[0] > time.time():
                return hit[1]
            key_lock = self._key_locks.setdefault(key, threading.Lock())
        with key_lock:
            with self._lock:
                hit = self._data.get(key)
                if hit and hit[0] > time.time():
                    return hit[1]
            result = fetch()
            ttl = self.OK_TTL if result is not None else self.FAIL_TTL
            value = result or {}
            with self._lock:
                self._data[key] = (time.time() + ttl, value)
            return value


_history_cache = _HistoryCache()


def clear_version_caches() -> int:
    """"Clear cache" in the web UI: drop cached version data (not the sign-in
    or URL bag). Returns how many entries were dropped."""
    from . import catalog

    count = catalog.clear_cache()
    for cache in (_CATALOG_CACHE, _ARCADE_CACHE, _MIN_OS_CACHE, _MIN_OS_MISS_CACHE, _APPS_SITE_BACKOFF,
                  _DOWNLOAD_STAGE_HINTS, _ENT_DOWNLOAD_REFUSED):
        with cache._lock:
            count += len(cache._data)
            cache._data.clear()
    with _history_cache._lock:
        count += len(_history_cache._data)
        _history_cache._data.clear()
    return count


def _step_name(url: str) -> str:
    """Short, user-facing name of which Apple call failed."""
    host = urlparse(url).hostname or ""
    if host.startswith("init."):
        return "bag"
    if host.startswith("auth."):
        return "sign-in"
    if "buyProduct" in url:
        return "purchase"
    if "volumeStoreDownloadProduct" in url:
        return "download info"
    return host or "request"


def _unexpected_message(step: str, status: int, content_type: str) -> str:
    kind = (content_type or "no content-type").split(";")[0].strip()
    return f"unexpected response from Apple ({step}: HTTP {status}, {kind})"


@dataclass
class AppStoreConfig:
    state: SessionState
    machine: Machine
    verify: bool | str = True


def validate_authentication_endpoint(endpoint: str) -> str:
    """ipatool v2.6.0 validateAuthenticationEndpoint: only Apple's MZFinance
    authenticate path on buy.itunes.apple.com or a *-buy pod host."""
    # ipatool 1ec8b3e: no credentials, fragment, non-443 port or encoded path.
    # Messages don't echo the URL (it may carry query parameters).
    parsed = urlparse(endpoint or "")
    try:
        port = parsed.port
    except ValueError:
        port = -1
    host = (parsed.hostname or "").lower()
    if (
        parsed.scheme != "https" or not host or parsed.username is not None or parsed.password is not None
        or parsed.fragment or "%" in parsed.path or port not in (None, 443)
    ):
        raise AppStoreError("invalid authentication endpoint")
    if host != constants.PRIVATE_APPSTORE_HOST and not host.endswith("-buy.itunes.apple.com"):
        raise AppStoreError("unsupported authentication endpoint")
    if parsed.path not in (constants.PRIVATE_APPSTORE_API_PATH_AUTH, constants.PRIVATE_APPSTORE_API_PATH_AUTH + "/"):
        raise AppStoreError("unsupported authentication endpoint")
    return endpoint


# Redirects that may replay a signed POST (ipatool http.IsAuthenticationRedirect).
# 303 means "repeat as GET" - not part of this flow.
_AUTH_REDIRECT_STATUSES = (301, 302, 307, 308)


def resolve_authentication_redirect(endpoint: str, location: str) -> str:
    """ipatool 1ec8b3e resolveAuthenticationRedirect: Location may be
    relative to the current endpoint; the result must pass validation."""
    location = (location or "").strip()
    if not location:
        raise AppStoreError("invalid authentication redirect location")
    destination = urljoin(endpoint, location)
    try:
        return validate_authentication_endpoint(destination)
    except AppStoreError as exc:
        parsed = urlparse(destination)
        raise AppStoreError(
            f"invalid authentication redirect: {exc} ({parsed.scheme}://{parsed.hostname}{parsed.path})"
        ) from exc


def normalize_auth_code(code: Optional[str]) -> str:
    """Port of ipatool's normalizeAuthCode (after v2.6.0): strip whitespace and
    bracketed-paste markers, require exactly six digits."""
    if not code:
        return ""
    code = code.strip()
    if code.startswith("\x1b[200~") and code.endswith("\x1b[201~"):
        code = code[len("\x1b[200~") : -len("\x1b[201~")]
    code = "".join(ch for ch in code if not ch.isspace())
    if len(code) != 6 or not all("0" <= ch <= "9" for ch in code):
        raise AppStoreError("2FA code must contain exactly six digits")
    return code


def hardware_id_from_guid(guid: str) -> bytes:
    """The SAP machine id: the GUID's 6 bytes (as ipatool's MAC); a non-hex
    IPATOOL_DEVICE_GUID is hashed to that size."""
    try:
        raw = bytes.fromhex(guid)
        if 1 <= len(raw) <= 20:
            return raw
    except ValueError:
        pass
    return hashlib.sha256(guid.encode("utf-8")).digest()[:6]


def _retry_after_seconds(value: str) -> Optional[float]:
    value = (value or "").strip()
    if not value:
        return None
    if value.isdigit():
        return float(value)
    try:
        from email.utils import parsedate_to_datetime

        when = parsedate_to_datetime(value)
        return max(0.0, when.timestamp() - time.time())
    except (TypeError, ValueError):
        return None


_DOWNLOAD_DISPATCH_HOST = "downloaddispatch.itunes.apple.com"


def _validate_download_endpoint(endpoint: str, path: str) -> str:
    parsed = urlparse(endpoint)
    if (
        parsed.scheme != "https"
        or parsed.netloc != _DOWNLOAD_DISPATCH_HOST
        or parsed.path != path
        or parsed.query
        or parsed.fragment
        or parsed.params
    ):
        raise AppStoreError("invalid download endpoint in bag")
    return endpoint


def _download_data(result: Optional[HTTPResult]) -> Dict[str, Any]:
    if result is None or not isinstance(result.data, dict):
        return {}
    return result.data


def _is_empty_download_response(result: HTTPResult) -> bool:
    data = _download_data(result)
    return (
        result.status_code == 200
        and not data.get("failureType")
        and not data.get("customerMessage")
        and not data.get("songList")
    )


def _is_subscription_required_response(result: Optional[HTTPResult]) -> bool:
    """Apple Arcade over the Configurator route: "Subscription Required"
    (dialog OcelotNotSubscribed) instead of a package."""
    if result is None:
        return False
    data = _download_data(result)
    return not data.get("songList") and (
        data.get("customerMessage") == constants.CUSTOMER_MESSAGE_SUBSCRIPTION_REQUIRED or _is_arcade_not_subscribed(data)
    )


def _is_unavailable_download_response(result: Optional[HTTPResult]) -> bool:
    if result is None:
        return False
    data = _download_data(result)
    message = str(data.get("customerMessage") or "").strip().lower()
    return (
        result.status_code == 200
        and not data.get("failureType")
        and not data.get("songList")
        and (message == "no longer available" or message.endswith(" no longer available"))
    )


def _is_empty_redownload_error(error: AppStoreError) -> bool:
    """ipatool isEmptyRedownloadError: HTTP 500 with an empty body."""
    cause = error.__cause__
    return isinstance(cause, ResponseDecodeError) and cause.status_code == 500 and not cause.body


class _TTLCache:
    def __init__(self, ttl: float) -> None:
        self._ttl = ttl
        self._lock = threading.Lock()
        self._data: Dict[Any, Tuple[float, Any]] = {}

    def get(self, key: Any) -> Any:
        with self._lock:
            hit = self._data.get(key)
            if hit and hit[0] > time.time():
                return hit[1]
            self._data.pop(key, None)
            return None

    def set(self, key: Any, value: Any) -> None:
        with self._lock:
            self._data[key] = (time.time() + self._ttl, value)

    def discard(self, key: Any) -> None:
        with self._lock:
            self._data.pop(key, None)


# The bag's download endpoints change rarely; one fetch per hour is plenty
# (it was fetched again for every single version before).
_URL_BAG_CACHE = _TTLCache(3600)
# The download-product stage that last worked per (account, app): start there,
# fall back to the full chain if it doesn't deliver.
_DOWNLOAD_STAGE_HINTS = _TTLCache(30 * 60)
_ARCADE_CACHE = _TTLCache(6 * 60 * 60)
# (app id, version id) -> (OS name, minimum version) read from that version's
# IPA. A version's package never changes; "" results are kept shorter.
_MIN_OS_CACHE = _TTLCache(7 * 24 * 60 * 60)
_MIN_OS_MISS_CACHE = _TTLCache(30 * 60)
# apps.apple.com answered 429 (rate limit, per IP): don't ask it again for a
# while - every extra request only extends the block.
_APPS_SITE_BACKOFF = _TTLCache(3 * 60)
_KNOWN_VERSIONS: Dict[str, KnownVersions] = {}
_KNOWN_VERSIONS_LOCK = threading.Lock()
# apps.apple.com catalog API answers per (app, storefront, platform).
_CATALOG_CACHE = _TTLCache(30 * 60)
_CATALOG_URL = "https://apps.apple.com/api/apps/v1/catalog/{cc}/apps/{id}?platform={platform}"
# (DSID, device GUID) that ent/download answered 401/403: skip it for a while.
_ENT_DOWNLOAD_REFUSED = _TTLCache(5 * 60)
_ENT_DOWNLOAD_REFUSAL_MINUTES = 5

# ent/download (ipatool 3411d57): the bag's "volumeStoreDownloadProduct" now
# points here; requests carry a kbsync blob generated by Apple's StoreAgent.
_ENT_DOWNLOAD_PATH = "/WebObjects/DownloadDispatch.woa/wa/ent/download"
_ENT_DOWNLOAD_USER_AGENT = "Configurator/2.18 (Macintosh; OS X 15.3.2; 24D81) AppleWebKit/0620.2.4.11.6"
# kbsync per (DSID, device GUID). In memory only: the server is long-lived,
# so a blob is generated (~10 s) once per account/device per server run.
_KBSYNC_LOCK = threading.Lock()
# (DSID, GUID) -> (blob, monotonic time Apple last served a response with it)
_KBSYNC_CACHE: Dict[Tuple[int, str], Tuple[str, float]] = {}
# One generation at a time per account/device; parallel requests reuse it.
_KBSYNC_KEY_LOCKS: Dict[Tuple[int, str], threading.Lock] = {}
# A blob that worked this recently isn't blamed for an HTTP 5xx: that's Apple
# failing on the version (seen for some old versions, every time).
_KBSYNC_TRUSTED_SECONDS = 15 * 60


def _kbsync_cached(dsid: int, guid: str) -> str:
    with _KBSYNC_LOCK:
        return (_KBSYNC_CACHE.get((dsid, guid)) or ("", 0.0))[0]


def _kbsync_recently_ok(dsid: int, guid: str, blob: str) -> bool:
    with _KBSYNC_LOCK:
        entry = _KBSYNC_CACHE.get((dsid, guid))
    return bool(entry) and entry[0] == blob and time.monotonic() - entry[1] < _KBSYNC_TRUSTED_SECONDS


def _kbsync_store(dsid: int, guid: str, blob: str) -> None:
    with _KBSYNC_LOCK:
        _KBSYNC_CACHE[(dsid, guid)] = (blob, time.monotonic())


def _kbsync_invalidate(dsid: int, guid: str, blob: str) -> None:
    with _KBSYNC_LOCK:
        if (_KBSYNC_CACHE.get((dsid, guid)) or ("", 0.0))[0] == blob:
            del _KBSYNC_CACHE[(dsid, guid)]


def _kbsync_key_lock(dsid: int, guid: str) -> threading.Lock:
    with _KBSYNC_LOCK:
        return _KBSYNC_KEY_LOCKS.setdefault((dsid, guid), threading.Lock())


def _apple_server_error(exc: Exception) -> bool:
    metadata = getattr(exc, "metadata", None)
    status = metadata.get("status") if isinstance(metadata, dict) else None
    return isinstance(status, int) and status >= 500


def _kbsync_accepted(exc: Exception) -> bool:
    """Did Apple accept the kbsync blob of this failed ent/download request
    (it answered about the app or version) - as opposed to refusing the
    request itself (HTTP 401/403) or no answer at all?"""
    if isinstance(exc, VersionNotServedError):
        return True
    metadata = getattr(exc, "metadata", None)
    if not isinstance(metadata, dict) or metadata.get("status") in (401, 403):
        return False
    # Only answers clearly about the app; an unknown failure (5002) may be the blob's fault.
    return (str(metadata.get("failureType") or "") in (constants.FAILURE_LICENSE_NOT_FOUND,
                                                         constants.FAILURE_TEMPORARILY_UNAVAILABLE)
            or metadata.get("customerMessage") == constants.CUSTOMER_MESSAGE_SUBSCRIPTION_REQUIRED)


def forget_kbsync(dsid: str) -> None:
    """Drop cached kbsync blobs of an account (sign-out; ipatool revoke)."""
    try:
        key = int(dsid)
    except (TypeError, ValueError):
        return
    with _KBSYNC_LOCK:
        for cache_key in [k for k in _KBSYNC_CACHE if k[0] == key]:
            del _KBSYNC_CACHE[cache_key]


def _ent_download_endpoint(url: str) -> Optional[str]:
    """ipatool newDownloadEndpoint(endpoint, entDownloadPath): only the exact
    ent/download URL on downloaddispatch.itunes.apple.com."""
    parsed = urlparse(url or "")
    if (
        parsed.scheme != "https" or parsed.hostname != "downloaddispatch.itunes.apple.com" or parsed.port not in (None, 443)
        or parsed.path != _ENT_DOWNLOAD_PATH or parsed.query or parsed.fragment or parsed.username or "%" in parsed.path
    ):
        return None
    return url
_STAGE_VOLUME_STORE, _STAGE_REDOWNLOAD, _STAGE_UPDATE = "volumeStore", "redownload", "update"


def _header(headers, name: str) -> Optional[str]:
    if not headers:
        return None
    lower = name.lower()
    for key, value in headers.items():
        if str(key).lower() == lower:
            return value
    return None


def _summarize_auth_statuses(statuses: List[str]) -> str:
    """"HTTP 204, 404" when Apple answered every time (the existing format),
    "HTTP 204, transport error" when connections also failed (ipatool e8a7ba8)."""
    if all(s.isdigit() for s in statuses):
        return "HTTP " + ", ".join(statuses)
    return ", ".join(s if not s.isdigit() else f"HTTP {s}" for s in statuses)


def _apple_reason(metadata: Any) -> str:
    """Short, redacted summary of what Apple said in an error response
    (failureType / customerMessage / dialog text), for log lines."""
    if not isinstance(metadata, dict):
        return ""
    data: Any = metadata
    body = metadata.get("body")
    if not body:
        # Empty body: the status line and Apple's headers are all there is.
        headers = metadata.get("headers") if isinstance(metadata.get("headers"), dict) else {}
        hints = [
            f"{k}: {v}" for k, v in headers.items()
            if str(k).lower() in ("www-authenticate", "x-apple-jingle-correlation-key", "x-apple-application-site")
            or str(k).lower().startswith("x-apple-error")
        ]
        status = metadata.get("status")
        text = "; ".join(([f"HTTP {status}, empty body"] if status else []) + hints)
        return redact_text(text[:300])
    if isinstance(body, (bytes, str)) and body:
        raw = body.encode("utf-8", "replace") if isinstance(body, str) else body
        try:
            data = plistlib.loads(_normalize_plist_body(raw))
        except Exception:  # noqa: BLE001 - not a plist: show a short text excerpt
            text = re.sub(r"<[^>]+>", " ", raw.decode("utf-8", "replace"))
            return redact_text(re.sub(r"\s+", " ", text).strip()[:160])
    if not isinstance(data, dict):
        return ""
    dialog = data.get("dialog") if isinstance(data.get("dialog"), dict) else {}
    metrics = data.get("metrics") if isinstance(data.get("metrics"), dict) else {}
    parts = [
        f"failureType {data['failureType']}" if data.get("failureType") else "",
        str(data.get("customerMessage") or ""),
        str(dialog.get("explanation") or "").replace("\xa0", " "),
        str(metrics.get("dialogId") or ""),
    ]
    return redact_text("; ".join(p for p in parts if p)[:300])


def _is_arcade_not_subscribed(data: Any) -> bool:
    metrics = data.get("metrics") if isinstance(data, dict) else None
    dialog_id = str((metrics or {}).get("dialogId", "")) if isinstance(metrics, dict) else ""
    return "OcelotNotSubscribed" in dialog_id


def _parse_catalog_app(data: Any, app: App, platform: str) -> Dict[str, Any]:
    """Validate an apps.apple.com/api/apps/v1/catalog answer like upstream:
    exactly one item, same id, type "apps", the platform among its device
    families, same bundle id. {} when it doesn't check out."""
    items = data.get("data") if isinstance(data, dict) else None
    if not isinstance(items, list) or len(items) != 1 or not isinstance(items[0], dict):
        return {}
    item = items[0]
    if str(item.get("id")) != str(int(app.id)) or item.get("type") != "apps":
        return {}
    attributes = item.get("attributes") or {}
    ios = (attributes.get("platformAttributes") or {}).get("ios")
    families = attributes.get("deviceFamilies") or []
    if not isinstance(ios, dict) or platform not in families:
        return {}
    bundle_id = str(ios.get("bundleId") or "")
    if app.bundle_id and bundle_id and bundle_id != app.bundle_id:
        return {}
    version = str(ios.get("externalVersionId") or "")
    if not version.isdigit() or int(version) == 0:
        version = ""
    return {"externalVersionId": version, "bundleId": bundle_id, "supportsArcade": bool(attributes.get("supportsArcade"))}


def phone_number_storefront(apple_id: str) -> str:
    """ipatool 93b527a phoneNumberStorefront: a routing hint for phone-number
    Apple Accounts in mainland China and India (the Apple ID sent is unchanged)."""
    number = (apple_id or "").strip().replace(" ", "").replace("-", "")
    international = False
    if number.startswith("+"):
        international, number = True, number[1:]
    elif number.startswith("00"):
        international, number = True, number[2:]
    if not number or not number.isdigit() or not number.isascii():
        return ""
    # Full length first: a local Indian number can itself start with 91.
    if len(number) == 13 and number.startswith("861"):
        return constants.STORE_FRONTS["CN"]
    if len(number) == 12 and number.startswith("91"):
        number = number[2:]
    elif international:
        return ""
    if len(number) == 11 and number[0] == "1":
        return constants.STORE_FRONTS["CN"]
    if not international and len(number) == 11 and number[0] == "0":
        number = number[1:]  # Indian trunk prefix
    if len(number) == 10 and "6" <= number[0] <= "9":
        return constants.STORE_FRONTS["IN"]
    return ""


def _login_headers(apple_id: str) -> Dict[str, str]:
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    storefront = phone_number_storefront(apple_id)
    if storefront:
        headers["X-Apple-Store-Front"] = storefront
    return headers


def _is_retryable_transport_error(cause: Optional[BaseException]) -> bool:
    """ipatool e8a7ba8 retryableAuthenticationError for transport failures:
    timeouts, connection resets and truncated responses - but not TLS
    verification or proxy failures, which a retry won't fix."""
    if cause is None:
        return False
    if isinstance(cause, (requests.exceptions.SSLError, requests.exceptions.ProxyError)):
        return False
    return isinstance(
        cause, (requests.exceptions.Timeout, requests.exceptions.ConnectionError, requests.exceptions.ChunkedEncodingError)
    )


def _describe_auth_response(status: int, headers, body_len: Optional[int]) -> str:
    """Compact diagnostics for a useless sign-in response, for the log and
    the error message (no secrets: status, content type, size, Apple's
    request correlation id)."""
    parts = [f"HTTP {status}"]
    content_type = (_header(headers, "Content-Type") or "").split(";")[0].strip()
    parts.append(content_type or "no content type")
    if body_len is not None:
        parts.append(f"{body_len} bytes")
    if 300 <= status < 400:
        parts.append("no redirect target" if not _header(headers, "Location") else "redirect")
    correlation = _header(headers, "X-Apple-Jingle-Correlation-Key")
    if correlation:
        parts.append(f"Apple request id {correlation}")
    return ", ".join(parts)


# At most this many SAP emulators at once: each maps ~120 MB of guest memory.
_SIGNER_SLOTS = threading.BoundedSemaphore(2)


# Free disk space a download must leave behind (other programs on the server
# need their room too); see _check_disk_space.
DISK_RESERVE_BYTES = 1 << 30


def set_disk_reserve(megabytes: int) -> None:
    global DISK_RESERVE_BYTES
    from . import jobs

    DISK_RESERVE_BYTES = max(0, int(megabytes)) << 20
    jobs.MIN_FREE_BYTES = DISK_RESERVE_BYTES


def _check_disk_space(path: Path, remaining: int, total: int) -> None:
    """Refuse a download that won't fit: the rest of the file, one more copy
    (the archive is rewritten once) and the reserve."""
    try:
        free = shutil.disk_usage(path.parent).free
    except OSError:
        return
    needed = max(0, remaining) + max(0, total) + DISK_RESERVE_BYTES
    if free < needed:
        raise AppStoreError(
            f"not enough free disk space on the server for this download: it needs about "
            f"{needed / 2**30:.1f} GB (the package {total / 2**30:.1f} GB twice while it's prepared, plus "
            f"{DISK_RESERVE_BYTES / 2**30:.1f} GB kept free), {free / 2**30:.1f} GB are free"
        )


def set_emulator_slots(count: int) -> None:
    """How many Apple-signature emulations may run at once (sign-ins and
    download kbsyncs together). Each takes ~400 MB of memory at its peak on
    top of ~190 MB for the loaded Apple files: 1 suits a 1 GB server."""
    global _SIGNER_SLOTS
    _SIGNER_SLOTS = threading.BoundedSemaphore(max(1, int(count)))


class AppStoreService:
    """Port of the Go ``appstore.AppStore`` implementation."""

    def __init__(self, config: AppStoreConfig) -> None:
        self._state = config.state
        self._machine = config.machine
        self._http = HTTPClient(config.state.cookies, verify=config.verify)
        self._verify = config.verify
        self._storage_dir = Path(config.machine.home_directory()) / ".ipatool"
        self._storage_dir.mkdir(parents=True, exist_ok=True)
        with _KNOWN_VERSIONS_LOCK:
            path = str(self._storage_dir / "known_versions.json")
            self._known_versions = _KNOWN_VERSIONS.setdefault(path, KnownVersions(Path(path)))

    # ------------------------------------------------------------------
    # Authentication
    # ------------------------------------------------------------------

    def login(self, email: str, password: str, auth_code: str | None = None, rotate_session: bool = True) -> Account:
        """Sign in the way ipatool v2.6.0 does: endpoint and SAP configuration
        from the bag, every authentication request carrying a fresh
        X-Apple-ActionSignature computed by Apple's own code (see sap/)."""
        auth_code = normalize_auth_code(auth_code)
        guid = self._guid()
        bag = self.bag()
        if bag.sap is None:
            raise AppStoreError("Apple's bag has no SAP signing configuration")

        with _SIGNER_SLOTS:
            # The signer lives in a holder so a retry can swap in a fresh SAP
            # session (see _refresh_auth_context).
            holder = {"signer": self._create_signer(bag.sap, hardware_id_from_guid(guid))}

            def sign(body: bytes) -> bytes:
                return holder["signer"].sign(body)

            def refresh() -> None:
                self._refresh_auth_context(holder, bag.sap, guid)

            self._auth_refresh = refresh
            try:
                account = self._login(email, password, auth_code, guid, bag.auth_endpoint, sign)
            finally:
                self._auth_refresh = None
                try:
                    holder["signer"].close()
                except Exception:  # noqa: BLE001
                    logger.warning("failed to close SAP signer", exc_info=True)

        if rotate_session:
            self._state.on_login()
        self._persist_account(account)
        # The same Apple ID may also be among the saved sign-ins: the new
        # sign-in replaces it.
        try:
            from .state import account_slot_id

            self._state.forget_account(account_slot_id(account.to_dict()))
        except NotImplementedError:
            pass
        return account

    def _create_signer(self, sap_config: SAPConfig, hardware_id: bytes):
        from .sap import SAPError, SAPUnavailableError, Signer, SignerConfig
        from .sap import assets as sap_assets

        config = SignerConfig(
            setup_url=sap_config.setup_url,
            certificate_url=sap_config.certificate_url,
            version=sap_config.version,
            hardware_id=hardware_id,
        )
        try:
            for attempt in range(3):
                try:
                    return Signer(config, cache_dir=self._storage_dir / "sap" / sap_assets.CACHE_VERSION,
                                  verify=self._verify)
                except (requests.ConnectionError, requests.Timeout) as exc:
                    if attempt == 2:
                        raise
                    # A dropped connection / timeout is often momentary.
                    logger.info("sign-in signature: %s to %s - retrying", exc.__class__.__name__, _host_of(exc))
                    time.sleep(2 + 3 * attempt)
            raise RuntimeError("unreachable")
        except SAPUnavailableError as exc:
            raise AppStoreError(
                "App Store sign-in now requires the 'unicorn' package on the server: pip install unicorn"
            ) from exc
        except SAPError as exc:
            raise AppStoreError(f"failed to prepare Apple sign-in signature: {exc}") from exc
        except requests.RequestException as exc:
            raise AppStoreError(
                f"failed to prepare Apple sign-in signature (network): {exc.__class__.__name__} "
                f"connecting to {_host_of(exc)} - Apple's server didn't answer; check the internet connection, "
                "VPN or proxy and try again") from exc

    def _refresh_auth_context(self, holder: Dict[str, Any], sap_config: SAPConfig, guid: str) -> None:
        """New SAP session and TLS connection before retrying a rejected
        sign-in (GUID and cookies kept). Since Sep 2026 a rejected session
        usually stays rejected."""
        try:
            new_signer = self._create_signer(sap_config, hardware_id_from_guid(guid))
        except AppStoreError as exc:
            logger.info("sign-in: could not start a fresh SAP session (%s); retrying with the current one", exc)
        else:
            old, holder["signer"] = holder["signer"], new_signer
            try:
                old.close()
            except Exception:  # noqa: BLE001
                pass
        # Drop pooled connections so the next request opens a new one.
        self._http.signed_session.close()

    def _login(
        self,
        email: str,
        password: str,
        auth_code: str,
        guid: str,
        endpoint: str,
        sign: Callable[[bytes], bytes],
    ) -> Account:
        # ipatool 1ec8b3e: a redirect keeps the attempt and payload, only the
        # endpoint changes; later attempts go to the redirected endpoint.
        request_url = endpoint
        attempt = 1
        redirects = 0
        result: Optional[HTTPResult] = None
        while True:
            request = HTTPRequest(
                method="POST",
                url=request_url,
                headers=_login_headers(email),
                payload=XMLPayload(
                    {
                        "appleId": email,
                        "attempt": str(attempt),
                        "guid": guid,
                        "password": f"{password}{auth_code}",
                        "rmp": "0",
                        "why": "signIn",
                        # Fields AppleMediaServices adds (ipatool 5dc4c80).
                        "createSession": True,
                        "credentialSource": 0,
                        "deviceOffersCheck": "true",
                        "isSilentAuthentication": False,
                        "passwordSettings": {"free": "always", "paid": "always"},
                    }
                ),
                response_format=constants.ResponseFormatXML,
                follow_redirects=False,
                signer=sign,
                timeout=(constants.AUTH_CONNECT_TIMEOUT, constants.AUTH_READ_TIMEOUT),
            )
            stage = "2FA verification" if auth_code else "sign-in"
            if redirects:
                stage += " at Store pod"
            logger.debug("%s attempt %d: POST %s", stage, attempt, request.url.split("?")[0])
            result = self._send_authentication_request(request, stage)
            retry, redirect = self._parse_login_response(result, attempt, auth_code, request_url)
            if not retry:
                break
            if redirect:
                if redirects >= constants.MAX_AUTH_REDIRECTS:
                    raise AppStoreError(f"too many authentication redirects (HTTP {result.status_code})")
                redirects += 1
                request_url = redirect
                continue
            attempt += 1
            if attempt > 4:  # parseLoginResponse only retries attempt 1; belt and braces
                raise AppStoreError("too many login attempts", metadata=result.data)

        try:
            store_front = result.get_header(constants.HTTP_HEADER_STOREFRONT)
        except KeyError as exc:
            raise AppStoreError("missing storefront header") from exc
        try:
            pod = result.get_header(constants.HTTP_HEADER_POD)
        except KeyError:
            pod = None

        account_info = result.data.get("accountInfo", {}) or {}
        address = account_info.get("address", {}) or {}
        return Account(
            email=account_info.get("appleId", email),
            name=" ".join(filter(None, [address.get("firstName"), address.get("lastName")])),
            password_token=result.data.get("passwordToken", ""),
            directory_services_id=result.data.get("dsPersonId", ""),
            store_front=store_front,
            password=password,
            pod=pod,
        )

    def _send_authentication_request(self, request: HTTPRequest, stage: str) -> HTTPResult:
        """ipatool sendAuthenticationRequest: up to 3 re-signed tries on
        non-plist 204/404/429/5xx answers (and a 3xx without Location)."""
        statuses: List[str] = []
        attempt = 0
        while True:
            attempt += 1
            transport_name = ""
            # ipatool: login requests never reuse a pooled connection
            # (DisableKeepAlives on the authentication client).
            self._http.signed_session.close()
            try:
                result = self._send_request(request)
            except AppStoreError as exc:
                cause = exc.__cause__
                if _is_retryable_transport_error(cause):
                    # ipatool e8a7ba8: timeouts and dropped connections are retried
                    # like Apple's non-answers (TLS/proxy failures are not).
                    status, headers, body_len = 0, {}, None
                    metadata = exc.metadata
                    transport_name = cause.__class__.__name__
                elif isinstance(cause, ResponseDecodeError):
                    status, headers, body_len = cause.status_code, cause.headers, len(cause.body or b"")
                    metadata = exc.metadata
                else:
                    raise
            else:
                if not (300 <= result.status_code < 400) or _header(result.headers, "Location"):
                    return result
                status, headers, body_len = result.status_code, result.headers, None
                metadata = {"status": status}

            detail = (
                f"transport error ({transport_name})" if status == 0
                else _describe_auth_response(status, headers, body_len)
            )
            # Since Sep 2026 Apple answers some sign-ins with HTML stubs, 403 included
            # (real sign-in errors are plists with failureType).
            retryable = status in (0, 204, 403, 404, 429) or status // 100 == 5 or 300 <= status < 400
            if not retryable:
                raise AppStoreError(
                    f"{stage} failed: Apple returned no usable authentication response ({detail}); "
                    "try again later or from another network",
                    metadata=metadata,
                )
            statuses.append("transport error" if status == 0 else str(status))
            logger.info("%s: Apple returned %s", stage, detail)
            if attempt >= constants.MAX_AUTH_REQUEST_ATTEMPTS:
                reason = "Apple rate limited authentication" if status == 429 else "Apple returned no usable authentication response"
                raise AppStoreError(
                    f"{stage} failed after {attempt} attempts ({_summarize_auth_statuses(statuses)}): {reason}; "
                    "try again later or from another network",
                    metadata=metadata,
                )
            delay = min(constants.AUTH_RETRY_DELAY * (2 ** (attempt - 1)), constants.MAX_AUTH_RETRY_DELAY)
            requested = _retry_after_seconds(_header(headers, "Retry-After") or "")
            if requested is not None:
                if requested > constants.MAX_AUTH_RETRY_DELAY:
                    raise AppStoreError(
                        f"Apple asked to wait {int(requested)}s before signing in again; try again later",
                        metadata=metadata,
                    )
                delay = max(requested, 1.0)
            logger.info("%s: retrying in %.0fs with a fresh SAP session and connection", stage, delay)
            time.sleep(delay)
            refresh = getattr(self, "_auth_refresh", None)
            if refresh is not None:
                refresh()

    def account_info(self) -> Account:
        return self._state.load_account()

    def revoke(self) -> None:
        """Forget the session: account, cookies and device GUID (a new GUID
        forces a full 2FA sign-in next time)."""
        try:
            forget_kbsync(self._state.load_account().directory_services_id)  # ipatool 3411d57 revoke
        except Exception:  # noqa: BLE001 - nothing signed in
            pass
        try:
            self._http.session.cookies.clear()
        except Exception:  # pragma: no cover - paranoia
            pass
        self._state.clear()

    # ------------------------------------------------------------------
    # Bag retrieval
    # ------------------------------------------------------------------

    def bag(self) -> BagOutput:
        """Fetch Apple's bag: the sign-in endpoint and SAP configuration
        (ipatool v2.6.0 appstore_bag.go, with the same validation)."""
        guid = self._guid()
        request = HTTPRequest(
            method="GET",
            url=f"https://{constants.PRIVATE_INIT_DOMAIN}{constants.PRIVATE_INIT_PATH}?guid={guid}",
            headers={"Accept": "application/xml"},
            payload=None,
            response_format=constants.ResponseFormatXML,
            # ipatool e8a7ba8: the bag request is bounded like login requests.
            timeout=(constants.AUTH_CONNECT_TIMEOUT, constants.AUTH_READ_TIMEOUT),
        )
        result = self._send_request(request)
        if result.status_code != 200:
            raise AppStoreError(f"failed to get bag: HTTP {result.status_code}")
        url_bag = (result.data or {}).get("urlBag", {}) or {}

        auth_endpoint = validate_authentication_endpoint(str(url_bag.get("authenticateAccount", "")))
        # ipatool f9aa653: always the trailing-slash path (the bare one can break).
        parsed_auth = urlparse(auth_endpoint)
        auth_endpoint = parsed_auth._replace(path=constants.PRIVATE_APPSTORE_API_PATH_AUTH + "/").geturl()
        try:
            version = int(str(url_bag.get("sign-sap-version", "")))
        except ValueError as exc:
            raise AppStoreError(f"invalid SAP version {url_bag.get('sign-sap-version')!r} in bag") from exc
        sap = SAPConfig(
            setup_url=str(url_bag.get("sign-sap-setup", "")),
            certificate_url=str(url_bag.get("sign-sap-setup-cert", "")),
            version=version,
        )
        for label, value in (("SAP setup", sap.setup_url), ("SAP setup certificate", sap.certificate_url)):
            parsed = urlparse(value)
            if parsed.scheme != "https" or not parsed.hostname:
                raise AppStoreError(f"invalid {label} endpoint {value!r} in bag")
        if sap.version != constants.SUPPORTED_SAP_VERSION:
            raise AppStoreError(f"unsupported SAP version {sap.version} in bag")
        return BagOutput(auth_endpoint=auth_endpoint, sap=sap)

    # ------------------------------------------------------------------
    # App discovery
    # ------------------------------------------------------------------

    def search(
        self,
        account: Account,
        term: str,
        limit: int = 5,
        include_tvos: bool = False,
        platform: str = "",
        country: str = "",
    ) -> SearchOutput:
        # `country`: search another region's store; downloading is still up to Apple.
        country = (country or self._country_code_from_storefront(account.store_front)).upper()
        if platform == platform_module.PLATFORM_VISIONOS:
            return self._search_visionos(term, limit, country)
        # `platform` uses ipatool's searchEntity() mapping; `include_tvos` is
        # kept for older callers.
        if platform:
            entity = platform_module.search_entity(platform)
        else:
            entity = "software,iPadSoftware"
            if include_tvos:
                entity += ",tvSoftware"
        watch_only = platform == platform_module.PLATFORM_WATCH
        params = {
            "entity": entity,
            # The watch filter drops results, so ask for more and trim after.
            "limit": str(min(limit * 4, 200) if watch_only else limit),
            "media": "software",
            "term": term,
            "country": country,
        }
        url = self._build_query_url(constants.ITUNES_API_SEARCH_PATH, params)
        request = HTTPRequest(
            method="GET",
            url=url,
            headers={},
            payload=None,
            response_format=constants.ResponseFormatJSON,
        )
        result = self._send_request(request)
        items = result.data.get("results", [])
        if watch_only:
            items = [item for item in items if platform_module.has_watch_app(item)][:limit]
            return SearchOutput(count=len(items), results=[App.from_dict(item) for item in items])
        apps = [App.from_dict(item) for item in items]
        return SearchOutput(count=int(result.data.get("resultCount", len(apps))), results=apps)

    def _search_visionos(self, term: str, limit: int, country: str) -> SearchOutput:
        """ipatool searchVisionOS: the apps.apple.com vision search page, then
        iTunes lookup (entity xrosSoftware) to fill in the metadata."""
        page = self._vision_storefront_page(lambda cc: storefront.vision_search_url(term, cc), country, "visionOS search")
        try:
            found = storefront.vision_apps(page, limit)
        except storefront.StorefrontError as exc:
            raise AppStoreError(f"failed to parse visionOS search results: {exc}") from exc
        if not found:
            return SearchOutput(count=0, results=[])
        params = {
            "id": ",".join(str(app["id"]) for app in found),
            "entity": platform_module.search_entity(platform_module.PLATFORM_VISIONOS),
            "media": "software",
            "country": country,
        }
        request = HTTPRequest(
            method="GET",
            url=self._build_query_url(constants.ITUNES_API_LOOKUP_PATH, params),
            headers={},
            payload=None,
            response_format=constants.ResponseFormatJSON,
        )
        hydrated: Dict[int, Dict[str, Any]] = {}
        for lookup_country in dict.fromkeys((country, "us")):  # US: storefronts without visionOS listings
            params["country"] = lookup_country
            request.url = self._build_query_url(constants.ITUNES_API_LOOKUP_PATH, params)
            try:
                for item in self._send_request(request).data.get("results", []):
                    if isinstance(item, dict) and item.get("trackId"):
                        hydrated.setdefault(int(item["trackId"]), item)
            except AppStoreError as exc:
                logger.info("visionOS metadata lookup failed (%s)", exc)
            if hydrated:
                break
        results = []
        for app in found:
            item = hydrated.get(app["id"]) or {"trackId": app["id"], "bundleId": app["bundleId"], "trackName": app["name"]}
            results.append(App.from_dict(item))
        return SearchOutput(count=len(results), results=results)

    def _vision_storefront_page(self, make_url: Callable[[str], str], country: str, what: str) -> bytes:
        """The account's storefront first; storefronts without a Vision Pro
        section (observed: RU answers 404) fall back to the US one - app and
        version ids are the same in every storefront."""
        try:
            return self._storefront_page(make_url(country), what)
        except _StorefrontNotFound:
            if country.lower() == "us":
                raise AppStoreError(f"{what} request failed: HTTP 404")
            logger.info("the %s App Store has no Vision Pro section; using the US one for %s", country.upper(), what)
            try:
                return self._storefront_page(make_url("us"), what)
            except _StorefrontNotFound as exc:
                raise AppStoreError(f"{what} request failed: HTTP 404") from exc

    def _storefront_page(self, url: str, what: str) -> bytes:
        try:
            response = requests.get(
                url, headers={"User-Agent": constants.DEFAULT_USER_AGENT}, timeout=(10, 30), verify=self._verify
            )
        except requests.RequestException as exc:
            raise AppStoreError(f"{what} request failed: {exc}") from exc
        if response.status_code == 404:
            raise _StorefrontNotFound(f"{what} request failed: HTTP 404")
        if response.status_code != 200:
            raise AppStoreError(f"{what} request failed: HTTP {response.status_code}")
        return response.content

    def is_arcade(self, account: Account, app: App) -> bool:
        """Apple Arcade game? The catalog API's supportsArcade, else "no price"
        in the iTunes lookup. Cached; False when unsure."""
        if not app.id:
            return False
        country = self._country_code_from_storefront(account.store_front).lower()
        key = (int(app.id), country)
        cached = _ARCADE_CACHE.get(key)
        if cached is not None:
            return cached
        catalog = self._catalog_app(app, country)
        if catalog is not None:
            arcade = catalog["supportsArcade"]
        else:
            arcade = self._arcade_from_itunes_lookup(app, country)
            if arcade is None:
                return False
        _ARCADE_CACHE.set(key, arcade)
        if arcade:
            logger.info("app %s is an Apple Arcade game", app.id)
        return arcade

    def _arcade_from_itunes_lookup(self, app: App, country: str) -> Optional[bool]:
        request = HTTPRequest(
            method="GET",
            url=self._build_query_url(
                constants.ITUNES_API_LOOKUP_PATH, {"id": str(app.id), "country": country, "media": "software"}
            ),
            headers={},
            payload=None,
            response_format=constants.ResponseFormatJSON,
        )
        try:
            results = self._send_request(request).data.get("results") or []
        except AppStoreError as exc:
            logger.debug("Arcade check for app %s failed: %s", app.id, exc)
            return None
        item = next((r for r in results if isinstance(r, dict) and str(r.get("trackId")) == str(app.id)), None)
        return bool(item) and item.get("kind") == "software" and item.get("price") is None and not item.get("formattedPrice")

    def arcade_latest_version_id(self, account: Account, app: App) -> str:
        """Current externalVersionId of an Arcade game ("" if unknown) - the
        only version Apple serves for Arcade."""
        country_code = self._country_code_from_storefront(account.store_front).lower()
        for country in [country_code] + [c for c in self._LOOKUP_FALLBACK_COUNTRIES if c != country_code]:
            catalog = self._catalog_app(app, country)
            if catalog and catalog.get("externalVersionId"):
                self._known_versions.remember(app.id, catalog["externalVersionId"])
                return catalog["externalVersionId"]
        version = self._web_external_version_id(account, app)
        if version:
            self._known_versions.remember(app.id, version)
            return version
        known = self._known_version_fallback(app)
        if not known:
            logger.info("couldn't resolve the current version of Arcade game %s", app.id)
        return known

    def apps_site_rate_limited(self) -> bool:
        """apps.apple.com is currently rate-limiting this server's IP."""
        return bool(_APPS_SITE_BACKOFF.get("429"))

    def _known_version_fallback(self, app: App) -> str:
        """The last version id seen for this app (any id of an app gets the
        full version list from ent/download), when Apple's lookups failed."""
        known = self._known_versions.get(app.id)
        if not known:
            return ""
        version_id, seen = known
        logger.info(
            "app %s: Apple's lookups gave no current version%s; using the last one seen, %s (%s) - "
            "Apple lists all versions from any of them",
            app.id, " (apps.apple.com is rate-limiting this IP)" if self.apps_site_rate_limited() else "",
            version_id, time.strftime("%Y-%m-%d", time.localtime(seen)) if seen else "date unknown",
        )
        return version_id

    def _catalog_app(self, app: App, country: str, platform: str = "iphone") -> Optional[Dict[str, Any]]:
        """ipatool e3932ce: the App Store catalog API entry (also for Arcade
        games): externalVersionId, bundleId, supportsArcade, or None. Cached."""
        key = (int(app.id), country.lower(), platform)
        cached = _CATALOG_CACHE.get(key)
        if cached is not None:
            return cached or None
        if self.apps_site_rate_limited():
            return None  # asking now would only extend the block
        url = _CATALOG_URL.format(cc=country.lower(), id=int(app.id), platform=platform)
        result: Dict[str, Any] = {}
        try:
            for attempt in (1, 2):
                response = requests.get(
                    url, headers={"User-Agent": constants.DEFAULT_USER_AGENT, "Accept": "application/json"},
                    timeout=10, verify=self._verify,
                )
                if response.status_code != 429 or attempt == 2:
                    break
                time.sleep(2)  # one short retry: brief bursts of 429 do clear
            if response.status_code == 200:
                result = _parse_catalog_app(response.json(), app, platform)
            elif response.status_code == 429:
                _APPS_SITE_BACKOFF.set("429", True)
                logger.info("App Store catalog API: apps.apple.com is rate-limiting this IP (HTTP 429, app %s, %s); "
                            "not asking it again for 3 min", app.id, country.upper())
                return None  # not cached: the app may well be listed
            elif response.status_code >= 500:
                logger.info("App Store catalog API: HTTP %s for app %s in %s", response.status_code, app.id, country.upper())
                return None  # not cached: transient
            else:
                logger.info("App Store catalog API: HTTP %s for app %s in %s", response.status_code, app.id, country.upper())
        except (requests.RequestException, ValueError) as exc:
            logger.info("App Store catalog API request for app %s failed: %s", app.id, exc)
            return None  # not cached: transient
        _CATALOG_CACHE.set(key, result)
        return result or None

    def lookup(self, account: Account, bundle_id: str) -> App:
        country = self._country_code_from_storefront(account.store_front)
        params = {
            "entity": "software,iPadSoftware",
            "limit": "1",
            "media": "software",
            "bundleId": bundle_id,
            "country": country,
        }
        url = self._build_query_url(constants.ITUNES_API_LOOKUP_PATH, params)
        request = HTTPRequest(
            method="GET",
            url=url,
            headers={},
            payload=None,
            response_format=constants.ResponseFormatJSON,
        )
        result = self._send_request(request)
        results = result.data.get("results", [])
        if not results:
            raise AppNotFoundError("app not found", metadata=result.data)
        return App.from_dict(results[0])

    # ------------------------------------------------------------------
    # Purchasing & downloading
    # ------------------------------------------------------------------

    def purchase(self, account: Account, app: App) -> None:
        if app.price and app.price > 0:
            raise AppStoreError("purchasing paid apps is not supported")

        self._start_operation()
        guid = self._guid()
        try:
            self._purchase_with_params(account, app, guid, constants.PRICING_PARAM_APPSTORE)
        except (TemporarilyUnavailableError, SubscriptionRequiredError):
            # Arcade games take the "GAME" pricing (also after "subscription required").
            try:
                self._purchase_with_params(account, app, guid, constants.PRICING_PARAM_ARCADE)
            except (TemporarilyUnavailableError, SubscriptionRequiredError) as exc:
                if self.is_arcade(account, app):
                    raise ArcadeRefusedError(metadata=exc.metadata) from exc
                if isinstance(exc, TemporarilyUnavailableError):
                    # 2059 "ProductNotForSale" to both requests: in practice the
                    # app isn't sold in this account's region, not a hiccup.
                    country = self._country_code_from_storefront(account.store_front).upper()
                    raise AppStoreError(
                        f"Apple won't issue this app to this account (\"not for sale\"). Usually it isn't "
                        f"available in the account's App Store region ({country}) - apps found with another "
                        "search region can only be downloaded by accounts of a region where they're sold.",
                        metadata=exc.metadata,
                    ) from exc
                raise

    def _purchase_with_params(self, account: Account, app: App, guid: str, pricing: str) -> None:
        payload = {
            "appExtVrsId": "0",
            "hasAskedToFulfillPreorder": "true",
            "buyWithoutAuthorization": "true",
            "hasDoneAgeCheck": "true",
            "guid": guid,
            "needDiv": "0",
            "origPage": f"Software-{app.id}",
            "origPageLocation": "Buy",
            "price": "0",
            "pricingParameters": pricing,
            "productType": "C",
            "salableAdamId": app.id,
        }
        pod_prefix = f"p{account.pod}-" if account.pod else ""
        request = HTTPRequest(
            method="POST",
            url=f"https://{pod_prefix}{constants.PRIVATE_APPSTORE_HOST}{constants.PRIVATE_PURCHASE_PATH}",
            headers={
                "iCloud-DSID": account.directory_services_id,
                "X-Dsid": account.directory_services_id,
                "X-Apple-Store-Front": account.store_front,
                "X-Token": account.password_token,
            },
            payload=XMLPayload(payload),
            response_format=constants.ResponseFormatXML,
        )
        result = self._send_request(request)
        failure_type = result.data.get("failureType", "")
        customer_message = result.data.get("customerMessage", "")

        if failure_type == constants.FAILURE_TEMPORARILY_UNAVAILABLE:
            raise TemporarilyUnavailableError("item temporarily unavailable", metadata=result.data)
        if customer_message == constants.CUSTOMER_MESSAGE_SUBSCRIPTION_REQUIRED:
            raise SubscriptionRequiredError("subscription required", metadata=result.data)
        if failure_type == constants.FAILURE_PASSWORD_TOKEN_EXPIRED or customer_message == constants.CUSTOMER_MESSAGE_PASSWORD_CHANGED:
            raise PasswordTokenExpiredError("password token expired", metadata=result.data)
        if failure_type:
            message = customer_message or "purchase failed"
            raise AppStoreError(message, metadata=result.data)

        if result.status_code == 500:
            raise AppStoreError("license already exists", metadata=result.data)

        if result.data.get("jingleDocType") != "purchaseSuccess" or result.data.get("status") != 0:
            raise AppStoreError("failed to complete purchase", metadata=result.data)

    def download(
        self,
        account: Account,
        app: App,
        output_dir: str,
        external_version_id: Optional[str] = None,
        on_progress: Optional["Callable[[int, Optional[int]], None]"] = None,
        on_patch_progress: Optional["Callable[[int, int], None]"] = None,
        platform: str = "",
    ) -> DownloadOutput:
        """Download, patch (iTunesMetadata.plist and SINF are appended) and
        place the IPA in ``output_dir``."""
        self._start_operation()
        guid = self._guid()
        result = self._send_download_request(account, app, guid, external_version_id, platform)
        self._validate_download_result(result)

        items = result.data.get("songList", [])
        if not items:
            raise AppStoreError("invalid download response")

        item = items[0]
        metadata = dict(item.get("metadata", {}))
        version = str(metadata.get("bundleShortVersionString", "unknown"))
        sinfs = [Sinf(id=int(s.get("id", 0)), data=s.get("sinf", b"")) for s in item.get("sinfs", [])]

        destination = self._resolve_destination_path(app, version, output_dir)
        # Unique per call, so two concurrent downloads of the same app/version
        # (two users, or two tabs) can't write into each other's file.
        temp_destination = f"{destination}.{uuid.uuid4().hex[:8]}.part"
        try:
            self._download_file(item.get("URL"), temp_destination, on_progress=on_progress)
            self._finalize_package(temp_destination, metadata, account, sinfs, on_progress=on_patch_progress)
            self._ensure_streaming_framing(temp_destination, on_patch_progress)
            replace_with_retry(temp_destination, destination)
        except BaseException:
            Path(temp_destination).unlink(missing_ok=True)
            raise

        return DownloadOutput(destination_path=destination, sinfs=sinfs)

    def _finalize_package(
        self,
        package_path: str,
        metadata: Optional[Dict[str, Any]],
        account: Optional[Account],
        sinfs: List[Sinf],
        on_progress: Optional["Callable[[int, int], None]"] = None,
    ) -> None:
        additions: Dict[str, bytes] = {}
        if metadata is not None and account is not None:
            additions["iTunesMetadata.plist"] = self._metadata_bytes(metadata, account)

        with ZipFile(package_path, "r") as zf:
            names = zf.namelist()
            if sinfs:
                bundle_name = self._read_bundle_name(zf)
                manifest = self._read_manifest_plist(zf)
                info = self._read_info_plist(zf)

        if not sinfs:
            # ipatool dd28a3a: downloads can come without SINF; inject only what Apple sent.
            logger.info("Apple supplied no SINF for this package; adding metadata only")
        elif manifest:
            for sinf, relative_path in zip(sinfs, manifest.get("SinfPaths", [])):
                additions[f"Payload/{bundle_name}/{relative_path}"] = sinf.data
        elif info:
            executable = info.get("CFBundleExecutable")
            if not executable:
                raise AppStoreError("missing CFBundleExecutable")
            additions[f"Payload/{bundle_name}/SC_Info/{executable}.sinf"] = sinfs[0].data
        else:
            raise AppStoreError("failed to find manifest or info plist")

        if on_progress:
            on_progress(0, 1)

        if not set(additions) & set(names):
            # Apple's entries stay untouched; added ones are STORED with inline
            # sizes, as OTA installers need (ipatool 843f5c6).
            with ZipFile(package_path, "a") as zf:
                for name, data in additions.items():
                    entry = ZipInfo(name, date_time=time.localtime()[:6])
                    entry.compress_type = ZIP_STORED
                    entry.external_attr = 0o644 << 16
                    zf.writestr(entry, data)
        else:
            logger.info("package already contains patched entries, doing a full rewrite")
            self._rewrite_zip(package_path, additions, on_progress=on_progress)

        if on_progress:
            on_progress(1, 1)

    def _ensure_streaming_framing(
        self, package_path: str, on_progress: Optional["Callable[[int, int], None]"] = None
    ) -> None:
        """ipatool v2.6.0's streaming ZIP framing for OTA installs; entries are
        copied raw, nothing is rewritten if the framing is already there."""
        try:
            if zipframe.ensure_streaming_framing(package_path, on_progress=on_progress):
                logger.info("repacked %s with streaming-compatible ZIP framing", Path(package_path).name)
        except (zipframe.ZipFramingError, struct.error, ValueError, EOFError) as exc:
            # Still a valid IPA; only OTA streaming might refuse it.
            logger.warning("could not apply streaming ZIP framing (%s); OTA install may fail", exc)

    def _rewrite_zip(
        self,
        package_path: str,
        replacements: Dict[str, bytes],
        on_progress: Optional["Callable[[int, int], None]"] = None,
    ) -> None:
        """Streaming rewrite: entries are copied through in 1 MB chunks
        instead of being read fully into memory first."""
        source = Path(package_path)
        temp = source.with_name(source.name + ".rewrite")
        try:
            with ZipFile(source, "r") as src_zip, ZipFile(temp, "w", allowZip64=True) as dst_zip:
                entries = [e for e in src_zip.infolist() if e.filename not in replacements]
                total = len(entries) + len(replacements)
                for index, info in enumerate(entries):
                    new_info = ZipInfo(filename=info.filename, date_time=info.date_time)
                    new_info.compress_type = info.compress_type
                    new_info.external_attr = info.external_attr
                    new_info.file_size = info.file_size
                    with src_zip.open(info) as src, dst_zip.open(new_info, "w", force_zip64=info.file_size > 0x7FFFFFFF) as dst:
                        shutil.copyfileobj(src, dst, 1024 * 1024)
                    if on_progress:
                        on_progress(index + 1, total)
                for name, data in replacements.items():
                    entry = ZipInfo(name, date_time=time.localtime()[:6])
                    entry.compress_type = ZIP_STORED
                    entry.external_attr = 0o644 << 16
                    dst_zip.writestr(entry, data)
            replace_with_retry(temp, source)
        except BaseException:
            temp.unlink(missing_ok=True)
            raise

    def _start_operation(self) -> None:
        """Every operation starts without earlier session cookies, as each
        ipatool command does (with them ent/download answers 401)."""
        drop = getattr(self._state.cookies, "drop_session_cookies", None)
        if drop is not None:
            drop()

    def list_versions(
        self, account: Account, app: App, external_version_id: Optional[str] = None, platform: str = ""
    ) -> ListVersionsOutput:
        self._start_operation()
        guid = self._guid()
        with self._noting_route():
            result = self._send_download_request(account, app, guid, external_version_id, platform)
            self._validate_download_result(result)
        item = self._extract_first_item(result)

        metadata = item.get("metadata", {})
        identifiers = metadata.get("softwareVersionExternalIdentifiers")
        if not isinstance(identifiers, list):
            raise AppStoreError("invalid version identifiers", metadata=metadata)
        external_ids = [str(value) for value in identifiers]
        latest = str(metadata.get("softwareVersionExternalIdentifier"))
        self._known_versions.remember(app.id, max(external_ids, key=lambda v: int(v) if v.isdigit() else 0, default=latest))
        return ListVersionsOutput(
            external_version_identifiers=external_ids,
            latest_external_version_id=latest,
        )

    def probe_arcade_versions(
        self, account: Account, app: App, candidates, platform: str = "", limit: int = 12
    ) -> Optional[Tuple[ListVersionsOutput, str]]:
        """Arcade: the version list can be refused for the current version but
        answered for older ones. Try known ids newest first."""
        tried = 0
        for version_id in candidates:
            version_id = str(version_id or "").strip()
            if not version_id.isdigit():
                continue
            if tried >= limit:
                break
            tried += 1
            try:
                output = self.list_versions(account, app, version_id, platform=platform)
            except PasswordTokenExpiredError:
                raise
            except AppStoreError as exc:
                logger.debug("Arcade probe: version %s of app %s refused: %s", version_id, app.id, exc)
                continue
            logger.info("Apple Arcade game %s: Apple answered the version list for pinned version %s (%d tried)",
                        app.id, version_id, tried)
            return output, version_id
        logger.info("Apple Arcade game %s: none of %d known versions got a version list from Apple", app.id, tried)
        return None

    # ------------------------------------------------------------------
    # Version catalogs: the project's own, external ones and community
    # databases (Timbrd, bilin). Unofficial: a listed id isn't a promise that
    # Apple serves it; downloads still go through download().
    # ------------------------------------------------------------------

    # (name, URL, query parameter or None for a path id); bilin wraps the list in {"code", "data"}.
    COMMUNITY_SOURCES = (
        ("timbrd", "https://api.timbrd.com/apple/app-version/index.php", "id"),
        ("bilin", "https://apis.bilin.eu.org/history/{id}", None),
    )
    # The project's catalog (GitHub repo filled by the collector, services/catalog.py),
    # asked before the community ones. Empty "repo" disables it.
    BUILTIN_CATALOG = {
        "repo": "SoulRune/pyIPATool-VerRepo",       # "owner/name"
        "branch": "main",
        "prefix": "apps",
        "token": "",      # read-only fine-grained token (private repository)
    }

    def _community_source(self, name: str, url: str, param: Optional[str], app: App) -> List[CommunityVersionEntry]:
        target = url if param else url.format(id=int(app.id))
        response = self._http.raw_request(
            "GET",
            target,
            params={param: app.id} if param else None,
            timeout=(constants.DEFAULT_CONNECT_TIMEOUT, constants.DEFAULT_READ_TIMEOUT),
        )
        response.raise_for_status()
        data = response.json()
        if isinstance(data, dict):
            data = data.get("data")
        if not isinstance(data, list):
            raise ValueError("unexpected data shape")
        entries = []
        for raw in data:
            if not isinstance(raw, dict) or raw.get("external_identifier") in (None, ""):
                continue
            entries.append(CommunityVersionEntry(
                external_version_id=str(raw.get("external_identifier")),
                bundle_version=str(raw.get("bundle_version", "")).strip(),
                created_at=raw.get("created_at"),
                size=raw.get("size"),
                source=name,
            ))
        return entries

    def _private_catalog_entries(self, app: App) -> Optional[List[CommunityVersionEntry]]:
        """Entries of the private GitHub catalog (services/catalog.py), None
        if it isn't configured or has no file for this app."""
        from . import catalog

        documents = [
            ("catalog", catalog.fetch_builtin(self.BUILTIN_CATALOG, int(app.id))),
            ("catalog-external", catalog.fetch(int(app.id)) if catalog.configured() else None),
        ]
        documents = [(name, doc) for name, doc in documents if doc]
        if not documents:
            return None
        entries: Dict[str, CommunityVersionEntry] = {}
        for source, document in documents:
            for version_id, info in catalog.sorted_versions(document):
                if version_id in entries:
                    entries[version_id].also_in.append(f"{source}:{info.get('status') or catalog.STATUS_UNKNOWN}")
                    continue
                entries[version_id] = self._catalog_entry(version_id, info, source)
        return sorted(entries.values(), key=lambda e: int(e.external_version_id), reverse=True)

    @staticmethod
    def _catalog_entry(version_id: str, info: Dict[str, Any], source: str) -> CommunityVersionEntry:
        from . import catalog

        size = info.get("size")
        return CommunityVersionEntry(
            external_version_id=version_id,
            bundle_version=str(info.get("version") or ""),
            created_at=info.get("releaseDate"),
            size=size if isinstance(size, int) else None,
            source=source,
            status=str(info.get("status") or catalog.STATUS_UNKNOWN),
            checked_at=info.get("checkedAt"),
            build=str(info["build"]) if info.get("build") else None,
            minimum_os=str(info["minimumOs"]) if info.get("minimumOs") else None,
            release_date_display=str(info["releaseDateDisplay"]) if info.get("releaseDateDisplay") else None,
            artist=str(info["artist"]) if info.get("artist") else None,
            genre=str(info["genre"]) if info.get("genre") else None,
            age_rating=str(info["ageRating"]) if info.get("ageRating") else None,
            copyright=str(info["copyright"]) if info.get("copyright") else None,
        )

    def private_catalog_configured(self) -> bool:
        from . import catalog

        return catalog.any_configured(self.BUILTIN_CATALOG)

    def private_catalog_versions(self, app: App) -> Tuple[List[CommunityVersionEntry], str, str]:
        """Only the private catalog(s): (entries newest first, last update
        of the app's file, its bundle id). ([], "", "") if no catalog has this app."""
        from . import catalog

        if not app.id:
            return [], "", ""
        documents = [doc for doc in (catalog.fetch_builtin(self.BUILTIN_CATALOG, int(app.id)),
                                     catalog.fetch(int(app.id)) if catalog.configured() else None) if doc]
        entries = self._private_catalog_entries(app) or []
        updated = max((str(doc.get("updatedAt") or "") for doc in documents), default="")
        bundle_id = next((str(doc["bundleId"]) for doc in documents if doc.get("bundleId")), "")
        return entries, updated, bundle_id

    def list_versions_community(self, app: App) -> CommunityVersionsOutput:
        """Version ids from the project's catalog, an external one, Timbrd and
        bilin, merged in that order (first catalog wins)."""
        if not app.id:
            raise AppStoreError("app id is required for community version lookup")
        merged: Dict[str, CommunityVersionEntry] = {}
        used: List[str] = []
        errors: List[str] = []
        private = self._private_catalog_entries(app)
        if private is not None:
            used.extend(sorted({entry.source for entry in private}))
            for entry in private:
                merged.setdefault(entry.external_version_id, entry)
        for name, url, param in self.COMMUNITY_SOURCES:
            try:
                entries = self._community_source(name, url, param, app)
            except (requests.exceptions.RequestException, ValueError) as exc:
                errors.append(f"{name}: {exc}")
                logger.info("community catalog %s failed for app %s: %s", name, app.id, exc)
                continue
            used.append(name)
            for entry in entries:
                existing = merged.get(entry.external_version_id)
                if existing is None:
                    merged[entry.external_version_id] = entry
                elif name not in existing.also_in:
                    # Cross-check: which other catalogs know this id too.
                    existing.also_in.append(name)
        if not used:
            raise AppStoreError("community version lookup failed (" + "; ".join(errors) + ")")
        entries = sorted(merged.values(), key=lambda e: (e.created_at or "", e.external_version_id), reverse=True)
        return CommunityVersionsOutput(source="+".join(used), entries=entries)

    # ------------------------------------------------------------------
    # Platforms (ipatool v2.3.0 platform version lookup): the MDM lookup gives
    # a platform's latest external version id, which list_versions() and
    # download() then use to get that platform's build.
    # ------------------------------------------------------------------

    # Tried when the account's storefront returns nothing (seen for RU); an
    # external version id is the same in every storefront.
    _LOOKUP_FALLBACK_COUNTRIES = ("us", "gb")

    def lookup_latest_external_version_id(self, account: Account, app: App, platform: str) -> str:
        if not app.id:
            raise AppStoreError("app id is required for platform version lookup")

        country_code = self._country_code_from_storefront(account.store_front).lower()
        if platform == platform_module.PLATFORM_VISIONOS:
            # ipatool lookupLatestVisionOSExternalVersionID: from the app's
            # apps.apple.com page (?platform=vision) purchase configuration.
            page = self._vision_storefront_page(
                lambda cc: storefront.vision_product_url(app.id, cc), country_code, "visionOS version lookup"
            )
            try:
                return storefront.vision_external_version_id(page, app.id)
            except storefront.StorefrontError as exc:
                raise PlatformLookupEmptyError(f"visionOS version lookup: {exc}") from exc
        # ipatool e5211d6: consumer catalogs first (some storefronts lack the enterprise listing).
        catalogs = [platform_module.metadata_platform(platform)]
        if platform in (platform_module.PLATFORM_IPHONE, platform_module.PLATFORM_IPAD):
            catalogs += ["iphone", "ipad"]
        # Last resort (not in ipatool): other storefronts; the id is the same everywhere.
        attempts = [(country_code, c) for c in catalogs] + [
            (country, catalogs[0]) for country in self._LOOKUP_FALLBACK_COUNTRIES if country != country_code
        ]
        first_error: Optional[AppStoreError] = None
        for country, catalog in attempts:
            try:
                version_id = self._platform_version_lookup(app, catalog, country)
            except PlatformLookupEmptyError as exc:
                if first_error is None:
                    first_error = exc
                continue
            if country != country_code:
                logger.info(
                    "latest-version lookup is empty for storefront %s; using version %s of app %s from the %s storefront",
                    country_code.upper(), version_id, app.id, country.upper(),
                )
            elif catalog != catalogs[0]:
                logger.debug("latest-version lookup: %s catalog empty, found %s in the %s catalog", catalogs[0], version_id, catalog)
            self._known_versions.remember(app.id, version_id)
            return version_id
        if platform in (platform_module.PLATFORM_IPHONE, platform_module.PLATFORM_IPAD):
            # ipatool e3932ce: Arcade games are only in the App Store catalog API.
            for country in [country_code] + [c for c in self._LOOKUP_FALLBACK_COUNTRIES if c != country_code]:
                catalog = self._catalog_app(app, country, platform)
                if catalog and catalog.get("externalVersionId"):
                    logger.info(
                        "app %s isn't in Apple's MDM catalogs (e.g. Apple Arcade); using version %s from the App Store catalog API (%s)",
                        app.id, catalog["externalVersionId"], country.upper(),
                    )
                    self._known_versions.remember(app.id, catalog["externalVersionId"])
                    return catalog["externalVersionId"]
            # Last resort: the public App Store page also shows the app's
            # current version id.
            web_version = self._web_external_version_id(account, app)
            if web_version:
                logger.info(
                    "app %s isn't in Apple's catalogs (e.g. Apple Arcade); using version %s from its App Store page",
                    app.id, web_version,
                )
                self._known_versions.remember(app.id, web_version)
                return web_version
            known = self._known_version_fallback(app)
            if known:
                return known
        if first_error is None:  # unreachable: the loop always tries at least once
            raise PlatformLookupEmptyError("platform version lookup returned no app")
        raise first_error

    def _platform_version_lookup(self, app: App, catalog: str, country_code: str) -> str:
        metadata_platform = catalog
        params = {
            "version": "2",
            "id": str(app.id),
            "p": "mdm-lockup",
            "caller": "MDM",
            "platform": metadata_platform,
            "cc": country_code,
            "l": "en",
        }
        url = "https://uclient-api.itunes.apple.com/WebObjects/MZStorePlatform.woa/wa/lookup?" + urlencode(params)
        request = HTTPRequest(
            method="GET",
            url=url,
            headers={},
            payload=None,
            response_format=constants.ResponseFormatJSON,
        )
        result = self._send_request(request)

        data = result.data if isinstance(result.data, dict) else {}
        results = data.get("results", {}) if isinstance(data.get("results"), dict) else {}
        item = results.get(str(app.id))
        if not item:
            raise PlatformLookupEmptyError("platform version lookup returned no app", metadata=data)

        offers = item.get("offers") or []
        if not offers:
            raise PlatformLookupEmptyError("platform version lookup returned no offers", metadata=data)

        offer = offers[0]
        version_info = offer.get("version") or {}
        external_version_id = str(version_info.get("externalId") or "")

        if not external_version_id:
            buy_params = offer.get("buyParams", "")
            parsed = parse_qs(buy_params)
            values = parsed.get("appExtVrsId")
            external_version_id = values[0] if values else ""

        if not external_version_id:
            raise AppStoreError("platform version lookup returned no external version id", metadata=data)

        return external_version_id

    def validate_package_platform(self, package_path: str, platform: str) -> None:
        """Check the IPA supports the requested platform (ipatool
        validatePackagePlatform, extended to iPhone/iPad)."""
        wanted = {
            platform_module.PLATFORM_APPLETV: "AppleTVOS",
            platform_module.PLATFORM_VISIONOS: "XROS",
        }.get(platform, "iPhoneOS")
        # Apple Watch: an iPhone app carrying its watch app, or (ipatool
        # 4484b55) a watch-only app whose package declares WatchOS.
        also_ok = ("WatchOS",) if platform == platform_module.PLATFORM_WATCH else ()
        with ZipFile(package_path) as zf:
            for name in zf.namelist():
                # Only the main app (Payload/X.app/Info.plist), not nested
                # watch/extension bundles, which declare their own platforms.
                if not name.startswith("Payload/") or not name.endswith(".app/Info.plist") or name.count("/") != 2:
                    continue
                try:
                    data = zf.read(name)
                    info = plistlib.loads(data)
                except Exception:
                    continue
                supported = info.get("CFBundleSupportedPlatforms")
                if wanted == "iPhoneOS" and supported is None:
                    # ipatool 1b9ff28: legacy iOS apps predate the key. Only a
                    # missing declaration qualifies; an empty one does not.
                    return
                if wanted in (supported or []) or any(p in (supported or []) for p in also_ok):
                    return
                break  # the main app's Info.plist decides

        if wanted != "iPhoneOS":
            raise AppStoreError(f"downloaded package does not declare {wanted} support")
        raise AppStoreError(
            "Apple returned a package for another platform (e.g. Apple TV) - pick a specific version from the list"
        )

    def get_version_metadata(self, account: Account, app: App, version_id: str) -> GetVersionMetadataOutput:
        self._start_operation()
        guid = self._guid()
        with self._noting_route():
            result = self._send_download_request(account, app, guid, version_id)
            self._validate_download_result(result)
        item = self._extract_first_item(result)

        metadata = item.get("metadata", {})
        asset_info = item.get("asset-info", {})
        
        display_version = str(metadata.get("bundleShortVersionString", "N/A"))
        release = self._release_date_from_metadata(metadata, result.headers)
        history_date = self._app_store_history_dates(account, app).get(display_version)
        if history_date:
            release = self._parse_apple_date(history_date)
        release_display = self._release_date_display(account, app, metadata, release)

        age_ratings = metadata.get("appAgeRatings", {})
        us_rating = age_ratings.get("US", {})
        min_os_name, min_os = self._minimum_os(app, version_id, item.get("URL"), asset_info.get("file-size"))

        return GetVersionMetadataOutput(
            display_version=display_version,
            build_number=str(metadata.get("bundleVersion", "N/A")),
            release_date=release,
            release_date_display=release_display,
            file_size=asset_info.get("file-size", 0),
            bundle_id=str(metadata.get("softwareVersionBundleId", "N/A")),
            artist_name=str(metadata.get("artistName", "N/A")),
            item_name=str(metadata.get("itemName", "N/A")),
            genre=str(metadata.get("genre", "N/A")),
            age_rating=str(us_rating.get("label", "N/A")),
            requires_rosetta=bool(metadata.get("requiresRosetta", False)),
            runs_on_apple_silicon=bool(metadata.get("runsOnAppleSilicon", False)),
            copyright_info=str(metadata.get("copyright", "N/A")),
            minimum_os=min_os,
            minimum_os_name=min_os_name,
        )

    @contextlib.contextmanager
    def _noting_route(self):
        """Errors from the legacy endpoints after ent/download gave no answer
        get ``not_checked``: not Apple's verdict on the version."""
        try:
            yield
        except AppStoreError as exc:
            skip = getattr(self, "_ent_skip", "")
            if skip and not getattr(exc, "not_checked", ""):
                exc.not_checked = skip
            raise

    def _minimum_os(self, app: App, version_id: str, url: Optional[str], size: Any = None) -> Tuple[str, str]:
        """(OS name, minimum version) of this version, read from its IPA's
        Info.plist with a few small range requests; ("", "") if that fails
        (the version list must not break over it)."""
        key = (str(app.id), str(version_id))
        cached = _MIN_OS_CACHE.get(key) or _MIN_OS_MISS_CACHE.get(key)
        if cached is not None:
            return cached
        if not url:
            return "", ""

        def get(spec: str) -> requests.Response:
            response = self._http.raw_request("GET", url, headers={"Range": spec}, stream=True, timeout=(5, 10))
            if response.status_code != 206:  # never pull the whole IPA for this
                response.close()
                raise remote_ipa.RemoteZipError(f"no range support (HTTP {response.status_code})")
            return response

        total = [int(size) if str(size or "").isdigit() and int(size) > 0 else 0]

        def fetch(start: int, end: int) -> bytes:
            # Apple's CDN answers 501 to suffix ranges ("bytes=-N"), so the
            # tail is asked for by absolute offsets from the archive's size.
            if start < 0:
                if not total[0]:
                    probe = get("bytes=0-0")
                    try:
                        total[0] = int(probe.headers.get("Content-Range", "").rsplit("/", 1)[-1])
                    except ValueError:
                        raise remote_ipa.RemoteZipError("CDN didn't report the file size")
                    finally:
                        probe.close()
                start, end = max(0, total[0] + start), total[0] - 1
            response = get(f"bytes={start}-{end}")
            try:
                return response.content
            finally:
                response.close()

        try:
            result = remote_ipa.minimum_os(remote_ipa.read_info_plist(fetch))
        except (remote_ipa.RemoteZipError, requests.RequestException, OSError, ValueError,
                struct.error, zlib.error) as exc:
            logger.info("minimum OS for %s/%s unavailable: %s", app.id, version_id, exc)
            _MIN_OS_MISS_CACHE.set(key, ("", ""))
            return "", ""
        if result[1]:
            _MIN_OS_CACHE.set(key, result)
        else:
            _MIN_OS_MISS_CACHE.set(key, result)
        return result

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _persist_account(self, account: Account) -> None:
        self._state.save_account(account)

    def _parse_login_response(
        self, result: HTTPResult, attempt: int, auth_code: str, endpoint: str
    ) -> Tuple[bool, Optional[str]]:
        """ipatool parseLoginResponse (1ec8b3e) -> (retry, redirect).
        ``endpoint`` is where this request went (relative Locations resolve
        against it); a redirect is returned only for a redirect response."""
        status = result.status_code
        data = result.data if isinstance(result.data, dict) else {}
        failure_type = data.get("failureType", "")
        customer_message = data.get("customerMessage", "")

        if 300 <= status < 400:
            try:
                location = result.get_header("Location")
            except KeyError as exc:
                raise AppStoreError(f"authentication redirect is missing Location (HTTP {status})") from exc
            if status not in _AUTH_REDIRECT_STATUSES:
                raise AppStoreError(f"unsupported authentication redirect status (HTTP {status})")
            return True, resolve_authentication_redirect(endpoint, location)

        if attempt == 1 and failure_type == constants.FAILURE_INVALID_CREDENTIALS:
            return True, None

        if not failure_type and customer_message == constants.CUSTOMER_MESSAGE_BAD_LOGIN:
            if not auth_code:
                # Apple answers a wrong password exactly like "send the code":
                # the code request is all that can be said - the message says both.
                raise AuthCodeRequiredError(
                    "Enter the 6-digit code shown on your Apple device. No code appeared? Then the password "
                    "is most likely wrong - Apple answers a wrong password the same way as a request for the code.",
                    metadata=data,
                )
            raise AppStoreError(
                "Apple didn't accept the sign-in. The code may be wrong or expired - or the password is wrong "
                "(Apple reports both the same way). Check the password and request a new code.",
                metadata=data,
            )

        if not failure_type and customer_message == constants.CUSTOMER_MESSAGE_ACCOUNT_DISABLED:
            raise AppStoreError("account is disabled", metadata=data)

        if not failure_type and customer_message == constants.CUSTOMER_MESSAGE_ACTION_SIGN_IN_PAGE:
            raise AppStoreError(
                "account requires browser sign-in (2FA or Apple ID review required)",
                metadata=data,
            )

        if failure_type:
            raise AppStoreError(customer_message or "something went wrong", metadata=data)

        if status != 200 or not data.get("passwordToken") or not data.get("dsPersonId"):
            raise AppStoreError(
                f"Apple returned no usable authentication response (HTTP {status}): missing account "
                "credentials or unexpected status; try again later or from another network",
                metadata=data,
            )

        return False, None

    def _country_code_from_storefront(self, store_front: str) -> str:
        prefix = store_front.split("-")[0]
        for code, value in constants.STORE_FRONTS.items():
            if value == prefix:
                return code
        raise AppStoreError(f"unknown storefront: {store_front}")

    def _build_query_url(self, path: str, params: Dict[str, str]) -> str:
        from urllib.parse import urlencode

        query = urlencode(params)
        return f"https://{constants.ITUNES_API_DOMAIN}{path}?{query}"

    def _release_date_from_metadata(
        self,
        metadata: Dict[str, Any],
        headers: Dict[str, str],
    ) -> Optional[datetime]:
        generated_dates = self._response_generated_dates(headers)
        for key in (
            "softwareVersionReleaseDate",
            "versionReleaseDate",
            "currentVersionReleaseDate",
        ):
            raw_value = metadata.get(key)
            parsed = self._parse_apple_date(raw_value)
            if not parsed:
                continue
            if any(parsed == generated or parsed.date() == generated.date() for generated in generated_dates):
                continue
            return parsed
        return None

    def _release_date_display(
        self,
        account: Account,
        app: App,
        metadata: Dict[str, Any],
        release: Optional[datetime],
    ) -> str:
        display_version = str(metadata.get("bundleShortVersionString", "")).strip()
        history_date = self._app_store_history_dates(account, app).get(display_version)
        if history_date:
            return history_date
        if release:
            return release.date().isoformat()

        original_release = self._parse_apple_date(metadata.get("releaseDate"))
        if original_release:
            return f"Unknown ({original_release.date().isoformat()})"
        return "Unknown"

    def _app_store_history_dates(self, account: Account, app: App) -> Dict[str, str]:
        page = self._app_store_page(account, app)
        return {k: v for k, v in page.items() if k != _WEB_VERSION_KEY}

    def _web_external_version_id(self, account: Account, app: App) -> str:
        """The app's current externalVersionId as shown on its public
        apps.apple.com page. Used for apps missing from Apple's catalogs
        (Apple Arcade games are never listed there)."""
        return self._app_store_page(account, app).get(_WEB_VERSION_KEY, "")

    def _app_store_page(self, account: Account, app: App) -> Dict[str, str]:
        """Parsed public App Store page (release dates per version, plus the
        current externalVersionId under _WEB_VERSION_KEY); fetched once per
        app/storefront and cached, shared by both uses."""
        country = self._country_code_from_storefront(account.store_front).lower()
        url = f"https://apps.apple.com/{country}/app/id{app.id}"

        def fetch() -> Optional[Dict[str, str]]:
            if self.apps_site_rate_limited():
                return None
            try:
                response = requests.get(
                    url,
                    headers={"User-Agent": constants.DEFAULT_USER_AGENT},
                    timeout=10,
                    verify=self._verify,
                )
                response.raise_for_status()
            except requests.RequestException as exc:
                status = getattr(getattr(exc, "response", None), "status_code", None)
                if status == 429:
                    _APPS_SITE_BACKOFF.set("429", True)
                    logger.info(
                        "apps.apple.com rate-limited the release-date lookup for app %s; "
                        "using dates from App Store metadata instead (retry in 5 min)", app.id,
                    )
                else:
                    logger.warning("failed to fetch App Store version history from %s: %s", url, exc)
                return None
            parsed = self._parse_app_store_history_dates(response.text)
            version_id = _parse_web_external_version_id(response.text, app.id)
            if version_id:
                parsed[_WEB_VERSION_KEY] = version_id
            return parsed

        return _history_cache.get_or_fetch((app.id, country), fetch)

    def _parse_app_store_history_dates(self, page_html: str) -> Dict[str, str]:
        history: Dict[str, str] = {}
        pattern = re.compile(
            r'<div[^>]*class="[^"]*\bmetadata\b[^"]*"[^>]*>\s*'
            r'<span[^>]*>\s*([^<]+?)\s*</span>\s*'
            r'<time[^>]*datetime="(\d{4}-\d{2}-\d{2})"[^>]*>',
            re.IGNORECASE | re.DOTALL,
        )
        for version, release_date in pattern.findall(page_html):
            version = html.unescape(version).strip()
            if version and version not in history:
                history[version] = release_date
        return history

    def _response_generated_dates(self, headers: Dict[str, str]) -> List[datetime]:
        dates: List[datetime] = []
        for key in ("x-apple-date-generated", "Date", "Expires"):
            parsed = self._parse_apple_date(headers.get(key))
            if parsed:
                dates.append(parsed)
        return dates

    def _parse_apple_date(self, value: Any) -> Optional[datetime]:
        if not value:
            return None
        if isinstance(value, datetime):
            return value
        text = str(value).strip()
        if not text:
            return None
        try:
            return datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            pass
        try:
            return parsedate_to_datetime(text)
        except (TypeError, ValueError):
            return None

    def _send_request(self, request: HTTPRequest, allow_decode_error: bool = False) -> HTTPResult:
        try:
            logger.debug("%s %s", request.method, request.url.split("?")[0])
            response = self._http.send(request)
            if logger.isEnabledFor(logging.DEBUG):
                # Redacted: Apple's responses carry tokens, DSID and cookies.
                data_repr = repr(redact(response.data))
                if len(data_repr) > 4000:
                    data_repr = data_repr[:4000] + "... (truncated)"
                logger.debug("-> %s %s", response.status_code, data_repr)
            return response
        except HTTPClientResponseError as exc:
            logger.warning("HTTP error %s from %s", exc.status_code, request.url.split("?")[0])
            body_preview = exc.body[:2048]
            if isinstance(body_preview, bytes):
                body_text = body_preview.decode("utf-8", errors="replace")
            else:
                body_text = str(body_preview)
            metadata = {
                "status": exc.status_code,
                "headers": exc.headers,
                "body": body_text,
            }
            raise AppStoreError(
                _unexpected_message(_step_name(request.url), exc.status_code, exc.headers.get("Content-Type", "")),
                metadata=metadata,
            ) from exc
        except ResponseDecodeError as exc:
            if allow_decode_error:
                raise
            metadata = {
                "status": exc.status_code,
                "headers": exc.headers,
                "contentType": exc.content_type,
                "body": exc.body,
                "urls": exc.urls,
            }
            raise AppStoreError(
                _unexpected_message(_step_name(request.url), exc.status_code, exc.content_type),
                metadata=metadata,
            ) from exc
        except requests.RequestException as exc:
            raise AppStoreError(
                f"network request failed ({_step_name(request.url)}): {exc.__class__.__name__}",
                metadata={"error": str(exc)},
            ) from exc

    def _guid(self) -> str:
        return self._state.device_guid()

    # --- download-product endpoints (ipatool v2.6.0): volumeStore, then
    # redownloadProduct, then updateProduct when the previous one is empty.

    def _send_download_request(
        self,
        account: Account,
        app: App,
        guid: str,
        external_version_id: Optional[str],
        platform: str = "",
    ) -> HTTPResult:
        self._ent_skip = ""
        preferred = self._try_ent_download(account, app, guid, external_version_id, platform)
        if preferred is not None:
            return preferred
        hint_key = (account.directory_services_id, app.id, platform)
        hint = _DOWNLOAD_STAGE_HINTS.get(hint_key)
        if hint in (_STAGE_REDOWNLOAD, _STAGE_UPDATE):
            try:
                result = self._download_product_chain(account, app, guid, external_version_id, platform, start=hint)
                if result is not None:
                    return result
            except VersionNotServedError:
                raise  # a definitive answer; the full chain would end the same way
            except AppStoreError as exc:
                logger.debug("shortcut via %s failed for app %s (%s), using full chain", hint, app.id, exc)
            _DOWNLOAD_STAGE_HINTS.discard(hint_key)
        return self._download_product_chain(
            account, app, guid, external_version_id, platform, start=_STAGE_VOLUME_STORE, hint_key=hint_key
        )

    def _download_product_chain(
        self,
        account: Account,
        app: App,
        guid: str,
        external_version_id: Optional[str],
        platform: str,
        start: str,
        hint_key: Optional[Tuple[Any, ...]] = None,
    ) -> Optional[HTTPResult]:
        """volumeStore, redownload, updateProduct (ipatool sendDownloadProduct).
        Started past volumeStore, returns None instead of a non-final result."""
        external_version_id = external_version_id or ""
        shortcut = start != _STAGE_VOLUME_STORE
        result: Optional[HTTPResult] = None

        if start == _STAGE_VOLUME_STORE:
            pod_prefix = f"p{account.pod}-" if account.pod else ""
            volume_store = (
                f"https://{pod_prefix}{constants.PRIVATE_APPSTORE_HOST}{constants.PRIVATE_DOWNLOAD_PATH}",
                "externalVersionId",
            )
            result = self._post_download_product(volume_store, account, app, guid, external_version_id)
            if not _is_empty_download_response(result) and not _is_unavailable_download_response(result):
                if hint_key is not None:
                    _DOWNLOAD_STAGE_HINTS.discard(hint_key)
                return result

        url_bag = self._fetch_url_bag(guid)
        redownload_url = str(url_bag.get("redownloadProduct") or "")
        update_url = str(url_bag.get("updateProduct") or "")
        if not redownload_url:
            return None if shortcut else result

        if not external_version_id and platform in ("", platform_module.PLATFORM_IPHONE, platform_module.PLATFORM_IPAD):
            # Unpinned redownloads can fail or return a tvOS package; pin the
            # current iOS build first.
            platform = platform or platform_module.PLATFORM_IPHONE
            try:
                external_version_id = self.lookup_latest_external_version_id(account, app, platform)
            except PlatformLookupEmptyError:
                # Not in any catalog (Arcade): unpinned redownload as ipatool 387d1a4;
                # the package platform is validated afterwards.
                logger.info(
                    "app %s isn't in Apple's catalogs (e.g. Apple Arcade); trying redownload without a pinned version",
                    app.id,
                )
                external_version_id = ""
            except AppStoreError as exc:
                raise AppStoreError(f"failed to resolve latest iOS version for redownload: {exc}", metadata=exc.metadata) from exc

        can_update = bool(update_url and external_version_id) and platform in (
            "", platform_module.PLATFORM_IPHONE, platform_module.PLATFORM_IPAD, platform_module.PLATFORM_APPLETV
        )

        redownload_result: Optional[HTTPResult] = None
        redownload_error: Optional[AppStoreError] = None
        if start != _STAGE_UPDATE:
            if not shortcut:
                logger.info("volumeStore returned no items for app %s, trying redownload", app.id)
            redownload = (_validate_download_endpoint(redownload_url, "/r/redownload"), "appExtVrsId")
            try:
                redownload_result = self._post_download_product(redownload, account, app, guid, external_version_id)
            except AppStoreError as exc:
                redownload_error = exc

            subscription_required = redownload_error is None and _is_subscription_required_response(redownload_result)
            needs_update = (redownload_error is not None and _is_empty_redownload_error(redownload_error)) or (
                redownload_error is None and _is_unavailable_download_response(redownload_result)
            ) or subscription_required
            if not (can_update and needs_update):
                if redownload_error is not None:
                    raise AppStoreError(
                        f"redownload request failed: {redownload_error}", metadata=redownload_error.metadata
                    ) from redownload_error
                if hint_key is not None and redownload_result is not None and redownload_result.data.get("songList"):
                    _DOWNLOAD_STAGE_HINTS.set(hint_key, _STAGE_REDOWNLOAD)
                if shortcut and (redownload_result is None or not redownload_result.data.get("songList")):
                    return None
                return redownload_result
            if not shortcut:
                logger.info("redownload returned nothing for app %s, trying updateProduct", app.id)
        elif not can_update:
            return None

        try:
            update_result = self._send_update_product(update_url, account, app, guid, external_version_id)
        except AppStoreError as exc:
            if start != _STAGE_UPDATE and redownload_result is not None and _is_subscription_required_response(redownload_result):
                # Apple Arcade: updateProduct didn't serve this version either -
                # report redownload's "Subscription Required".
                logger.info("updateProduct didn't serve version %s of Arcade game %s either: %s",
                            external_version_id, app.id, exc)
                return redownload_result
            raise
        if hint_key is not None and update_result.data.get("songList"):
            _DOWNLOAD_STAGE_HINTS.set(hint_key, _STAGE_UPDATE)
        return update_result

    def _send_update_product(self, endpoint: str, account: Account, app: App, guid: str, external_version_id: str) -> HTTPResult:
        update = (_validate_download_endpoint(endpoint, "/up/updateProduct"), "appExtVrsId")
        result = self._post_download_product(update, account, app, guid, external_version_id)
        return self._validate_versioned_response(result, app, external_version_id, "update")

    def _validate_versioned_response(
        self, result: HTTPResult, app: App, external_version_id: str, source: str
    ) -> HTTPResult:
        """ipatool validateDownloadResponse (3411d57, 7578671), for updateProduct
        and ent/download: exactly one item, for this app, version (when one was
        asked for) and bundle."""
        data = result.data if isinstance(result.data, dict) else {}
        if data.get("failureType"):
            return result
        if data.get("customerMessage"):
            raise AppStoreError(f"received {source} error: {data.get('customerMessage')}", metadata=data)
        if result.status_code != 200:
            raise AppStoreError(f"received unexpected {source} status code: {result.status_code}")
        items = data.get("songList") or []
        if len(items) != 1:
            raise AppStoreError(f"{source} response must contain exactly one item", metadata=data)
        metadata = items[0].get("metadata", {}) or {}
        got_item = str(metadata.get("itemId"))
        got_version = str(metadata.get("softwareVersionExternalIdentifier"))
        details = {
            "requestedAppId": str(app.id),
            "returnedAppId": got_item,
            "requestedVersionId": str(external_version_id),
            "returnedVersionId": got_version,
            "returnedVersion": str(metadata.get("bundleShortVersionString", "")),
        }
        if got_item != str(app.id):
            raise AppStoreError(f"{source} response is for a different app", metadata=details)
        # ipatool 7578671: an empty version lets Apple pick one (unpinned
        # redownload); the app and bundle checks still apply.
        if external_version_id and got_version != str(external_version_id):
            raise VersionNotServedError(
                "Apple doesn't serve this version to this account any more "
                f"(asked for {external_version_id}, Apple offered only {got_version}"
                + (f" = v{details['returnedVersion']}" if details["returnedVersion"] else "")
                + ")",
                metadata=details,
            )
        bundle_id = metadata.get("softwareVersionBundleId")
        if not isinstance(bundle_id, str) or not bundle_id or (app.bundle_id and bundle_id != app.bundle_id):
            raise AppStoreError(f"{source} response does not match the requested bundle identifier")
        return result

    # -- ent/download with kbsync (ipatool 3411d57) ------------------------

    def _try_ent_download(
        self, account: Account, app: App, guid: str, external_version_id: Optional[str], platform: str
    ) -> Optional[HTTPResult]:
        """ipatool sendDownloadProduct (3411d57): prefer ent/download when the
        bag offers it and the emulator is available; on any failure return
        None so the legacy volumeStore -> redownload -> update chain runs."""
        from .sap import unicorn_available

        if not unicorn_available():
            self._ent_skip = "ent/download unavailable (the sign-in emulator isn't installed)"
            return None
        # Includes the sign-in token: signing in again lifts the block.
        refusal_key = (account.directory_services_id, guid,
                       hashlib.sha256(str(account.password_token or "").encode()).hexdigest()[:16])
        if _ENT_DOWNLOAD_REFUSED.get(refusal_key):
            # Apple refused this account/device twice in a row just now: don't
            # spend ~20 s of emulation on a kbsync blob it will refuse again.
            self._ent_skip = f"ent/download paused for {_ENT_DOWNLOAD_REFUSAL_MINUTES} min after two refusals"
            return None
        try:
            endpoint = _ent_download_endpoint(str(self._fetch_url_bag(guid).get("volumeStoreDownloadProduct", "")))
        except AppStoreError as exc:
            self._ent_skip = f"ent/download endpoint unavailable ({exc})"
            return None
        if endpoint is None:
            self._ent_skip = "ent/download not offered by Apple's bag"
            return None
        version_id = external_version_id or ""
        try:
            if not version_id:
                version_id = self.lookup_latest_external_version_id(
                    account, app, platform or platform_module.PLATFORM_IPHONE
                )
            try:
                result = self._send_ent_download(endpoint, account, app, guid, version_id)
            except PasswordTokenExpiredError:
                raise
            except Exception as first:  # noqa: BLE001
                metadata = getattr(first, "metadata", None)
                if not (isinstance(metadata, dict) and metadata.get("status") in (401, 403)):
                    raise
                # A single 401/403 happens now and then for an account that is
                # served fine a moment later - one more try with a fresh kbsync.
                logger.info("ent/download refused app %s once (HTTP %s); trying again", app.id, metadata.get("status"))
                result = self._send_ent_download(endpoint, account, app, guid, version_id)
        except PasswordTokenExpiredError:
            raise
        except Exception as exc:  # noqa: BLE001 - asset, emulator, network or Apple failures all fall back
            metadata = getattr(exc, "metadata", None)
            reason = _apple_reason(metadata)
            refused = isinstance(metadata, dict) and metadata.get("status") in (401, 403)
            if refused:
                _ENT_DOWNLOAD_REFUSED.set(refusal_key, True)
            # Apple's own answer is definitive; anything else means the version
            # wasn't checked on this route.
            answered = isinstance(exc, VersionNotServedError) or (
                not refused and isinstance(metadata, dict)
                and bool(metadata.get("failureType") or metadata.get("customerMessage"))
            )
            if not answered:
                self._ent_skip = f"ent/download failed ({str(exc)[:120]})"
            logger.info(
                "ent/download unavailable for app %s (%s%s); using the legacy download endpoints%s",
                app.id, exc, f" - Apple says: {reason}" if reason else "",
                f" (refused twice; not tried for this sign-in for {_ENT_DOWNLOAD_REFUSAL_MINUTES} min)" if refused else "",
            )
            return None
        logger.info("ent/download served app %s version %s", app.id, version_id)
        return result

    def _send_ent_download(self, endpoint: str, account: Account, app: App, guid: str, version_id: str) -> HTTPResult:
        try:
            hardware_id = bytes.fromhex(guid)
        except ValueError:
            hardware_id = b""
        if len(hardware_id) != 6:
            raise AppStoreError("ent/download requires a six-byte device GUID")
        try:
            dsid = int(account.directory_services_id)
        except (TypeError, ValueError):
            dsid = 0
        if dsid <= 0:
            raise AppStoreError("ent/download requires a nonzero numeric account DSID")

        cached = _kbsync_cached(dsid, guid)
        if cached:
            try:
                return self._ent_download_request(endpoint, account, app, guid, version_id, hardware_id, cached)
            except AppStoreError as exc:
                if _kbsync_accepted(exc):
                    raise  # Apple's own answer about this app/version: the blob is fine, keep it
                if _apple_server_error(exc) and _kbsync_recently_ok(dsid, guid, cached):
                    raise  # Apple failing on this version; the blob served others just now
                # A rejected cached blob is retried once with a fresh one.
                _kbsync_invalidate(dsid, guid, cached)
        with _kbsync_key_lock(dsid, guid):
            fresh = _kbsync_cached(dsid, guid)
            if fresh and fresh != cached:
                # Made by a parallel request while this one waited.
                blob = fresh
            else:
                blob = self._generate_kbsync(hardware_id, dsid)
        try:
            result = self._ent_download_request(endpoint, account, app, guid, version_id, hardware_id, blob)
        except AppStoreError as exc:
            if _kbsync_accepted(exc):
                # Apple answered about the app, so the blob works: keep it.
                _kbsync_store(dsid, guid, blob)
            raise
        _kbsync_store(dsid, guid, blob)  # only blobs Apple accepted
        return result

    def _generate_kbsync(self, hardware_id: bytes, dsid: int) -> str:
        from .sap import assets as sap_assets
        from .sap.machine import generate_kbsync

        started = time.monotonic()
        with _SIGNER_SLOTS:  # the emulator is heavy: share the signer's concurrency limit
            bundle = sap_assets.load(cache_dir=self._storage_dir / "sap" / sap_assets.CACHE_VERSION, verify=self._verify)
            data = generate_kbsync(bundle, hardware_id, dsid)
        logger.info("generated download kbsync in %.1fs", time.monotonic() - started)
        return base64.b64encode(data).decode("ascii")

    def _ent_download_request(
        self, endpoint: str, account: Account, app: App, guid: str, version_id: str, hardware_id: bytes, blob: str
    ) -> HTTPResult:
        serial = bytes((0x54, 0xC8, 0xB0, 0xA9, 0x88)) + hardware_id[2:]
        request = HTTPRequest(
            method="POST",
            # Twice, as Apple's framework sends it (ipatool 5dc4c80): ipatool
            # adds the guid and the framework appends it again for this URL.
            url=f"{endpoint}?guid={guid}&guid={guid}",
            headers={
                "Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
                "User-Agent": _ENT_DOWNLOAD_USER_AGENT,
                "iCloud-DSID": account.directory_services_id,
                "X-Dsid": account.directory_services_id,
                "X-Apple-Store-Front": account.store_front,
                "X-Token": account.password_token,
            },
            payload=XMLPayload(
                {
                    "creditDisplay": "",
                    "guid": guid,
                    "kbsync": blob,
                    "salableAdamId": str(app.id),
                    "serialNumber": base64.b64encode(serial).decode("ascii"),
                    "externalVersionId": version_id,
                }
            ),
            response_format=constants.ResponseFormatXML,
            follow_redirects=False,  # X-Token must not reach a redirect destination
            timeout=(constants.AUTH_CONNECT_TIMEOUT, constants.AUTH_READ_TIMEOUT),
        )
        result = self._send_request(request)
        data = result.data if isinstance(result.data, dict) else {}
        failure_type = str(data.get("failureType") or "")
        if failure_type == constants.FAILURE_PASSWORD_TOKEN_EXPIRED or (
            data.get("customerMessage") == constants.CUSTOMER_MESSAGE_PASSWORD_CHANGED
        ):
            raise PasswordTokenExpiredError("password token expired", metadata=redact(data))
        if failure_type:
            raise AppStoreError(f"received ent/download error: {failure_type}", metadata=redact(data))
        self._validate_versioned_response(result, app, version_id, "ent/download")
        if not (data.get("songList") or [{}])[0].get("URL"):
            raise AppStoreError("ent/download response has no package URL")
        return result

    def _post_download_product(
        self, endpoint: Tuple[str, str], account: Account, app: App, guid: str, external_version_id: str
    ) -> HTTPResult:
        base_url, version_key = endpoint
        payload: Dict[str, Any] = {
            "creditDisplay": "",
            "guid": guid,
            "salableAdamId": app.id,
            "serialNumber": "0",
        }
        if external_version_id:
            payload[version_key] = external_version_id
        request = HTTPRequest(
            method="POST",
            url=f"{base_url}?guid={guid}",
            headers={
                "Content-Type": "application/x-apple-plist",
                "iCloud-DSID": account.directory_services_id,
                "X-Dsid": account.directory_services_id,
            },
            payload=XMLPayload(payload),
            response_format=constants.ResponseFormatXML,
        )
        return self._send_request(request)

    def _fetch_url_bag(self, guid: str) -> Dict[str, Any]:
        cached = _URL_BAG_CACHE.get("urlBag")
        if cached is not None:
            return cached
        request = HTTPRequest(
            method="GET",
            url=f"https://{constants.PRIVATE_INIT_DOMAIN}{constants.PRIVATE_INIT_PATH}?guid={guid}",
            headers={"Accept": "application/xml"},
            payload=None,
            response_format=constants.ResponseFormatXML,
            # ipatool e8a7ba8: the bag request is bounded like login requests.
            timeout=(constants.AUTH_CONNECT_TIMEOUT, constants.AUTH_READ_TIMEOUT),
        )
        result = self._send_request(request)
        if result.status_code != 200:
            raise AppStoreError(f"failed to get bag: HTTP {result.status_code}")
        url_bag = (result.data or {}).get("urlBag", {}) if isinstance(result.data, dict) else {}
        url_bag = url_bag if isinstance(url_bag, dict) else {}
        if url_bag:
            _URL_BAG_CACHE.set("urlBag", url_bag)
        return url_bag

    def _validate_download_result(self, result: HTTPResult) -> None:
        failure_type = result.data.get("failureType", "")
        customer_message = result.data.get("customerMessage", "")
        market_allowed = result.data.get("m-allowed", True)

        if failure_type == constants.FAILURE_PASSWORD_TOKEN_EXPIRED or customer_message == constants.CUSTOMER_MESSAGE_PASSWORD_CHANGED:
            raise PasswordTokenExpiredError("password token expired", metadata=result.data)
        if failure_type == constants.FAILURE_LICENSE_NOT_FOUND:
            raise LicenseRequiredError("license required", metadata=result.data)
        if customer_message == constants.CUSTOMER_MESSAGE_SUBSCRIPTION_REQUIRED or _is_arcade_not_subscribed(result.data):
            # Arcade game without a license: "Subscription Required" instead of
            # "License not found"; getting the game once creates the license.
            raise ArcadeRefusedError(ARCADE_NOT_SUBSCRIBED_MESSAGE, metadata=result.data)
        # 5002 with m-allowed=False is Apple refusing this app for the account
        # (not retryable, not a license issue): say so plainly.
        if failure_type == constants.FAILURE_UNKNOWN_ERROR and market_allowed is False:
            raise AppStoreError(
                (customer_message or "An unknown error has occurred")
                + " - Apple is refusing this app/version for this account (not a licensing issue - "
                "this can happen even for versions listed in a community database, since Apple "
                "re-checks eligibility on every download, not just when listing versions)",
                metadata=result.data,
            )
        if failure_type and customer_message:
            raise AppStoreError(customer_message, metadata=result.data)
        if failure_type:
            raise AppStoreError(f"download failed ({failure_type})", metadata=result.data)

    def _extract_first_item(self, result: HTTPResult) -> Dict[str, Any]:
        items = result.data.get("songList", [])
        if not items:
            # Prefer whatever Apple explained over a bare "invalid payload".
            message = str(result.data.get("customerMessage") or "")
            dialog = result.data.get("dialog") if isinstance(result.data.get("dialog"), dict) else {}
            explanation = str(dialog.get("explanation") or "").replace("\xa0", " ")
            if message or explanation:
                raise AppStoreError(" - ".join(x for x in (message, explanation) if x), metadata=result.data)
            raise AppStoreError("Apple returned no download for this app (empty response)", metadata=result.data)
        return items[0]

    def _resolve_destination_path(self, app: App, version: str, output_dir: str) -> str:
        """``output_dir`` is always a directory chosen by the server - never a
        client-supplied path (the old /api/download accepted an arbitrary
        ``outputPath`` from the request body)."""
        file_name_parts = []
        if app.bundle_id:
            file_name_parts.append(app.bundle_id)
        if app.id:
            file_name_parts.append(str(app.id))
        if version:
            file_name_parts.append(version)
        raw_name = "_".join(file_name_parts) or "app"
        file_name = _UNSAFE_FILENAME_CHARS_RE.sub("-", raw_name).strip(".-") or "app"
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        return str(out / f"{file_name}.ipa")

    # Retries a stalled or reset CDN download, resuming with Range (as ipatool-py).
    _DOWNLOAD_MAX_RETRIES = 8

    def _download_file(
        self,
        url: str,
        destination: str,
        on_progress: Optional["Callable[[int, Optional[int]], None]"] = None,
    ) -> None:
        dest_path = Path(destination)
        dest_path.parent.mkdir(parents=True, exist_ok=True)

        last_error: Optional[Exception] = None
        for attempt in range(1, self._DOWNLOAD_MAX_RETRIES + 1):
            try:
                self._download_file_once(url, dest_path, on_progress=on_progress)
                return
            except (requests.exceptions.RequestException, OSError) as exc:
                last_error = exc
                if attempt < self._DOWNLOAD_MAX_RETRIES:
                    # The partial file stays: the next attempt resumes it.
                    time.sleep(min(2 ** (attempt - 1), 15))
                    continue

        dest_path.unlink(missing_ok=True)
        raise AppStoreError(
            f"download failed after {self._DOWNLOAD_MAX_RETRIES} attempts: {last_error}"
        ) from last_error

    def _download_file_once(
        self,
        url: str,
        dest_path: Path,
        on_progress: Optional["Callable[[int, Optional[int]], None]"] = None,
    ) -> None:
        existing = dest_path.stat().st_size if dest_path.exists() else 0
        headers = {}
        if existing:
            headers["Range"] = f"bytes={existing}-"

        response = self._http.raw_request("GET", url, headers=headers, stream=True)
        try:
            if response.status_code == 416 and existing:
                # The partial file is already full size (left over): start over.
                dest_path.unlink(missing_ok=True)
                raise requests.exceptions.ConnectionError("range not satisfiable, restarting download")
            response.raise_for_status()

            # Resume only on 206: some CDN URLs ignore Range and send the whole file.
            resumed = existing > 0 and response.status_code == 206
            mode = "ab" if resumed else "wb"
            base_offset = existing if resumed else 0

            expected_total: Optional[int] = None
            content_length = response.headers.get("Content-Length")
            if content_length is not None:
                try:
                    expected_total = base_offset + int(content_length)
                except ValueError:
                    expected_total = None

            written = base_offset
            if expected_total is not None:
                _check_disk_space(dest_path, expected_total - written, expected_total)
            if on_progress:
                on_progress(written, expected_total)
            with dest_path.open(mode) as handle:
                for chunk in response.iter_content(chunk_size=1024 * 1024):
                    if not chunk:
                        continue
                    handle.write(chunk)
                    written += len(chunk)
                    if on_progress:
                        on_progress(written, expected_total)

            if expected_total is not None and written != expected_total:
                # Treat a short/incomplete transfer as retryable rather than
                # silently handing a truncated IPA to the zip-patching step.
                raise requests.exceptions.ChunkedEncodingError(
                    f"incomplete download: got {written} bytes, expected {expected_total}"
                )
        finally:
            response.close()

    def _metadata_bytes(self, metadata: Dict[str, Any], account: Account) -> bytes:
        metadata = dict(metadata)
        metadata["apple-id"] = account.email
        metadata["userName"] = account.email
        return plistlib.dumps(metadata, fmt=plistlib.FMT_BINARY)

    def _read_manifest_plist(self, zip_file: ZipFile) -> Optional[Dict[str, Any]]:
        for name in zip_file.namelist():
            if _MAIN_MANIFEST_RE.match(name):
                return plistlib.loads(zip_file.read(name))
        return None

    def _read_info_plist(self, zip_file: ZipFile) -> Optional[Dict[str, Any]]:
        for name in zip_file.namelist():
            if _MAIN_INFO_PLIST_RE.match(name):
                return plistlib.loads(zip_file.read(name))
        return None

    def _read_bundle_name(self, zip_file: ZipFile) -> str:
        for name in zip_file.namelist():
            if _MAIN_INFO_PLIST_RE.match(name):
                return name.split("/")[1]
        raise AppStoreError("could not determine bundle name")


def _host_of(exc: Exception) -> str:
    """The host a requests error was about (for messages; no paths / queries)."""
    from urllib.parse import urlsplit

    request = getattr(exc, "request", None)
    url = getattr(request, "url", "") or ""
    return urlsplit(url).hostname or "Apple"
