"""REST API routes for the Flask application."""
from __future__ import annotations

import logging
import re
import shutil
import threading
import time
from http import HTTPStatus
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Tuple
from urllib.parse import quote, urlparse

from flask import Blueprint, Response, current_app, g, jsonify, request

from ..services.appstore import AppStoreService
from ..services.errors import (
    APPS_SITE_RATE_LIMITED_MESSAGE,
    ARCADE_VERSIONS_UNAVAILABLE_MESSAGE,
    AppNotFoundError,
    ArcadeNotSupportedError,
    AppStoreError,
    PlatformLookupEmptyError,
    AuthCodeRequiredError,
    LicenseRequiredError,
    PasswordTokenExpiredError,
)
from ..services.constants import STORE_FRONTS
from ..services import jobs as jobs_module
from ..services.jobs import MAX_ACTIVE_PER_OWNER, MAX_ACTIVE_TOTAL, download_jobs
from ..services.models import Account, App, DownloadOutput
from ..services.redact import redact, redact_text

logger = logging.getLogger(__name__)

api_bp = Blueprint("api", __name__, url_prefix="/api")

SEARCH_LIMIT_MAX = 50


def _service() -> AppStoreService:
    return g.appstore


def _owner() -> str:
    return g.session_state.owner_id


def _server_save_allowed() -> bool:
    return bool(current_app.config.get("ALLOW_SERVER_SAVE", False))


def _server_download_dir() -> Path:
    return Path(current_app.config["MACHINE"].home_directory()) / "Downloads" / "IPATool"


def _temp_download_dir() -> Path:
    return Path(current_app.config["STORAGE_DIR"]) / "temp_downloads"


def _json_body() -> Dict[str, Any]:
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}


# ---------------------------------------------------------------------------
# Request guard (CSRF)
# ---------------------------------------------------------------------------


@api_bp.before_request
def _csrf_guard():
    """Reject cross-site state-changing requests: JSON only (forces a CORS
    preflight that is never answered) and a matching Origin."""
    if request.method not in ("POST", "PUT", "PATCH", "DELETE"):
        return None
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), HTTPStatus.UNSUPPORTED_MEDIA_TYPE
    origin = request.headers.get("Origin")
    if origin and origin != "null":
        if urlparse(origin).netloc.lower() != request.host.lower():
            return jsonify({"error": "cross-origin request rejected"}), HTTPStatus.FORBIDDEN
    elif origin == "null":
        return jsonify({"error": "cross-origin request rejected"}), HTTPStatus.FORBIDDEN
    return None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _content_disposition(filename: str) -> str:
    ascii_name = filename.encode("ascii", "ignore").decode("ascii").replace('"', "").replace("\\", "") or "app.ipa"
    return f"attachment; filename=\"{ascii_name}\"; filename*=UTF-8''{quote(filename)}"


def _stream_file(file_path: Path, filename: str) -> Response:
    """Stream a file. Not deleted afterwards (some download managers fetch
    twice); the job sweep cleans up. Own open() so the handle closes promptly."""

    def generate():
        with file_path.open("rb") as handle:
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                yield chunk

    headers = {"Content-Disposition": _content_disposition(filename)}
    if file_path.exists():
        headers["Content-Length"] = str(file_path.stat().st_size)
    return Response(generate(), mimetype="application/octet-stream", headers=headers)


def _silent_relogin(service: AppStoreService, account: Account) -> Account:
    """Apple said the password token expired: sign in again with the stored
    password, as ipatool does. Keeps the browser session id so running
    download jobs stay reachable."""
    if not account.password:
        raise AppStoreError("your Apple session expired - sign out and sign in again")
    logger.info("Apple session token expired; signing in again automatically")
    try:
        return service.login(email=account.email, password=account.password, rotate_session=False)
    except AuthCodeRequiredError as exc:
        raise AppStoreError(
            "your Apple session expired and Apple asks for a 2FA code - sign out and sign in again"
        ) from exc


def _with_token_refresh(action):
    """Run ``action(account)``; on an expired password token, re-login once
    silently and retry."""
    service = _service()
    account = service.account_info()
    try:
        return action(account)
    except PasswordTokenExpiredError:
        return action(_silent_relogin(service, account))


def _download_with_retries(
    service: AppStoreService,
    account: Account,
    app: App,
    output_dir: Path,
    external_version_id: Optional[str],
    auto_purchase: bool,
    on_progress: Optional[Callable] = None,
    on_patch_progress: Optional[Callable] = None,
    platform: str = "",
) -> Tuple[DownloadOutput, Account]:
    """Single implementation of the "re-login on expired token / buy free
    license if needed" retry loop (previously copy-pasted three times)."""
    for _ in range(3):
        try:
            result = service.download(
                account=account,
                app=app,
                output_dir=str(output_dir),
                external_version_id=external_version_id,
                on_progress=on_progress,
                on_patch_progress=on_patch_progress,
                platform=platform,
            )
            return result, account
        except PasswordTokenExpiredError:
            account = _silent_relogin(service, account)
        except LicenseRequiredError:
            if not auto_purchase:
                raise
            try:
                service.purchase(account, app)
            except PasswordTokenExpiredError:
                # Getting the app often wants a fresher session than the
                # download did: sign in again, get it, then download.
                account = _silent_relogin(service, account)
                service.purchase(account, app)
    raise AppStoreError("failed to download app")


_VERSION_ID_RE = re.compile(r"^\d{1,20}$")


def _version_id(value: Any, name: str) -> str:
    """App Store version ids are plain numbers. They can come from the
    third-party community DB, so don't pass anything else on to Apple."""
    text = str(value).strip()
    if not _VERSION_ID_RE.match(text):
        raise AppStoreError(f"{name} must be a number")
    return text


def _enough_free_space(directory: Path) -> bool:
    probe = directory
    while not probe.exists() and probe.parent != probe:
        probe = probe.parent
    try:
        return shutil.disk_usage(probe).free >= jobs_module.MIN_FREE_BYTES
    except OSError:
        return True  # can't tell - don't block downloads over it


def _parse_int(value: Any, name: str, default: int, minimum: int, maximum: int) -> int:
    if value in (None, ""):
        return default
    try:
        number = int(value)
    except (TypeError, ValueError) as exc:
        raise AppStoreError(f"{name} must be an integer") from exc
    return max(minimum, min(maximum, number))


def _resolve_supported_app(payload: Dict[str, Any], account: Account, *_unused, **_unused_kw) -> App:
    """_resolve_app for purchase/download requests (Arcade too, ipatool e3932ce)."""
    return _resolve_app(payload, account)


def _resolve_app(payload: Dict[str, Any], account: Account) -> App:
    bundle_id = payload.get("bundleId")
    app_id = payload.get("appId")

    if bundle_id:
        try:
            return _service().lookup(account, str(bundle_id))
        except AppNotFoundError:
            # ipatool 387d1a4: delisted apps can still be downloaded by their
            # numeric id, even though the catalog lookup no longer finds them.
            if not app_id:
                raise
            try:
                return App(id=int(app_id), bundle_id=str(bundle_id))
            except (TypeError, ValueError) as exc:
                raise AppStoreError("appId must be numeric") from exc
    if app_id:
        try:
            return App(id=int(app_id))
        except (TypeError, ValueError) as exc:
            raise AppStoreError("appId must be numeric") from exc
    raise AppStoreError("either appId or bundleId must be supplied")


def _download_platform_param(value: Any) -> str:
    """Platform for versions/purchases/downloads: Apple Watch apps download as
    the iPhone package that carries the watch app."""
    from ..services import platform as platform_module

    return platform_module.download_platform(_parse_platform_param(value))


def _parse_platform_param(value: Any) -> str:
    from ..services import platform as platform_module

    try:
        return platform_module.parse_platform(value)
    except ValueError as exc:
        raise AppStoreError(str(exc)) from exc


def _resolve_external_version_id(account: Account, app: App, platform: str, explicit_id: Any) -> Any:
    """For Apple TV without a pinned version, resolve the latest tvOS external
    version id via the MDM lookup (see AppStoreService.lookup_latest_external_version_id)."""
    from ..services import platform as platform_module

    if explicit_id:
        return _version_id(explicit_id, "externalVersionId")
    if platform in (platform_module.PLATFORM_APPLETV, platform_module.PLATFORM_VISIONOS):
        try:
            return _service().lookup_latest_external_version_id(account, app, platform)
        except PlatformLookupEmptyError:
            # ipatool 387d1a4: a delisted tvOS app has no catalog offer but may
            # still be redownloadable; the package platform is validated later.
            logger.info("no tvOS catalog offer for app %s; downloading without a pinned version", app.id)
            return None
    return None


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


@api_bp.errorhandler(AppStoreError)
def _handle_appstore_error(exc: AppStoreError):
    payload: Dict[str, Any] = {"error": str(exc)}
    safe_metadata = redact(exc.metadata) if exc.metadata is not None else None
    # One readable log line; Apple's full answer only at --log-level DEBUG.
    brief = []
    if isinstance(safe_metadata, dict):
        headers = safe_metadata.get("headers") if isinstance(safe_metadata.get("headers"), dict) else {}
        for label, value in (("HTTP", safe_metadata.get("status")),
                             ("failureType", safe_metadata.get("failureType")),
                             ("Apple request id", headers.get("x-apple-jingle-correlation-key"))):
            if value:
                brief.append(f"{label} {value}")
    logger.warning("%s %s failed: %s%s", request.method, request.path, exc,
                   f" ({', '.join(brief)})" if brief else "")
    if logger.isEnabledFor(logging.DEBUG):
        details = repr(safe_metadata)
        logger.debug("  details: %s", details[:3000] + ("... (truncated)" if len(details) > 3000 else ""))
    if safe_metadata is not None:
        # Apple's raw responses can include tokens, DSIDs and cookies.
        payload["metadata"] = safe_metadata
    if isinstance(exc, LicenseRequiredError):
        payload["licenseRequired"] = True
    if isinstance(exc, ArcadeNotSupportedError):
        payload["arcade"] = True
        payload.pop("metadata", None)  # the message says it all
        if exc.latest_version_id:
            payload["arcadeLatestVersionId"] = exc.latest_version_id
    return jsonify(payload), HTTPStatus.BAD_REQUEST


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------


@api_bp.get("/config")
def server_config():
    return jsonify(
        {
            "sessionMode": current_app.config.get("SESSION_MODE"),
            "allowServerSave": _server_save_allowed(),
            "signInAvailable": bool(current_app.config.get("SAP_AVAILABLE", True)),
        }
    )


@api_bp.post("/auth/login")
def login():
    data = _json_body()
    email = str(data.get("email") or "").strip()
    password = str(data.get("password") or "")
    auth_code = data.get("authCode")
    if not email or not password:
        return jsonify({"error": "email and password are required"}), HTTPStatus.BAD_REQUEST

    try:
        account = _service().login(email=email, password=password, auth_code=str(auth_code) if auth_code else None)
    except AuthCodeRequiredError as exc:
        return (
            jsonify({"error": str(exc) or "auth code required", "authCodeRequired": True}),
            HTTPStatus.UNAUTHORIZED,
        )

    return jsonify({"account": account.to_public_dict()})


@api_bp.post("/auth/logout")
def logout():
    """Sign out: clears the stored account, Apple's session cookies and the
    device GUID (in browser mode: deletes this browser's session cookie)."""
    _service().revoke()
    return jsonify({"status": "ok"})


def _session_state():
    return g.session_state


@api_bp.get("/accounts")
def accounts_list():
    """The active and the saved sign-ins of this browser (local mode: of this
    server), public fields only."""
    try:
        accounts = _session_state().list_accounts()
    except NotImplementedError:
        accounts = []
    return jsonify({"accounts": accounts, "max": getattr(_session_state(), "MAX_SAVED", 0) + 1})


@api_bp.post("/accounts/add")
def accounts_add():
    """Keep the active sign-in as a saved one; the page then shows the
    sign-in form for another Apple ID."""
    _session_state().park_active()
    return jsonify({"accounts": _session_state().list_accounts()})


@api_bp.post("/accounts/switch")
def accounts_switch():
    slot_id = str(_json_body().get("id") or "")
    if not slot_id.isalnum():
        return jsonify({"error": "id is required"}), HTTPStatus.BAD_REQUEST
    account = _session_state().switch_account(slot_id)
    return jsonify({"account": account.to_public_dict(), "accounts": _session_state().list_accounts()})


@api_bp.post("/accounts/forget")
def accounts_forget():
    slot_id = str(_json_body().get("id") or "")
    if not slot_id.isalnum():
        return jsonify({"error": "id is required"}), HTTPStatus.BAD_REQUEST
    _session_state().forget_account(slot_id)
    return jsonify({"accounts": _session_state().list_accounts()})


@api_bp.get("/account")
def account_info():
    # "Not signed in" is a normal answer (every page load asks), not an
    # error - 200 with account=null keeps the access log free of scary 404s.
    try:
        account = _service().account_info()
    except AppStoreError:
        return jsonify({"account": None})
    return jsonify({"account": account.to_public_dict()})


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------


@api_bp.get("/search")
def search():
    term = (request.args.get("term") or "").strip()
    if not term:
        return jsonify({"error": "term query parameter is required"}), HTTPStatus.BAD_REQUEST
    limit = _parse_int(request.args.get("limit"), "limit", 5, 1, SEARCH_LIMIT_MAX)
    include_tvos = request.args.get("includeTvos", "false").lower() == "true"
    platform = _parse_platform_param(request.args.get("platform"))
    country = (request.args.get("country") or "").strip().upper()
    if country and country not in STORE_FRONTS:
        return jsonify({"error": f"unknown App Store region {country!r}"}), HTTPStatus.BAD_REQUEST

    account = _service().account_info()
    result = _service().search(account, term, limit, include_tvos, platform=platform, country=country)
    return jsonify({"count": result.count, "country": country, "results": [app.to_dict() for app in result.results]})


@api_bp.post("/purchase")
def purchase():
    payload = _json_body()

    def action(account):
        _service().purchase(account, _resolve_supported_app(payload, account, version_key=None))

    _with_token_refresh(action)
    return jsonify({"status": "purchased"})


@api_bp.get("/versions")
def list_versions():
    params = request.args or {}
    platform = _download_platform_param(params.get("platform"))

    probed: Dict[str, str] = {}

    def action(account):
        app = _resolve_supported_app(params, account)
        external_version_id = _resolve_external_version_id(account, app, platform, params.get("externalVersionId"))
        service = _service()
        try:
            return service.list_versions(account, app, external_version_id, platform=platform)
        except (LicenseRequiredError, PasswordTokenExpiredError):
            raise
        except AppStoreError as exc:
            if not isinstance(exc, ArcadeNotSupportedError) and not service.is_arcade(account, app):
                raise
            refusal = exc
        # Apple Arcade: retry pinned to known older versions - Apple answers
        # some of those (community database ids, newest first).
        try:
            entries = service.list_versions_community(app).entries
        except AppStoreError:
            entries = []
        # Versions the catalog confirmed first, then the rest (newest first),
        # versions it recorded as lost last - Apple's answer can change.
        def rank(e):
            vid = int(e.external_version_id) if str(e.external_version_id).isdigit() else 0
            return ({"ok": 2, "lost": 0}.get(e.status, 1), vid)
        candidates = [e.external_version_id for e in sorted(entries, key=rank, reverse=True)]
        candidates = [c for c in candidates if str(c) != str(external_version_id or "")]
        found = service.probe_arcade_versions(account, app, candidates, platform=platform)
        if found is not None:
            probed["versionId"] = found[1]
            return found[0]
        latest = (refusal.latest_version_id if isinstance(refusal, ArcadeNotSupportedError) else "") \
            or service.arcade_latest_version_id(account, app)
        if not latest and not external_version_id and service.apps_site_rate_limited():
            raise ArcadeNotSupportedError(APPS_SITE_RATE_LIMITED_MESSAGE) from refusal
        if isinstance(refusal, ArcadeNotSupportedError):
            refusal.latest_version_id = latest
            raise refusal
        raise ArcadeNotSupportedError(
            ARCADE_VERSIONS_UNAVAILABLE_MESSAGE.format(reason=str(refusal)[:200]),
            latest_version_id=latest,
        ) from refusal

    output = _with_token_refresh(action)
    body: Dict[str, Any] = {
        "latestExternalVersionId": output.latest_external_version_id,
        "externalVersionIdentifiers": output.external_version_identifiers,
    }
    if probed:
        body["arcadeProbeVersionId"] = probed["versionId"]
    return jsonify(body)


@api_bp.get("/versions/community")
def list_versions_community():
    """Version list from a third-party, crowd-sourced database (Timbrd). The
    .ipa itself is still fetched through the normal, official flow."""
    params = request.args or {}
    account = _service().account_info()
    app = _resolve_app(params, account)
    output = _service().list_versions_community(app)
    return jsonify({"source": output.source, "entries": [entry.to_dict() for entry in output.entries]})


@api_bp.get("/versions/catalog")
def list_versions_private_catalog():
    """Versions from the private catalog only ("Private catalog first"):
    {configured, found, updatedAt, entries}. No request to Apple."""
    params = request.args or {}
    service = _service()
    if not service.private_catalog_configured():
        return jsonify({"configured": False, "found": False, "updatedAt": "", "bundleId": "", "entries": []})
    account = service.account_info()
    app = _resolve_app(params, account)
    entries, updated, bundle_id = service.private_catalog_versions(app)
    return jsonify({"configured": True, "found": bool(entries), "updatedAt": updated, "bundleId": bundle_id,
                    "entries": [entry.to_dict() for entry in entries]})


@api_bp.post("/cache/clear")
def clear_cache():
    """Forget cached version data (catalogs, community lists, release dates,
    minimum OS, Arcade checks). Shared by everyone using this server; only
    costs a few extra requests afterwards."""
    from ..services.appstore import clear_version_caches

    count = clear_version_caches()
    logger.info("version caches cleared (%d entries)", count)
    return jsonify({"cleared": count})


@api_bp.get("/version-metadata")
def version_metadata():
    params = request.args or {}
    version_id = params.get("versionId")
    if not version_id:
        return jsonify({"error": "versionId is required"}), HTTPStatus.BAD_REQUEST
    version_id = _version_id(version_id, "versionId")

    def action(account):
        return _service().get_version_metadata(account, _resolve_supported_app(params, account, "versionId"), version_id)

    metadata = _with_token_refresh(action)
    return jsonify(metadata.to_dict())


# ---------------------------------------------------------------------------
# Downloads
# ---------------------------------------------------------------------------


@api_bp.post("/download")
def download():
    """Synchronous download into ~/Downloads/IPATool on the server."""
    if not _server_save_allowed():
        return jsonify({"error": "saving on the server is disabled"}), HTTPStatus.FORBIDDEN
    payload = _json_body()
    platform = _download_platform_param(payload.get("platform"))
    package_platform = _parse_platform_param(payload.get("platform"))  # watch: iPhone or watch-only package
    service = _service()
    account = service.account_info()
    app = _resolve_supported_app(payload, account)
    external_version_id = _resolve_external_version_id(account, app, platform, payload.get("externalVersionId"))

    result, _ = _download_with_retries(
        service, account, app, _server_download_dir(), external_version_id, bool(payload.get("purchaseIfNeeded")),
        platform=platform,
    )
    service.validate_package_platform(result.destination_path, package_platform)
    return jsonify({"destinationPath": result.destination_path, "sinfCount": len(result.sinfs)})


@api_bp.post("/download-stream")
def download_stream():
    """Deprecated: blocking download streamed in one response. Kept for API
    clients; the web UI uses /api/download-jobs."""
    payload = _json_body()
    platform = _download_platform_param(payload.get("platform"))
    package_platform = _parse_platform_param(payload.get("platform"))  # watch: iPhone or watch-only package
    service = _service()
    account = service.account_info()
    app = _resolve_supported_app(payload, account)
    external_version_id = _resolve_external_version_id(account, app, platform, payload.get("externalVersionId"))

    job = download_jobs.create(owner=_owner())
    work_dir = _temp_download_dir() / job.id
    download_jobs.update(job.id, work_dir=str(work_dir))
    result, _ = _download_with_retries(
        service, account, app, work_dir, external_version_id, bool(payload.get("purchaseIfNeeded")),
        platform=platform,
    )
    service.validate_package_platform(result.destination_path, package_platform)
    file_path = Path(result.destination_path)
    # Registered as a finished job so the regular TTL sweep removes it.
    download_jobs.update(job.id, status="ready", filename=file_path.name, file_path=str(file_path))
    return _stream_file(file_path, file_path.name)


@api_bp.post("/download-jobs")
def start_download_job():
    """Start a download in the background. The client polls
    /api/download-jobs/<id> and fetches .../file; jobs belong to their session."""
    payload = _json_body()
    platform = _download_platform_param(payload.get("platform"))
    package_platform = _parse_platform_param(payload.get("platform"))  # watch: iPhone or watch-only package
    service = _service()
    account = service.account_info()
    app = _resolve_supported_app(payload, account)
    external_version_id = _resolve_external_version_id(account, app, platform, payload.get("externalVersionId"))
    auto_purchase = bool(payload.get("purchaseIfNeeded", False))
    save_to_server_folder = bool(payload.get("saveToServerFolder", False))
    if save_to_server_folder and not _server_save_allowed():
        return jsonify({"error": "saving on the server is disabled"}), HTTPStatus.FORBIDDEN

    mine, total = download_jobs.active_counts(_owner())
    if mine >= MAX_ACTIVE_PER_OWNER or total >= MAX_ACTIVE_TOTAL:
        return (
            jsonify({"error": "too many downloads in progress - wait for one to finish"}),
            HTTPStatus.TOO_MANY_REQUESTS,
        )
    target_dir = _server_download_dir() if save_to_server_folder else _temp_download_dir()
    if not _enough_free_space(target_dir):
        logger.warning("refusing download: less than %d MB free on %s", jobs_module.MIN_FREE_BYTES // 2**20, target_dir)
        return jsonify({"error": "not enough free disk space on the server"}), HTTPStatus.INSUFFICIENT_STORAGE

    job = download_jobs.create(owner=_owner())
    if save_to_server_folder:
        out_dir = _server_download_dir()
    else:
        out_dir = _temp_download_dir() / job.id
        download_jobs.update(job.id, work_dir=str(out_dir))
    slots = download_jobs.slots

    def worker() -> None:
        started = time.time()
        logger.info(
            "download job %s queued: app %s, version %s%s",
            job.id[:8], app.id, external_version_id or "latest", " (save on server)" if save_to_server_folder else "",
        )
        try:
            with slots:
                download_jobs.update(job.id, status="downloading")
                result, _ = _download_with_retries(
                    service,
                    account,
                    app,
                    out_dir,
                    external_version_id,
                    auto_purchase,
                    on_progress=download_jobs.progress_callback(job.id),
                    on_patch_progress=download_jobs.patch_progress_callback(job.id),
                    platform=platform,
                )
                service.validate_package_platform(result.destination_path, package_platform)

            file_path = Path(result.destination_path)
            size = file_path.stat().st_size
            logger.info(
                "download job %s ready: %s (%.1f MB, %.0fs)", job.id[:8], file_path.name, size / 1e6, time.time() - started
            )
            common = dict(status="ready", filename=file_path.name, bytes_done=size, bytes_total=size)
            if save_to_server_folder:
                download_jobs.update(job.id, server_path=str(file_path), saved_to_server=True, **common)
            else:
                download_jobs.update(job.id, file_path=str(file_path), **common)
        except Exception as exc:  # noqa: BLE001 - surface any failure to the poller
            logger.warning("download job %s failed after %.0fs: %s", job.id[:8], time.time() - started, exc)
            download_jobs.update(job.id, status="error", error=redact_text(str(exc)))

    threading.Thread(target=worker, daemon=True, name=f"download-job-{job.id}").start()
    return jsonify({"jobId": job.id})


@api_bp.get("/download-jobs/<job_id>")
def poll_download_job(job_id: str):
    job = download_jobs.get(job_id, owner=_owner())
    if job is None:
        return jsonify({"error": "job not found"}), HTTPStatus.NOT_FOUND
    data = job.to_dict()
    if job.status == "ready":
        from .ota import ota_urls

        data.update(ota_urls(job))
        # iOS 7.1+ refuses OTA manifests that aren't served over HTTPS.
        data["otaNeedsHttps"] = not request.is_secure
    if job.saved_to_server and job.server_path:
        # Only the file name - no need to reveal the server's directory layout.
        data["serverPath"] = str(Path("Downloads") / "IPATool" / Path(job.server_path).name)
    return jsonify(data)


@api_bp.get("/download-jobs/<job_id>/file")
def fetch_download_job_file(job_id: str):
    job = download_jobs.get(job_id, owner=_owner())
    if job is None or job.status != "ready" or not job.file_path:
        logger.warning(
            "download job %s: file requested but %s", job_id[:8],
            "job unknown (expired, restarted server, or other session)" if job is None else f"status is {job.status}",
        )
        return jsonify({"error": "file not ready"}), HTTPStatus.NOT_FOUND

    file_path = Path(job.file_path)
    if not file_path.exists():
        logger.warning("download job %s: file is gone (expired?)", job_id[:8])
        return jsonify({"error": "file not found"}), HTTPStatus.NOT_FOUND
    logger.info("download job %s: sending %s to the browser", job_id[:8], job.filename or file_path.name)
    return _stream_file(file_path, job.filename or file_path.name)
