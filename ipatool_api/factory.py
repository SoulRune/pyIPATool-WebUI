"""Flask application factory."""
from __future__ import annotations

import logging
import os
import secrets
import shutil
from pathlib import Path
from typing import Iterable, Optional

from flask import Flask, g, request

from .routes.api import api_bp
from .routes.ota import ota_bp
from .routes.ui import ui_bp
from .services import (
    AppStoreConfig,
    AppStoreService,
    BrowserSessionCodec,
    CookieStore,
    FileKeychain,
    LocalState,
    Machine,
)
from .services.jobs import download_jobs

logger = logging.getLogger(__name__)

SESSION_MODE_LOCAL = "local"
SESSION_MODE_BROWSER = "browser"


def _ssl_verify_setting(config_dir: Path):
    if os.getenv("IPATOOL_SSL_NO_VERIFY") == "1":
        return False
    ca_bundle_env = os.getenv("IPATOOL_CA_BUNDLE")
    if ca_bundle_env:
        return ca_bundle_env
    default_bundle = config_dir / "ca-bundle.pem"
    if default_bundle.exists():
        return str(default_bundle)
    return True


def _clear_temp_downloads(temp_downloads_dir: Path) -> None:
    # Jobs live in memory, so anything left here at startup is orphaned.
    if temp_downloads_dir.exists():
        for leftover in temp_downloads_dir.iterdir():
            try:
                if leftover.is_file():
                    leftover.unlink()
                elif leftover.is_dir():
                    shutil.rmtree(leftover, ignore_errors=True)
            except OSError:
                pass  # best-effort
    temp_downloads_dir.mkdir(parents=True, exist_ok=True)


def create_app(
    ca_certificate: Optional[bytes] = None,
    legacy: bool = False,
    session_mode: str = SESSION_MODE_LOCAL,
    allow_server_save: Optional[bool] = None,
    trusted_hosts: Optional[Iterable[str]] = None,
    session_days: int = 30,
    max_concurrent_downloads: int = 2,
    repo_url: str = "",
    access_password: str = "",
) -> Flask:
    """session_mode "local": one shared account in ~/.ipatool; "browser": each
    browser signs in separately (encrypted cookie). allow_server_save: offer
    "Save on server" (default: only in local mode)."""
    if session_mode not in (SESSION_MODE_LOCAL, SESSION_MODE_BROWSER):
        raise ValueError(f"invalid session mode {session_mode!r}")
    if allow_server_save is None:
        allow_server_save = session_mode == SESSION_MODE_LOCAL

    package_root = Path(__file__).resolve().parent
    app = Flask(
        __name__,
        template_folder=str(package_root.parent / "templates"),
        static_folder=str(package_root.parent / "static"),
    )

    app.config["LEGACY_MODE"] = legacy
    app.config["CA_CERTIFICATE"] = ca_certificate
    app.config["SESSION_MODE"] = session_mode
    app.config["ALLOW_SERVER_SAVE"] = bool(allow_server_save)
    # Browsers may send JSON of any size to /api/*; nothing legit needs more.
    app.config["MAX_CONTENT_LENGTH"] = 64 * 1024
    # AGPL-3.0 section 13: the footer always links /source (this running copy);
    # --repo-url adds a link to the repository.
    app.config["REPO_URL"] = (repo_url or "").strip()
    if trusted_hosts:
        # Host allow-list against DNS rebinding. Not Flask's TRUSTED_HOSTS:
        # Werkzeug 3.1.9 can't match "[::1]".
        allowed = [_bare_host(name) for name in trusted_hosts if name]

        @app.before_request
        def _check_host():
            host = _bare_host(request.headers.get("Host", ""))
            if not host or not any(host == ref or (ref.startswith(".") and host.endswith(ref))
                                   for ref in allowed):
                return ("Bad Request: untrusted Host header", 400)
            return None

    @app.before_request
    def _require_https():
        """Behind an HTTPS proxy: plain-HTTP pages are redirected, anything
        that sends data is refused."""
        if not app.config.get("REQUIRE_HTTPS") or request.is_secure:
            return None
        if request.method in ("GET", "HEAD"):
            from flask import redirect

            # request.url keeps a path prefix the proxy may add (X-Forwarded-Prefix)
            return redirect("https://" + request.url.split("://", 1)[1], code=301)
        return ("HTTPS required", 403)

    # Access password and per-IP limits (access.py) - before any other work.
    from . import access

    access.install(app, access_password)

    machine = Machine()
    config_dir = Path(machine.home_directory()) / ".ipatool"
    config_dir.mkdir(parents=True, exist_ok=True)
    _clear_temp_downloads(config_dir / "temp_downloads")

    verify = _ssl_verify_setting(config_dir)
    app.config["SSL_VERIFY"] = verify
    app.config["MACHINE"] = machine
    app.config["STORAGE_DIR"] = config_dir
    download_jobs.configure(max_concurrent_downloads)

    from .services.sap import unicorn_available, unicorn_install_hint

    app.config["SAP_AVAILABLE"] = unicorn_available()
    app.config["SAP_INSTALL_HINT"] = "" if app.config["SAP_AVAILABLE"] else unicorn_install_hint()
    if not app.config["SAP_AVAILABLE"]:
        logger.warning(
            "the 'unicorn' package is not installed: App Store sign-in will not work. %s. "
            "Already signed-in sessions keep working until their token expires.",
            app.config["SAP_INSTALL_HINT"],
        )

    if session_mode == SESSION_MODE_LOCAL:
        state = LocalState(
            FileKeychain(str(config_dir / "keychain.json")),
            CookieStore(str(config_dir / "cookies.lwp")),
            machine,
            accounts_dir=config_dir / "accounts",  # saved sign-ins (account switcher)
        )
        shared_service = AppStoreService(AppStoreConfig(state=state, machine=machine, verify=verify))

        @app.before_request
        def _bind_local_state():
            g.session_state = state
            g.appstore = shared_service
            if request.path.startswith("/api/"):
                # Each operation starts without the previous one's session
                # cookies, as each ipatool command does.
                state.cookies.drop_session_cookies()

    else:
        codec = BrowserSessionCodec(
            BrowserSessionCodec.load_or_create_secret(config_dir / "session_secret.key"),
            max_age_days=session_days,
        )
        app.config["SESSION_CODEC"] = codec
        logger.info("per-browser sessions enabled (cookie encryption: %s)", codec.backend)

        @app.before_request
        def _bind_browser_state():
            state = codec.load(request.cookies)
            g.session_state = state
            # A service instance per request: it carries this browser's
            # cookie jar and device GUID, nothing is shared between users.
            g.appstore = AppStoreService(AppStoreConfig(state=state, machine=machine, verify=verify))

        @app.after_request
        def _persist_browser_state(response):
            state = g.get("session_state")
            if state is not None:
                codec.store(state, request, response)
            return response

    @app.before_request
    def _csp_nonce():
        g.csp_nonce = secrets.token_urlsafe(16)

    @app.context_processor
    def _inject_csp_nonce():
        return {"csp_nonce": g.get("csp_nonce", ""), "repo_url": app.config["REPO_URL"]}

    @app.after_request
    def _security_headers(response):
        if response.mimetype == "text/html":
            # Second line against XSS: own scripts and the nonce'd inline one, no framing.
            nonce = g.get("csp_nonce", "")
            response.headers.setdefault(
                "Content-Security-Policy",
                "default-src 'self'; "
                f"script-src 'self' 'nonce-{nonce}'; "
                "style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data:; "
                "connect-src 'self'; "
                "object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'self'",
            )
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        if app.config.get("REQUIRE_HTTPS") and request.is_secure:
            # Browsers then never try plain HTTP for this site again.
            response.headers.setdefault("Strict-Transport-Security", "max-age=31536000")
        if request.path.startswith("/api/"):
            response.headers.setdefault("Cache-Control", "no-store")
        return response

    app.register_blueprint(api_bp)
    app.register_blueprint(ota_bp)
    app.register_blueprint(ui_bp)
    return app


def _bare_host(value: str) -> str:
    """"Host" header / trusted name -> lower-case host without the port;
    IPv6 without brackets ("[::1]:5002", "[::1]", "::1" -> "::1")."""
    value = (value or "").strip().lower()
    if value.startswith("["):
        end = value.find("]")
        return value[1:end] if end > 0 else ""
    if value.count(":") > 1:
        return value  # bare IPv6
    return value.partition(":")[0]
