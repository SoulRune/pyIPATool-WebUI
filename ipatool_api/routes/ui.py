"""Web UI routes."""
from __future__ import annotations

from flask import Blueprint, Response, current_app, render_template

ui_bp = Blueprint("ui", __name__)


@ui_bp.get("/ca.crt")
def ca_certificate():
    """The root CA that signed this server's certificate (public, no key),
    as DER so iOS Safari offers to install it as a profile."""
    data = current_app.config.get("CA_CERTIFICATE")
    if not data:
        return Response("No CA certificate configured (start the server with --ca-file).", status=404, mimetype="text/plain")
    return Response(
        data,
        mimetype="application/x-x509-ca-cert",
        # inline, not attachment: iOS Safari hands this MIME type to the
        # profile installer; older iOS can't "download" a file at all.
        headers={"Content-Disposition": 'inline; filename="pyIPATool-root-ca.crt"'},
    )


@ui_bp.get("/")
def index():
    from ..services.constants import STORE_FRONTS

    return render_template(
        "index.html",
        store_regions=sorted(STORE_FRONTS),
        legacy=bool(current_app.config.get("LEGACY_MODE", False)),
        session_mode=current_app.config.get("SESSION_MODE", "local"),
        allow_server_save=bool(current_app.config.get("ALLOW_SERVER_SAVE", False)),
        sap_available=bool(current_app.config.get("SAP_AVAILABLE", True)),
        sap_install_hint=current_app.config.get("SAP_INSTALL_HINT", ""),
        ca_available=bool(current_app.config.get("CA_CERTIFICATE")),
        catalog_available=_catalog_available(),
    )


def _catalog_available() -> bool:
    from ..services import catalog
    from ..services.appstore import AppStoreService

    return catalog.any_configured(AppStoreService.BUILTIN_CATALOG)


# /source packs code and documentation only (allow-list), so keys or token
# files in the program folder can't leak; vendored Unicorn is left out.
_SOURCE_SKIP_DIRS = {"__pycache__", ".git", ".venv", "venv", "env", "node_modules", "unicorn"}
_SOURCE_SUFFIXES = (".py", ".html", ".js", ".css", ".md", ".txt", ".plist", ".toml", ".cfg", ".ini", ".sh",
                    ".bat", ".ps1", ".svg", ".png", ".ico", ".conf", ".service")
_SOURCE_NAMES = {"LICENSE", "NOTICE", "COPYING", "Makefile", "Dockerfile", "Caddyfile"}
_SOURCE_SECRET_HINTS = ("password", "secret", "token", "credential", "private")


def _source_file_wanted(name: str) -> bool:
    lower = name.lower()
    if name.startswith("."):
        return False
    code = lower.endswith((".py", ".html", ".js", ".css", ".md"))
    # "password.txt", "github-token.txt", ... - but not code such as vault.py.
    if not code and any(hint in lower for hint in _SOURCE_SECRET_HINTS):
        return False
    return name in _SOURCE_NAMES or lower.endswith(_SOURCE_SUFFIXES)


@ui_bp.get("/source")
def source_archive():
    """The source code of this running copy as a zip (GNU AGPL-3.0, section
    13): whoever uses the server can get exactly what it runs, with any local
    changes."""
    from pathlib import Path

    root = Path(__file__).resolve().parents[2]
    cached = _SOURCE_CACHE.get("zip")
    if cached is None:
        cached = _SOURCE_CACHE["zip"] = _build_source_zip(root)
    return Response(
        cached,
        mimetype="application/zip",
        headers={"Content-Disposition": 'attachment; filename="pyIPATool-WebUI-source.zip"'},
    )


# Built once per run (the code doesn't change while it runs) - asking for it
# repeatedly costs nothing.
_SOURCE_CACHE: dict = {}


def _build_source_zip(root) -> bytes:
    import io
    import os
    import zipfile
    from pathlib import Path

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for folder, dirs, files in os.walk(root):
            dirs[:] = sorted(d for d in dirs if d not in _SOURCE_SKIP_DIRS and not d.startswith("."))
            for name in sorted(files):
                if not _source_file_wanted(name):
                    continue
                path = Path(folder) / name
                if path.is_symlink():
                    continue
                archive.write(path, "pyIPATool-WebUI/" + path.relative_to(root).as_posix())
    return buffer.getvalue()
