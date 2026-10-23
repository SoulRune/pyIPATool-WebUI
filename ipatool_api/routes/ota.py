"""Over-the-air installation (itms-services) of finished downloads.

iOS fetches the manifest and the IPA itself, without the session cookie, so
both URLs carry the job's secret token. iOS 7.1+ needs HTTPS with a trusted
certificate.
"""
from __future__ import annotations

import logging
import plistlib
import re
from http import HTTPStatus
from pathlib import Path
from typing import Dict, Optional
from urllib.parse import quote
from zipfile import BadZipFile, ZipFile

from flask import Blueprint, Response, current_app, jsonify, request, send_file

from ..services.jobs import DownloadJob, download_jobs

logger = logging.getLogger(__name__)

ota_bp = Blueprint("ota", __name__, url_prefix="/ota")

_INFO_PLIST_RE = re.compile(r"^Payload/[^/]+\.app/Info\.plist$")


def job_package_path(job: DownloadJob) -> Optional[Path]:
    path = job.file_path or job.server_path
    return Path(path) if path else None


def ota_urls(job: DownloadJob) -> Dict[str, str]:
    """Absolute manifest URL and the itms-services link for a ready job."""
    base = request.host_url.rstrip("/") + (request.script_root or "")
    manifest = f"{base}/ota/{job.id}/{job.ota_token}/manifest.plist"
    package = job_package_path(job)
    minimum_os = _app_info(package, job)["minimum_os"] if package is not None and package.exists() else ""
    return {
        "minimumOsVersion": minimum_os,
        "manifestUrl": manifest,
        "installUrl": "itms-services://?action=download-manifest&url=" + quote(manifest, safe=""),
    }


_MAX_PLIST_BYTES = 4 * 1024 * 1024


def _read_plist(zf: ZipFile, name: Optional[str]) -> Dict:
    if not name:
        return {}
    try:
        if zf.getinfo(name).file_size > _MAX_PLIST_BYTES:  # never inflate a huge entry into memory
            return {}
        value = plistlib.loads(zf.read(name))
    except (KeyError, plistlib.InvalidFileException, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def _app_info(package: Path, job: Optional[DownloadJob] = None) -> Dict[str, str]:
    """Identity for the manifest from Info.plist (else the added
    iTunesMetadata.plist); cached on the job."""
    if job is not None and job.app_info:
        return job.app_info
    info_out = _read_app_info(package)
    if job is not None:
        download_jobs.update(job.id, app_info=info_out)
    return info_out


def _read_app_info(package: Path) -> Dict[str, str]:
    try:
        with ZipFile(package) as zf:
            names = zf.namelist()
            info = _read_plist(zf, next((n for n in names if _INFO_PLIST_RE.match(n)), None))
            meta = _read_plist(zf, "iTunesMetadata.plist" if "iTunesMetadata.plist" in names else None)
    except (OSError, BadZipFile):
        info, meta = {}, {}
    return {
        "minimum_os": str(info.get("MinimumOSVersion") or ""),
        "bundle_id": str(info.get("CFBundleIdentifier") or meta.get("softwareVersionBundleId") or ""),
        "version": str(
            info.get("CFBundleShortVersionString") or meta.get("bundleShortVersionString")
            or info.get("CFBundleVersion") or "1.0"
        ),
        "title": str(
            info.get("CFBundleDisplayName") or info.get("CFBundleName") or meta.get("itemName") or package.stem
        ),
    }


def _ready_job(job_id: str, token: str) -> Optional[DownloadJob]:
    job = download_jobs.get_by_ota_token(job_id, token)
    if job is None or job.status != "ready":
        return None
    package = job_package_path(job)
    if package is None or not package.exists():
        return None
    download_jobs.touch(job.id)
    return job


@ota_bp.get("/<job_id>/<token>/manifest.plist")
def manifest(job_id: str, token: str):
    job = _ready_job(job_id, token)
    if job is None:
        return jsonify({"error": "not found"}), HTTPStatus.NOT_FOUND
    package = job_package_path(job)
    info = _app_info(package, job)
    base = request.host_url.rstrip("/") + (request.script_root or "")
    package_base = base
    http_port = current_app.config.get("OTA_HTTP_PORT")
    if http_port:
        host = request.host
        if not host.endswith("]") and ":" in host:
            host = host.rsplit(":", 1)[0]  # drop the HTTPS port
        package_base = f"http://{host}:{http_port}{request.script_root or ''}"
    document = {
        "items": [
            {
                "assets": [
                    {"kind": "software-package", "url": f"{package_base}/ota/{job.id}/{job.ota_token}/app.ipa"},
                ],
                "metadata": {
                    "bundle-identifier": info["bundle_id"],
                    "bundle-version": info["version"],
                    "kind": "software",
                    "title": info["title"],
                },
            }
        ]
    }
    logger.info("OTA: manifest for %s (%s %s) requested by %s", job.id[:8], info["bundle_id"], info["version"], request.remote_addr)
    return Response(plistlib.dumps(document, fmt=plistlib.FMT_XML), mimetype="text/xml")


@ota_bp.get("/<job_id>/<token>/app.ipa")
def package(job_id: str, token: str):
    job = _ready_job(job_id, token)
    if job is None:
        return jsonify({"error": "not found"}), HTTPStatus.NOT_FOUND
    path = job_package_path(job)
    logger.info(
        "OTA: sending %s to the installer at %s over %s%s", path.name, request.remote_addr,
        request.scheme.upper(), f" (Range: {request.headers['Range']})" if request.headers.get("Range") else "",
    )
    # conditional=True: Range requests, so the installer can resume.
    return send_file(path, mimetype="application/octet-stream", conditional=True, etag=True, max_age=0)
