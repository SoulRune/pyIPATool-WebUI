"""In-memory registry of background downloads: a POST starts one, the client
polls its progress and fetches the file with a plain GET (works on iOS 6)."""
from __future__ import annotations

import hmac
import secrets
import shutil
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Optional

# Finished jobs and their files are swept this long after their last update.
JOB_TTL_SECONDS = 30 * 60
# A job that hasn't reported progress for this long is considered dead.
STALE_JOB_SECONDS = 3 * 60 * 60
# How many downloads may run at once; the rest wait in "queued". Each one
# holds a connection to Apple's CDN and, while patching, some CPU/disk.
DEFAULT_MAX_CONCURRENT = 2
# Unfinished (queued/downloading) jobs allowed at once - per session and in
# total - so nobody on the network can queue unlimited multi-GB downloads.
MAX_ACTIVE_PER_OWNER = 3
MAX_ACTIVE_TOTAL = 10
# Don't start a download with less free disk space than this.
MIN_FREE_BYTES = 1024 ** 3
_SWEEP_INTERVAL = 60


@dataclass
class DownloadJob:
    id: str
    owner: str = ""
    status: str = "queued"  # queued -> downloading -> ready | error
    # Sub-stage within "downloading": 'download' (raw bytes from Apple) or
    # 'patching' (adding iTunesMetadata.plist + SINF - now near-instant).
    phase: str = "download"
    bytes_done: int = 0
    bytes_total: Optional[int] = None
    items_done: int = 0
    items_total: Optional[int] = None
    filename: Optional[str] = None
    file_path: Optional[str] = None
    # Per-job scratch directory for browser-delivered downloads; removed
    # together with the job.
    work_dir: Optional[str] = None
    error: Optional[str] = None
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    # Set instead of file_path when the job saved straight to a persistent
    # folder on the server. Never auto-deleted.
    server_path: Optional[str] = None
    saved_to_server: bool = False
    # Authorises the OTA links (the iOS installer sends no session cookie).
    ota_token: str = field(default_factory=lambda: secrets.token_urlsafe(24))
    app_info: Optional[Dict[str, str]] = None  # cached identity of the finished package (OTA)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "phase": self.phase,
            "bytesDone": self.bytes_done,
            "bytesTotal": self.bytes_total,
            "itemsDone": self.items_done,
            "itemsTotal": self.items_total,
            "filename": self.filename,
            "error": self.error,
            "savedToServer": self.saved_to_server,
            "serverPath": self.server_path,
        }


class DownloadJobRegistry:
    def __init__(self, max_concurrent: int = DEFAULT_MAX_CONCURRENT) -> None:
        self._lock = threading.Lock()
        self._jobs: Dict[str, DownloadJob] = {}
        self._last_sweep = 0.0
        self.slots = threading.BoundedSemaphore(max(1, max_concurrent))

    def configure(self, max_concurrent: int) -> None:
        self.slots = threading.BoundedSemaphore(max(1, max_concurrent))

    def create(self, owner: str, work_dir: Optional[str] = None) -> DownloadJob:
        self._maybe_sweep(force=True)
        job = DownloadJob(id=uuid.uuid4().hex, owner=owner, work_dir=work_dir)
        with self._lock:
            self._jobs[job.id] = job
        return job

    def active_counts(self, owner: str):
        """(unfinished jobs of ``owner``, unfinished jobs overall)."""
        with self._lock:
            active = [j for j in self._jobs.values() if j.status in ("queued", "downloading")]
        return sum(1 for j in active if j.owner == owner), len(active)

    def get(self, job_id: str, owner: Optional[str] = None) -> Optional[DownloadJob]:
        """Return the job, or None if it doesn't exist *or belongs to someone
        else* - with per-browser sessions, one user must never be able to
        poll or fetch another user's download, even with a guessed id."""
        self._maybe_sweep()
        with self._lock:
            job = self._jobs.get(job_id)
        if job is None:
            return None
        if owner is not None and job.owner != owner:
            return None
        return job

    def update(self, job_id: str, **kwargs: Any) -> None:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                return
            for key, value in kwargs.items():
                setattr(job, key, value)
            job.updated_at = time.time()

    def progress_callback(self, job_id: str) -> Callable[[int, Optional[int]], None]:
        def _cb(bytes_done: int, bytes_total: Optional[int]) -> None:
            self.update(job_id, status="downloading", phase="download", bytes_done=bytes_done, bytes_total=bytes_total)

        return _cb

    def patch_progress_callback(self, job_id: str) -> Callable[[int, int], None]:
        def _cb(items_done: int, items_total: int) -> None:
            self.update(job_id, status="downloading", phase="patching", items_done=items_done, items_total=items_total)

        return _cb

    def get_by_ota_token(self, job_id: str, token: str) -> Optional[DownloadJob]:
        with self._lock:
            job = self._jobs.get(job_id)
        if job is None or not token or not hmac.compare_digest(job.ota_token, token):
            return None
        return job

    def touch(self, job_id: str) -> None:
        """Keep a job (and its file) alive while it's being used, e.g. by an
        OTA install that starts a while after the download finished."""
        with self._lock:
            job = self._jobs.get(job_id)
            if job is not None:
                job.updated_at = time.time()

    def remove(self, job_id: str) -> None:
        with self._lock:
            self._jobs.pop(job_id, None)

    def _maybe_sweep(self, force: bool = False) -> None:
        now = time.time()
        if not force and now - self._last_sweep < _SWEEP_INTERVAL:
            return
        self._last_sweep = now
        stale = []
        with self._lock:
            for job in self._jobs.values():
                idle = now - job.updated_at
                finished = job.status in ("ready", "error")
                if (finished and idle > JOB_TTL_SECONDS) or idle > STALE_JOB_SECONDS:
                    stale.append(job)
            for job in stale:
                self._jobs.pop(job.id, None)
        for job in stale:
            _cleanup_job_files(job)


def _cleanup_job_files(job: DownloadJob) -> None:
    if job.file_path:
        try:
            Path(job.file_path).unlink(missing_ok=True)
        except OSError:
            pass
    if job.work_dir:
        shutil.rmtree(job.work_dir, ignore_errors=True)


# One process-wide registry, mirroring how the app-level services are shared.
download_jobs = DownloadJobRegistry()
