"""Atomic, owner-only writes of sensitive files (0600 on POSIX; Windows
profiles are private by default)."""
from __future__ import annotations

import os
import tempfile
import time
from pathlib import Path
from typing import Union

IS_WINDOWS = os.name == "nt"

PathLike = Union[str, Path]


def make_private(path: PathLike) -> None:
    """Best-effort chmod 600 on POSIX; no-op on Windows."""
    if IS_WINDOWS:
        return
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def atomic_write_bytes(path: PathLike, data: bytes, private: bool = True) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{target.name}.", suffix=".tmp", dir=str(target.parent))
    try:
        if private:
            make_private(tmp_name)
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            try:
                os.fsync(handle.fileno())
            except OSError:
                pass
        replace_with_retry(tmp_name, target)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def atomic_write_text(path: PathLike, text: str, private: bool = True) -> None:
    atomic_write_bytes(path, text.encode("utf-8"), private=private)


def replace_with_retry(src: PathLike, dst: PathLike, attempts: int = 5) -> None:
    """``os.replace`` with retries (on Windows anything holding the file blocks it briefly)."""
    last_error: Exception | None = None
    for attempt in range(attempts):
        try:
            os.replace(src, dst)
            return
        except PermissionError as exc:
            last_error = exc
            time.sleep(0.2 * (attempt + 1))
    assert last_error is not None
    raise last_error
