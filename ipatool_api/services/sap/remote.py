"""Random access to a remote file over HTTP range requests.

The macOS restore image is ~26 GB; only a few hundred MB of it are ever read
(ipatool internal/sap/assets/http_range.go). ``RemoteFile`` reads exact
ranges, retrying broken transfers, and keeps a small cache of 64 KB blocks so
that the many tiny reads of zip/AEA/APFS metadata don't each become a request.
"""
from __future__ import annotations

import io
import logging
import re
import threading
from collections import OrderedDict
from typing import Optional

import requests

logger = logging.getLogger(__name__)

_ATTEMPTS = 3
_BLOCK = 64 << 10
_CACHED_BLOCKS = 256
_CONTENT_RANGE = re.compile(r"bytes (\d+)-(\d+)/(\d+)")


class RemoteError(IOError):
    pass


class RemoteFile:
    def __init__(self, url: str, session: Optional[requests.Session] = None, verify=True, timeout: float = 120.0) -> None:
        self.url = url
        self._session = session or requests.Session()
        self._verify = verify
        self._timeout = timeout
        self._lock = threading.Lock()
        self._blocks: "OrderedDict[int, bytes]" = OrderedDict()
        self.requests = 0
        self.bytes_read = 0
        response = self._get(0, 0)
        match = _CONTENT_RANGE.match(response.headers.get("Content-Range", ""))
        if response.status_code != 206 or not match:
            raise RemoteError(f"{url}: server doesn't support range requests (HTTP {response.status_code})")
        self.size = int(match.group(3))

    def _get(self, start: int, end: int) -> requests.Response:
        self.requests += 1
        return self._session.get(
            self.url, headers={"Range": f"bytes={start}-{end}"}, timeout=self._timeout, verify=self._verify
        )

    def _fetch(self, offset: int, length: int) -> bytes:
        data = bytearray()
        last_error: Optional[Exception] = None
        for _ in range(_ATTEMPTS):
            start = offset + len(data)
            end = offset + length - 1
            try:
                response = self._get(start, end)
                if response.status_code != 206:
                    raise RemoteError(f"range request returned HTTP {response.status_code}")
                match = _CONTENT_RANGE.match(response.headers.get("Content-Range", ""))
                if not match or int(match.group(1)) != start or int(match.group(2)) != end or int(match.group(3)) != self.size:
                    raise RemoteError(f"unexpected Content-Range {response.headers.get('Content-Range')!r}")
                data += response.content
                self.bytes_read += len(response.content)
                if len(data) >= length:
                    return bytes(data[:length])
            except (requests.RequestException, RemoteError) as exc:
                last_error = exc
                logger.debug("range read at %d failed: %s", start, exc)
        raise RemoteError(f"reading {length} bytes at offset {offset} failed: {last_error}")

    def read_at(self, offset: int, length: int) -> bytes:
        if offset < 0 or length < 0 or offset + length > self.size:
            raise RemoteError(f"read {offset}+{length} outside the file ({self.size} bytes)")
        if length == 0:
            return b""
        if length >= _BLOCK:
            return self._fetch(offset, length)
        out = bytearray()
        position = offset
        end = offset + length
        while position < end:
            index = position // _BLOCK
            block = self._block(index)
            inside = position - index * _BLOCK
            take = min(end - position, len(block) - inside)
            out += block[inside:inside + take]
            position += take
        return bytes(out)

    def _block(self, index: int) -> bytes:
        with self._lock:
            block = self._blocks.get(index)
            if block is not None:
                self._blocks.move_to_end(index)
                return block
        start = index * _BLOCK
        block = self._fetch(start, min(_BLOCK, self.size - start))
        with self._lock:
            self._blocks[index] = block
            while len(self._blocks) > _CACHED_BLOCKS:
                self._blocks.popitem(last=False)
        return block


class SectionReader:
    """read_at() view of part of another reader."""

    def __init__(self, source, offset: int, size: int) -> None:
        self._source = source
        self._offset = offset
        self.size = size

    def read_at(self, offset: int, length: int) -> bytes:
        if offset < 0 or offset + length > self.size:
            raise RemoteError("read outside the section")
        return self._source.read_at(self._offset + offset, length)


class FileAdapter(io.RawIOBase):
    """File object over a read_at() reader (for the zipfile module)."""

    def __init__(self, source) -> None:
        self._source = source
        self._position = 0

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def seek(self, offset: int, whence: int = 0) -> int:
        if whence == 1:
            offset += self._position
        elif whence == 2:
            offset += self._source.size
        self._position = max(0, offset)
        return self._position

    def tell(self) -> int:
        return self._position

    def read(self, size: int = -1) -> bytes:
        remaining = self._source.size - self._position
        if size is None or size < 0 or size > remaining:
            size = max(0, remaining)
        data = self._source.read_at(self._position, size)
        self._position += len(data)
        return data

    def readinto(self, buffer) -> int:
        data = self.read(len(buffer))
        buffer[:len(data)] = data
        return len(data)
