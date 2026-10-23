"""ZIP framing for OTA installs, ported from ipatool v2.6.0 replicateZip
(byte-for-byte the same output).

iOS unpacks an OTA download front to back from the local headers: deflated
entries get a data descriptor, stored ones inline sizes. Entry data is copied
raw.
"""
from __future__ import annotations

import logging
import os
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Callable, List, Optional

logger = logging.getLogger(__name__)

_LOCAL_SIG = 0x04034B50
_CENTRAL_SIG = 0x02014B50
_EOCD_SIG = 0x06054B50
_ZIP64_EOCD_SIG = 0x06064B50
_ZIP64_LOCATOR_SIG = 0x07064B50
_DESCRIPTOR_SIG = 0x08074B50
_ZIP64_EXTRA_ID = 0x0001

_LOCAL_LEN = 30
_CENTRAL_LEN = 46
_EOCD_LEN = 22
_ZIP64_EOCD_LEN = 56
_ZIP64_LOCATOR_LEN = 20

_U16MAX = 0xFFFF
_U32MAX = 0xFFFFFFFF

_STORE = 0
_DEFLATE = 8
_FLAG_DESCRIPTOR = 0x8
_ZIP_VERSION_45 = 45

_COPY_CHUNK = 1 << 20


class ZipFramingError(Exception):
    pass


@dataclass
class _Entry:
    creator_version: int
    reader_version: int
    flags: int
    method: int
    mod_time: int
    mod_date: int
    crc: int
    compressed_size: int
    uncompressed_size: int
    name: bytes
    central_extra: bytes
    comment: bytes
    external_attrs: int
    local_offset: int  # absolute, base already applied
    local_extra: bytes = b""
    local_flags: int = 0
    local_crc: int = 0
    local_compressed: int = 0
    local_uncompressed: int = 0
    data_offset: int = 0

    @property
    def is_dir(self) -> bool:
        return self.name.endswith(b"/")

    @property
    def is_zip64(self) -> bool:  # Go FileHeader.isZip64
        return self.compressed_size >= _U32MAX or self.uncompressed_size >= _U32MAX

    def target_flags(self) -> int:
        if self.is_dir or self.method == _STORE:
            return self.flags & ~_FLAG_DESCRIPTOR
        if self.method == _DEFLATE:
            return self.flags | _FLAG_DESCRIPTOR
        return self.flags


# ---------------------------------------------------------------------------
# Reading (appstore_zip_headers.go)
# ---------------------------------------------------------------------------


def _read_at(handle: BinaryIO, offset: int, size: int) -> bytes:
    handle.seek(offset)
    data = handle.read(size)
    if len(data) != size:
        raise ZipFramingError("unexpected end of archive")
    return data


def _directory_end(handle: BinaryIO, size: int):
    tail_len = min(size, _EOCD_LEN + _U16MAX)
    tail = _read_at(handle, size - tail_len, tail_len)
    for i in range(len(tail) - _EOCD_LEN, -1, -1):
        if struct.unpack_from("<I", tail, i)[0] != _EOCD_SIG:
            continue
        comment_len = struct.unpack_from("<H", tail, i + 20)[0]
        if i + _EOCD_LEN + comment_len > len(tail):
            continue
        records = struct.unpack_from("<H", tail, i + 10)[0]
        dir_size = struct.unpack_from("<I", tail, i + 12)[0]
        dir_offset = struct.unpack_from("<I", tail, i + 16)[0]
        end_offset = size - len(tail) + i
        # zip64 locator right before the end record?
        if end_offset >= _ZIP64_LOCATOR_LEN:
            locator = _read_at(handle, end_offset - _ZIP64_LOCATOR_LEN, _ZIP64_LOCATOR_LEN)
            if struct.unpack_from("<I", locator, 0)[0] == _ZIP64_LOCATOR_SIG:
                disk, offset64, disks = struct.unpack_from("<IQI", locator, 4)
                if offset64 > size or disk != 0 or disks != 1:
                    raise ZipFramingError("unsupported zip64 locator")
                end = _read_at(handle, offset64, _ZIP64_EOCD_LEN)
                if struct.unpack_from("<I", end, 0)[0] != _ZIP64_EOCD_SIG:
                    raise ZipFramingError("bad zip64 end record")
                records = struct.unpack_from("<Q", end, 32)[0]
                dir_size = struct.unpack_from("<Q", end, 40)[0]
                dir_offset = struct.unpack_from("<Q", end, 48)[0]
                end_offset = offset64
        return records, dir_size, dir_offset, end_offset
    raise ZipFramingError("not a zip archive")


def _zip64_values(extra: bytes):
    while len(extra) >= 4:
        tag, length = struct.unpack_from("<HH", extra, 0)
        if length > len(extra) - 4:
            raise ZipFramingError("malformed extra field")
        if tag == _ZIP64_EXTRA_ID:
            return extra[4 : 4 + length]
        extra = extra[4 + length :]
    return None


def _read_entries(handle: BinaryIO, size: int) -> List[_Entry]:
    records, dir_size, dir_offset, end_offset = _directory_end(handle, size)
    if dir_size > end_offset:
        raise ZipFramingError("bad central directory size")
    base = end_offset - dir_size - dir_offset
    if base > 0:
        # Prefer the declared offset if it already points at a central header.
        handle.seek(dir_offset)
        if handle.read(4) == struct.pack("<I", _CENTRAL_SIG):
            base = 0
    if base < 0 or base > size - dir_offset:
        raise ZipFramingError("bad central directory offset")

    entries: List[_Entry] = []
    handle.seek(base + dir_offset)
    directory = handle.read(end_offset - (base + dir_offset))
    pos = 0
    while pos + 4 <= len(directory) and struct.unpack_from("<I", directory, pos)[0] == _CENTRAL_SIG:
        if pos + _CENTRAL_LEN > len(directory):
            raise ZipFramingError("truncated central directory entry")
        (
            _sig, creator, reader, flags, method, mtime, mdate, crc, csize, usize,
            name_len, extra_len, comment_len, _disk, _internal, external, offset,
        ) = struct.unpack_from("<IHHHHHHIIIHHHHHII", directory, pos)
        pos += _CENTRAL_LEN
        name = directory[pos : pos + name_len]
        extra = directory[pos + name_len : pos + name_len + extra_len]
        comment = directory[pos + name_len + extra_len : pos + name_len + extra_len + comment_len]
        pos += name_len + extra_len + comment_len
        if pos > len(directory):
            raise ZipFramingError("truncated central directory entry")

        zip64 = _zip64_values(extra)
        cursor = 0
        if usize == _U32MAX:
            if zip64 is None or len(zip64) < cursor + 8:
                raise ZipFramingError("missing zip64 size")
            usize = struct.unpack_from("<Q", zip64, cursor)[0]
            cursor += 8
        if csize == _U32MAX:
            if zip64 is None or len(zip64) < cursor + 8:
                raise ZipFramingError("missing zip64 size")
            csize = struct.unpack_from("<Q", zip64, cursor)[0]
            cursor += 8
        if offset == _U32MAX:
            if zip64 is None or len(zip64) < cursor + 8:
                raise ZipFramingError("missing zip64 offset")
            offset = struct.unpack_from("<Q", zip64, cursor)[0]

        entries.append(
            _Entry(creator, reader, flags, method, mtime, mdate, crc, csize, usize,
                   name, extra, comment, external, base + offset)
        )

    if len(entries) != records:
        # Never rewrite an archive that wasn't fully parsed: a reframe of a
        # partial entry list would silently drop files from the IPA.
        raise ZipFramingError(f"central directory lists {records} entries, parsed {len(entries)}")

    for entry in entries:
        local = _read_at(handle, entry.local_offset, _LOCAL_LEN)
        (sig, _ver, lflags, _m, _t, _d, lcrc, lcsize, lusize, lname_len, lextra_len) = struct.unpack(
            "<IHHHHHIIIHH", local
        )
        if sig != _LOCAL_SIG:
            raise ZipFramingError("bad local header")
        meta = _read_at(handle, entry.local_offset + _LOCAL_LEN, lname_len + lextra_len)
        if meta[:lname_len] != entry.name:
            raise ZipFramingError("local and central names differ")
        entry.local_extra = meta[lname_len:]
        entry.local_flags = lflags
        entry.local_crc, entry.local_compressed, entry.local_uncompressed = lcrc, lcsize, lusize
        entry.data_offset = entry.local_offset + _LOCAL_LEN + lname_len + lextra_len
    return entries


# ---------------------------------------------------------------------------
# Checking
# ---------------------------------------------------------------------------


def is_streaming_framed(path: str) -> bool:
    """True if every entry already follows the framing rule, so rewriting
    would not change how a streaming installer reads it."""
    with open(path, "rb") as handle:
        size = os.fstat(handle.fileno()).st_size
        entries = _read_entries(handle, size)
        for entry in entries:
            wanted = entry.target_flags()
            if entry.flags != wanted or entry.local_flags != wanted:
                return False
            if wanted & _FLAG_DESCRIPTOR:
                if entry.local_crc or entry.local_compressed or entry.local_uncompressed:
                    return False
                handle.seek(entry.data_offset + entry.compressed_size)
                if handle.read(4) != struct.pack("<I", _DESCRIPTOR_SIG):
                    return False
            elif entry.method in (_STORE,) or entry.is_dir:
                if entry.local_crc != entry.crc:
                    return False
                if entry.is_zip64:
                    local64 = _zip64_values(entry.local_extra)
                    if local64 is None or len(local64) < 16:
                        return False
                    lu, lc = struct.unpack_from("<QQ", local64, 0)
                    if (lu, lc) != (entry.uncompressed_size, entry.compressed_size):
                        return False
                elif (entry.local_compressed, entry.local_uncompressed) != (
                    entry.compressed_size,
                    entry.uncompressed_size,
                ):
                    return False
    return True


# ---------------------------------------------------------------------------
# Writing (replicateZip + Go archive/zip Writer.CreateRaw/Close)
# ---------------------------------------------------------------------------


def _extra_without_zip64(extra: bytes) -> bytes:
    result = bytearray()
    while len(extra) >= 4:
        tag, length = struct.unpack_from("<HH", extra, 0)
        length += 4
        if length > len(extra):
            break
        if tag != _ZIP64_EXTRA_ID:
            result += extra[:length]
        extra = extra[length:]
    return bytes(result + extra)


def _stored_extra(entry: _Entry, extra: bytes) -> bytes:
    if entry.method != _STORE or (entry.compressed_size < _U32MAX and entry.uncompressed_size < _U32MAX):
        return extra
    return _extra_without_zip64(extra) + struct.pack(
        "<HHQQ", _ZIP64_EXTRA_ID, 16, entry.uncompressed_size, entry.compressed_size
    )


class _CountingWriter:
    def __init__(self, handle: BinaryIO) -> None:
        self._handle = handle
        self.count = 0

    def write(self, data: bytes) -> None:
        self._handle.write(data)
        self.count += len(data)


def reframe(
    src_path: str,
    dst_path: str,
    on_progress: Optional[Callable[[int, int], None]] = None,
) -> None:
    with open(src_path, "rb") as src, open(dst_path, "wb") as dst_handle:
        size = os.fstat(src.fileno()).st_size
        entries = _read_entries(src, size)
        out = _CountingWriter(dst_handle)
        written = []  # (entry, flags, offset, central_extra)

        total = len(entries)
        for index, entry in enumerate(entries):
            flags = entry.target_flags()
            local_extra = _stored_extra(entry, entry.local_extra)
            offset = out.count
            descriptor = bool(flags & _FLAG_DESCRIPTOR)

            if descriptor:
                crc, csize, usize = 0, 0, 0
            else:
                crc = entry.crc
                csize = min(entry.compressed_size, _U32MAX)
                usize = min(entry.uncompressed_size, _U32MAX)
            if len(entry.name) > _U16MAX or len(local_extra) > _U16MAX:
                raise ZipFramingError("entry name or extra field too long")
            out.write(
                struct.pack(
                    "<IHHHHHIIIHH",
                    _LOCAL_SIG, entry.reader_version, flags, entry.method, entry.mod_time, entry.mod_date,
                    crc, csize, usize, len(entry.name), len(local_extra),
                )
            )
            out.write(entry.name)
            out.write(local_extra)

            if not entry.is_dir:
                remaining = entry.compressed_size
                src.seek(entry.data_offset)
                while remaining:
                    chunk = src.read(min(_COPY_CHUNK, remaining))
                    if not chunk:
                        raise ZipFramingError("unexpected end of entry data")
                    out.write(chunk)
                    remaining -= len(chunk)
                if descriptor:
                    if entry.is_zip64:
                        out.write(struct.pack("<IIQQ", _DESCRIPTOR_SIG, entry.crc, entry.compressed_size, entry.uncompressed_size))
                    else:
                        out.write(struct.pack("<IIII", _DESCRIPTOR_SIG, entry.crc, entry.compressed_size, entry.uncompressed_size))
            elif entry.compressed_size:
                raise ZipFramingError("directory entry with data")

            written.append((entry, flags, offset, _extra_without_zip64(entry.central_extra)))
            if on_progress:
                on_progress(index + 1, total)

        start = out.count
        for entry, flags, offset, extra in written:
            if entry.is_zip64 or offset >= _U32MAX:
                csize_field = usize_field = _U32MAX
                extra = extra + struct.pack(
                    "<HHQQQ", _ZIP64_EXTRA_ID, 24, entry.uncompressed_size, entry.compressed_size, offset
                )
            else:
                csize_field, usize_field = entry.compressed_size, entry.uncompressed_size
            offset_field = _U32MAX if offset > _U32MAX else offset
            if len(extra) > _U16MAX:
                raise ZipFramingError("central extra field too long")
            out.write(
                struct.pack(
                    "<IHHHHHHIIIHHHHHII",
                    _CENTRAL_SIG, entry.creator_version, entry.reader_version, flags, entry.method,
                    entry.mod_time, entry.mod_date, entry.crc, csize_field, usize_field,
                    len(entry.name), len(extra), len(entry.comment), 0, 0, entry.external_attrs, offset_field,
                )
            )
            out.write(entry.name)
            out.write(extra)
            out.write(entry.comment)
        end = out.count

        records = len(written)
        dir_size = end - start
        dir_offset = start
        if records >= _U16MAX or dir_size >= _U32MAX or dir_offset >= _U32MAX:
            out.write(
                struct.pack(
                    "<IQHHIIQQQQ",
                    _ZIP64_EOCD_SIG, _ZIP64_EOCD_LEN - 12, _ZIP_VERSION_45, _ZIP_VERSION_45,
                    0, 0, records, records, dir_size, dir_offset,
                )
            )
            out.write(struct.pack("<IIQI", _ZIP64_LOCATOR_SIG, 0, end, 1))
            records, dir_size, dir_offset = _U16MAX, _U32MAX, _U32MAX
        out.write(struct.pack("<IHHHHIIH", _EOCD_SIG, 0, 0, records, records, dir_size, dir_offset, 0))


def ensure_streaming_framing(
    path: str, on_progress: Optional[Callable[[int, int], None]] = None
) -> bool:
    """Reframe ``path`` in place if needed. Returns True if it was rewritten."""
    if is_streaming_framed(path):
        return False
    target = Path(path)
    temp = target.with_name(target.name + ".reframe")
    try:
        reframe(path, str(temp), on_progress=on_progress)
        from .securefile import replace_with_retry

        replace_with_retry(temp, target)
    except BaseException:
        temp.unlink(missing_ok=True)
        raise
    return True
