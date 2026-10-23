"""Read the app's Info.plist from an IPA on Apple's CDN with a few range
requests (for each version's minimum OS)."""
from __future__ import annotations

import plistlib
import struct
import zlib
from typing import Callable, Dict, Optional, Tuple

# fetch(start, end_inclusive) -> bytes; start < 0 means "the last -start bytes".
Fetch = Callable[[int, int], bytes]

_TAIL = 64 * 1024            # EOCD + comment (max 64 KiB) + ZIP64 locator
_MAX_DIRECTORY = 48 * 1024 * 1024   # don't pull more than this just for a file list
_MAX_PLIST = 4 * 1024 * 1024
_LOCAL_SLACK = 1024          # local header extra field can differ from the directory's

_OS_NAMES = {"iPhoneOS": "iOS", "AppleTVOS": "tvOS", "WatchOS": "watchOS", "MacOSX": "macOS", "XROS": "visionOS"}


class RemoteZipError(Exception):
    pass


def _directory_location(tail: bytes, fetch: Fetch) -> Tuple[int, int]:
    """(offset, size) of the central directory, from the archive's tail."""
    eocd = tail.rfind(b"PK\x05\x06")
    if eocd < 0 or len(tail) - eocd < 22:
        raise RemoteZipError("not a zip archive (no end-of-directory record)")
    (_, _, _, _, _, cd_size, cd_offset, _) = struct.unpack("<IHHHHIIH", tail[eocd:eocd + 22])
    if cd_size != 0xFFFFFFFF and cd_offset != 0xFFFFFFFF:
        return cd_offset, cd_size
    # ZIP64: the locator sits right before the classic record.
    locator = tail.rfind(b"PK\x06\x07", 0, eocd)
    if locator < 0:
        raise RemoteZipError("zip64 locator missing")
    (_, _, record_offset, _) = struct.unpack("<IIQI", tail[locator:locator + 20])
    record = fetch(record_offset, record_offset + 56 - 1)
    if record[:4] != b"PK\x06\x06" or len(record) < 56:
        raise RemoteZipError("bad zip64 end-of-directory record")
    cd_size, cd_offset = struct.unpack("<QQ", record[40:56])
    return cd_offset, cd_size


def _zip64_values(extra: bytes, wanted: Dict[str, int]) -> Dict[str, int]:
    """Fill the 0xFFFFFFFF fields from the zip64 extra block (in spec order)."""
    pos = 0
    while pos + 4 <= len(extra):
        tag, size = struct.unpack("<HH", extra[pos:pos + 4])
        body = extra[pos + 4:pos + 4 + size]
        if tag == 0x0001:
            at = 0
            for key in ("usize", "csize", "offset"):
                if wanted.get(key) == 0xFFFFFFFF and at + 8 <= len(body):
                    wanted[key] = struct.unpack("<Q", body[at:at + 8])[0]
                    at += 8
            break
        pos += 4 + size
    return wanted


def _find_info_plist(directory: bytes) -> Optional[Dict[str, int]]:
    pos = 0
    while pos + 46 <= len(directory) and directory[pos:pos + 4] == b"PK\x01\x02":
        (method, csize, usize, name_len, extra_len, comment_len, offset) = (
            struct.unpack("<H", directory[pos + 10:pos + 12])[0],
            *struct.unpack("<II", directory[pos + 20:pos + 28]),
            *struct.unpack("<HHH", directory[pos + 28:pos + 34]),
            struct.unpack("<I", directory[pos + 42:pos + 46])[0],
        )
        name = directory[pos + 46:pos + 46 + name_len].decode("utf-8", "replace")
        extra = directory[pos + 46 + name_len:pos + 46 + name_len + extra_len]
        # Only the main app: Payload/X.app/Info.plist (not extensions/watch apps).
        if name.startswith("Payload/") and name.endswith(".app/Info.plist") and name.count("/") == 2:
            entry = _zip64_values(extra, {"csize": csize, "usize": usize, "offset": offset})
            entry.update(method=method, name_len=name_len)
            return entry
        pos += 46 + name_len + extra_len + comment_len
    return None


def read_info_plist(fetch: Fetch) -> Dict:
    tail = fetch(-_TAIL, -1)
    cd_offset, cd_size = _directory_location(tail, fetch)
    if cd_size > _MAX_DIRECTORY:
        raise RemoteZipError(f"file list too large ({cd_size} bytes)")
    directory = fetch(cd_offset, cd_offset + cd_size - 1)
    entry = _find_info_plist(directory)
    if entry is None:
        raise RemoteZipError("no Payload/*.app/Info.plist in the archive")
    if entry["csize"] > _MAX_PLIST:
        raise RemoteZipError("Info.plist unexpectedly large")
    start = entry["offset"]
    blob = fetch(start, start + 30 + entry["name_len"] + _LOCAL_SLACK + entry["csize"] - 1)
    if blob[:4] != b"PK\x03\x04":
        raise RemoteZipError("bad local file header")
    name_len, extra_len = struct.unpack("<HH", blob[26:30])
    data_start = 30 + name_len + extra_len
    data = blob[data_start:data_start + entry["csize"]]
    if len(data) < entry["csize"]:
        more = fetch(start + len(blob), start + data_start + entry["csize"] - 1)
        data = (data + more)[:entry["csize"]]
    if entry["method"] == 0:
        raw = data
    elif entry["method"] == 8:
        raw = zlib.decompressobj(-15).decompress(data)
    else:
        raise RemoteZipError(f"unsupported compression method {entry['method']}")
    info = plistlib.loads(raw)
    if not isinstance(info, dict):
        raise RemoteZipError("Info.plist is not a dictionary")
    return info


def minimum_os(info: Dict) -> Tuple[str, str]:
    """(OS name, minimum version) from an app's Info.plist, e.g. ("iOS", "15.0")."""
    platforms = info.get("CFBundleSupportedPlatforms") or []
    platform = next((p for p in platforms if p in _OS_NAMES), "iPhoneOS" if not platforms else str(platforms[0]))
    if platform == "MacOSX":
        version = info.get("LSMinimumSystemVersion") or info.get("MinimumOSVersion") or ""
    else:
        version = info.get("MinimumOSVersion") or ""
    return _OS_NAMES.get(platform, platform), str(version)
