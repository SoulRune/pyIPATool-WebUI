"""Apple framework files for SAP signing and kbsync (ipatool internal/sap/assets).

Read with range requests from the macOS 27.0.1 restore image on Apple's CDN
(zip, AEA, APFS, dyld cache, kernel collection): CoreFP, CoreFP.icxs,
commerce, adid, fairplayd, AppleMediaServices and the FairPlayIOKit kernel
extension. About 300 MB once, checked against pinned digests, cached.
"""
from __future__ import annotations

import hashlib
import logging
import shutil
import struct
import threading
import time
import zipfile
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional

import requests

from ..securefile import atomic_write_bytes
from .errors import SAPError

logger = logging.getLogger(__name__)

MACOS_VERSION = "27.0.1"
MACOS_BUILD = "26A434"
RESTORE_URL = (
    "https://updates.cdn-apple.com/2026FallFCS/59241290-5d51-4ca8-9df4-31624b9a4eac/"
    "UniversalMac_27.0.1_26A434_Restore.ipsw"
)
CACHE_VERSION = "apple-assets-macos-27-26A434-arm64-v2"
# Caches of earlier asset generations, removed once the new assets are in
# place: OS X 10.9 x86-64, then macOS 27 without the machine-verification
# images.
_OLD_CACHES = ("apple-assets-v2", "apple-storeagent-v1", "apple-assets-macos-27-26A434-arm64-v1")

FILE_SYSTEM_IMAGE = ("043-70867-640.dmg.aea", 11274289152, 14189330432)
SYSTEM_OS_IMAGE = ("043-70701-651.dmg.aea", 2415919104, 2879389696)
DYLD_CACHE_PATH = "/System/Library/dyld/dyld_shared_cache_arm64e"
APPLE_MEDIA_SERVICES_PATH = "/System/Library/PrivateFrameworks/AppleMediaServices.framework/Versions/A/AppleMediaServices"
APPLE_MEDIA_SERVICES_EXPORTS = ("_cp2g1b9ro", "_Mib5yocT", "_Fc3vhtJDvr", "_IPaI1oem5iL", "_jEHf8Xzsv8K")


@dataclass(frozen=True)
class FileSpec:
    name: str
    path: str
    size: int
    sha256: str


FRAMEWORK_FILES = (
    FileSpec("commerce", "/System/Library/PrivateFrameworks/CommerceKit.framework/Versions/A/Resources/commerce",
             8092640, "76de40a4a32f691947cb926ce3b128d2fc446f7cac9755f831c406cf5a316ac9"),
    FileSpec("CoreFP", "/System/Library/PrivateFrameworks/CoreFP.framework/Versions/A/CoreFP",
             94842464, "2c30fa2b5f695fd66c0360dce72f54757d03ddb7107549715c12cb359a003b46"),
    FileSpec("CoreFP.icxs", "/System/Library/PrivateFrameworks/CoreFP.framework/Versions/A/Resources/CoreFP.icxs",
             7365344, "cb8f55330ec567da3e692dab5f5388bed0312dd9093340477c5759078cc2aa7b"),
    FileSpec("adid", "/System/Library/PrivateFrameworks/CoreADI.framework/Versions/A/adid",
             9797952, "1fec225b6917206e3d9b00fe636c04878f82bfd06a87a4b6941711de60efab5b"),
    FileSpec("fairplayd", "/System/Library/PrivateFrameworks/CoreFP.framework/Versions/A/fairplayd",
             37689264, "28b4c7b2a5a0409c5020da55fc3984713a8e2b0eec8557076c8717f7166d003e"),
)
# Extracted by dyld.py, so the digest differs from ipatool's export (same code and data).
APPLE_MEDIA_SERVICES = FileSpec("AppleMediaServices", APPLE_MEDIA_SERVICES_PATH, 12089137,
                                "5672e9abc776655d18be65918a411838dbc1adce24bd53acee0399daa771ef74")
# Written by kernel.py, so the digest differs from ipatool's export (same segments).
FAIRPLAY_KEXT = FileSpec("FairPlayIOKit", "", 2130984,
                         "c78e73c327a4c49e210c04d724b8ff85a5240f59ee37faea5bc92cd975569f4a")
REQUIRED_FILES = FRAMEWORK_FILES + (APPLE_MEDIA_SERVICES, FAIRPLAY_KEXT)


@dataclass
class Bundle:
    apple_media_services: bytes
    commerce: bytes
    core_fp: bytes
    core_fp_icxs: bytes
    adid: bytes = b""
    fairplayd: bytes = b""
    fairplay_kext: bytes = b""
    # The Mach-O images are held with pointer authentication already removed
    # (macho.strip_image); the files on disk keep Apple's bytes.
    pac_stripped: bool = False


def prepare(bundle: Bundle) -> Bundle:
    """A copy of ``bundle`` whose images are stripped once for every
    emulator started from it."""
    from . import macho

    if bundle.pac_stripped:
        return bundle

    def strip(name: str, data: bytes) -> bytes:
        return macho.strip_image(name, data) if data else data

    return Bundle(
        apple_media_services=strip("AppleMediaServices", bundle.apple_media_services),
        commerce=strip("commerce", bundle.commerce),
        core_fp=strip("CoreFP", bundle.core_fp),
        core_fp_icxs=bundle.core_fp_icxs,
        adid=strip("adid", bundle.adid),
        fairplayd=strip("fairplayd", bundle.fairplayd),
        fairplay_kext=strip("FairPlayIOKit", bundle.fairplay_kext),
        pac_stripped=True,
    )


_load_lock = threading.Lock()
_memory_cache: Optional[Bundle] = None


def default_cache_dir() -> Path:
    return Path.home() / ".ipatool" / "sap" / CACHE_VERSION


def load(cache_dir: Optional[Path] = None, session: Optional[requests.Session] = None, verify=True) -> Bundle:
    """Return the verified bundle: memory cache -> disk cache -> Apple CDN.
    Its images are prepared once for the emulator (see ``prepare``)."""
    global _memory_cache
    with _load_lock:
        if _memory_cache is not None:
            return _memory_cache
        directory = Path(cache_dir) if cache_dir else default_cache_dir()
        files = _read_cache(directory)
        if files is None:
            # Files already fetched by an earlier version are reused (same
            # pinned digests); only the missing ones are extracted.
            have = _read_cache(directory, partial=True) or {}
            for name in _OLD_CACHES:
                for key, value in (_read_cache(directory.parent / name, partial=True) or {}).items():
                    have.setdefault(key, value)
            logger.info("downloading Apple SAP assets from the macOS %s restore image "
                        "(up to 300 MB, first sign-in only - this takes a few minutes)", MACOS_VERSION)
            files = download(session=session, verify=verify, have=have)
            _write_cache(directory, files)
            _remove_old_caches(directory.parent)
        _memory_cache = prepare(Bundle(
            apple_media_services=files["AppleMediaServices"],
            commerce=files["commerce"],
            core_fp=files["CoreFP"],
            core_fp_icxs=files["CoreFP.icxs"],
            adid=files["adid"],
            fairplayd=files["fairplayd"],
            fairplay_kext=files["FairPlayIOKit"],
        ))
        return _memory_cache


def _verify(spec: FileSpec, data: Optional[bytes]) -> None:
    if data is None:
        raise SAPError(f"Apple SAP asset {spec.name} was not found in the restore image")
    if len(data) != spec.size:
        raise SAPError(f"Apple SAP asset {spec.name} has size {len(data)}, expected {spec.size}")
    if hashlib.sha256(data).hexdigest() != spec.sha256:
        raise SAPError(f"Apple SAP asset {spec.name} failed integrity verification")


def _read_cache(directory: Path, partial: bool = False) -> Optional[Dict[str, bytes]]:
    """All verified files of the cache (None if one is missing), or with
    ``partial`` whichever of them are present and intact."""
    files: Dict[str, bytes] = {}
    for spec in REQUIRED_FILES:
        path = directory / spec.name
        try:
            if path.stat().st_size != spec.size:
                raise SAPError("size mismatch")
            data = path.read_bytes()
            _verify(spec, data)
        except (OSError, SAPError):
            if partial:
                continue
            return None
        files[spec.name] = data
    return files


def _write_cache(directory: Path, files: Dict[str, bytes]) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    for spec in REQUIRED_FILES:
        atomic_write_bytes(directory / spec.name, files[spec.name], private=True)


def _remove_old_caches(parent: Path) -> None:
    for name in _OLD_CACHES:
        old = parent / name
        if old.is_dir():
            shutil.rmtree(old, ignore_errors=True)
            logger.info("removed the cache of earlier Apple assets (%s)", old)


# ---------------------------------------------------------------------------
# Download: restore image (zip) -> AEA -> APFS -> files / dyld shared cache
# ---------------------------------------------------------------------------


def _kernel_extension(archive: zipfile.ZipFile) -> bytes:
    """kernel.go extractFairPlayKext: the deflated kernel collection (33 MB)
    is read whole, unpacked and the kext copied out of it."""
    from . import codecs, kernel

    try:
        info = archive.getinfo(kernel.KERNEL_CACHE_NAME)
    except KeyError as exc:
        raise SAPError(f"macOS {MACOS_VERSION} ({MACOS_BUILD}) restore image has no {kernel.KERNEL_CACHE_NAME}") from exc
    if (info.compress_type != zipfile.ZIP_DEFLATED or info.compress_size != kernel.KERNEL_CACHE_COMPRESSED_SIZE
            or info.file_size != kernel.KERNEL_CACHE_ARCHIVE_SIZE):
        raise SAPError(f"macOS {MACOS_VERSION} ({MACOS_BUILD}) restore member {kernel.KERNEL_CACHE_NAME} "
                       "doesn't match the pinned image")
    with archive.open(info) as member:
        data = member.read(kernel.KERNEL_CACHE_ARCHIVE_SIZE + 1)
    if len(data) != kernel.KERNEL_CACHE_ARCHIVE_SIZE:
        raise SAPError(f"pinned kernel collection has size {len(data)}, expected {kernel.KERNEL_CACHE_ARCHIVE_SIZE}")
    if hashlib.sha256(data).hexdigest() != kernel.KERNEL_CACHE_ARCHIVE_SHA256:
        raise SAPError(f"macOS {MACOS_VERSION} ({MACOS_BUILD}) restore member {kernel.KERNEL_CACHE_NAME} "
                       "doesn't match the pinned digest")
    payload = kernel.im4p_payload(data)
    del data
    if len(payload) != kernel.KERNEL_CACHE_PAYLOAD_SIZE:
        raise SAPError(f"pinned kernel payload has size {len(payload)}, expected {kernel.KERNEL_CACHE_PAYLOAD_SIZE}")
    image = codecs.lzfse_decompress(payload, kernel.KERNEL_CACHE_IMAGE_SIZE)
    del payload
    return kernel.extract_fairplay_kext(image)


def _zip_member(remote, archive: zipfile.ZipFile, name: str, archived_size: int):
    from .remote import SectionReader

    try:
        info = archive.getinfo(name)
    except KeyError as exc:
        raise SAPError(f"macOS {MACOS_VERSION} ({MACOS_BUILD}) restore image has no {name}") from exc
    if info.compress_type != zipfile.ZIP_STORED or info.compress_size != archived_size or info.file_size != archived_size:
        raise SAPError(f"macOS {MACOS_VERSION} ({MACOS_BUILD}) restore member {name} doesn't match the pinned image")
    local = remote.read_at(info.header_offset, 30)
    if local[:4] != b"PK\x03\x04":
        raise SAPError(f"restore member {name} has an invalid local header")
    name_length, extra_length = struct.unpack_from("<HH", local, 26)
    return SectionReader(remote, info.header_offset + 30 + name_length + extra_length, info.compress_size)


def download(session: Optional[requests.Session] = None, verify=True,
             have: Optional[Dict[str, bytes]] = None) -> Dict[str, bytes]:
    """Extract the required files from the restore image; files in
    ``have`` (already verified) are taken from there instead."""
    from . import aecrypto, codecs
    from .aea import AEAReader, AEAError
    from .apfs import APFS, APFSError
    from .dyld import DyldCache, DyldError
    from .remote import FileAdapter, RemoteError, RemoteFile

    session = session or requests.Session()
    started = time.monotonic()

    def fetch_key(url: str) -> bytes:
        response = session.get(url, timeout=60, verify=verify)
        if response.status_code != 200:
            raise SAPError(f"downloading Apple's archive key failed: HTTP {response.status_code}")
        return response.content

    logger.info("asset extraction backends: AES %s, LZFSE %s", aecrypto.aes_backend(),
                "native" if any(codecs._native()) else "pure Python (slow - 'pip install lzfse' speeds this up)")
    try:
        remote = RemoteFile(RESTORE_URL, session=session, verify=verify)
        archive = zipfile.ZipFile(FileAdapter(remote))
        found: Dict[str, bytes] = {name: data for name, data in (have or {}).items()
                                   if name in {spec.name for spec in REQUIRED_FILES}}

        missing = [spec for spec in FRAMEWORK_FILES if spec.name not in found]
        if missing:
            name, archived, expanded = FILE_SYSTEM_IMAGE
            image = AEAReader(_zip_member(remote, archive, name, archived), fetch_key)
            if image.size != expanded:
                raise SAPError(f"macOS filesystem image has size {image.size}, expected {expanded}")
            filesystem = APFS(image)
            for spec in missing:
                reader = filesystem.open(spec.path)
                data = reader.read_at(0, reader.size)
                _verify(spec, data)
                found[spec.name] = data
                logger.info("extracted %s (%.1f MB so far)", spec.name, remote.bytes_read / 1e6)

        if APPLE_MEDIA_SERVICES.name not in found:
            name, archived, expanded = SYSTEM_OS_IMAGE
            image = AEAReader(_zip_member(remote, archive, name, archived), fetch_key)
            if image.size != expanded:
                raise SAPError(f"SystemOS cryptex has size {image.size}, expected {expanded}")
            system_os = APFS(image)
            cache = DyldCache(lambda suffix: system_os.open(DYLD_CACHE_PATH + suffix))
            data = cache.extract(APPLE_MEDIA_SERVICES_PATH, APPLE_MEDIA_SERVICES_EXPORTS)
            _verify(APPLE_MEDIA_SERVICES, data)
            found[APPLE_MEDIA_SERVICES.name] = data
            logger.info("extracted %s (%.1f MB so far)", APPLE_MEDIA_SERVICES.name, remote.bytes_read / 1e6)

        if FAIRPLAY_KEXT.name not in found:
            data = _kernel_extension(archive)
            _verify(FAIRPLAY_KEXT, data)
            found[FAIRPLAY_KEXT.name] = data
            logger.info("extracted %s (%.1f MB so far)", FAIRPLAY_KEXT.name, remote.bytes_read / 1e6)
    except (RemoteError, AEAError, APFSError, DyldError, aecrypto.CryptoError, codecs.CodecError,
            zipfile.BadZipFile, KeyError, struct.error, zlib.error, ValueError) as exc:
        raise SAPError(f"reading Apple's macOS {MACOS_VERSION} restore image failed: {exc}") from exc
    logger.info("fetched Apple SAP assets in %.0fs (%.1f MB transferred, %d requests)",
                time.monotonic() - started, remote.bytes_read / 1e6, remote.requests)
    return found
