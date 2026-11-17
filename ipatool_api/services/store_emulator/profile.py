"""The precomputed profile the Store runtime starts from.

ipatool generates it from the pinned macOS 27.0.1 images
(``internal/store/profilegen``) and compiles it into the program
(``internal/store/profile``): metadata of the Objective-C classes, methods,
call stubs, Swift types and constants AppleMediaServices uses, the initialized
pages of guest memory it depends on, and the AMSAccountAuthenticationPlugin
image. This project ships the same three parts, xz-compressed, in
``store_profile.bin`` (see tools/build_store_profile.py); their SHA-256
digests are those ipatool pins.
"""
from __future__ import annotations

import base64
import hashlib
import json
import lzma
import struct
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

PROFILE_FILE = Path(__file__).with_name("store_profile.bin")
MAGIC = b"PYIPATOOL-AMSPROFILE1\n"
FRAMEWORK_UUID = "5DFC37A5-4689-3F9D-9655-D4774E1D8D08"
PLUGIN_UUID = "B8C07F94-4868-3CD7-A59A-F01E8C24C1B7"
# ipatool's pinned digests of the decoded parts (profile/data_generated.go).
PARTS = {
    "metadata": (4807917, "5e92717743272aa84343bd25f6bab6401155f88ade51b704ec535d3e6b5bd421"),
    "pages": (20893696, "4fd8cf193ca6e71d52a2d6e68d9ca76907332ff33dade332351c97efe5f0caed"),
    "plugin": (138088, "e33fff05a6e6593dd91e33fd103b5d3068b62a787c680df33b859f19b3acc4ea"),
}
# metadata.go: the pinned dyld lazy-import thunk, verified against its
# resolved import slot (0x1eaaee178); a host diagnostics preference.
_EXTRA_CALLS = ((0x1A2D0FB94, "CRIsAutoSubmitEnabled", ""),)


class ProfileError(Exception):
    pass


@dataclass
class ClassInfo:
    name: str
    address: int
    meta_address: int
    super: str
    size: int
    ivars: Dict[str, int]


class Metadata:
    """metadata.go prepareMetadata: the profile as lookup tables."""

    def __init__(self, raw: bytes, code_ranges: List[Tuple[int, int]], ivar_offsets: List[Tuple[int, int]],
                 media_mappings: List[Tuple[int, int]]) -> None:
        profile = json.loads(raw)
        if profile.get("UUID") != FRAMEWORK_UUID:
            raise ProfileError("unsupported Store profile UUID")
        if profile.get("PluginUUID") != PLUGIN_UUID:
            raise ProfileError("unsupported authentication plugin UUID")
        self.bridges: Dict[str, int] = profile.get("Bridges") or {}
        self.objc_metadata: Dict[str, int] = profile.get("ObjCMetadata") or {}
        self.swift_singletons: Dict[str, int] = profile.get("SwiftSingletons") or {}
        self.swift_foreign: Dict[str, int] = profile.get("SwiftForeign") or {}
        self.swift_dictionaries: Dict[str, Dict[str, int]] = profile.get("SwiftDictionaries") or {}
        self.swift_globals: Dict[str, int] = profile.get("SwiftGlobals") or {}
        self.swift_types: Dict[str, int] = profile.get("SwiftTypes") or {}
        self.swift_witnesses: Dict[str, int] = profile.get("SwiftWitnesses") or {}
        self.swift_accessors: Dict[str, int] = profile.get("SwiftAccessors") or {}
        self.symbols: Dict[str, int] = profile.get("Symbols") or {}
        self.features: Dict[str, bool] = profile.get("Features") or {}
        self.metadata_patches: List[Tuple[int, bytes]] = [
            (patch["Address"], base64.b64decode(patch.get("Data") or "")) for patch in profile.get("MetadataPatches") or []
        ]
        pages = profile.get("Pages") or []
        self.page_offsets: List[Tuple[int, int]] = [(page["Address"], page["Offset"]) for page in pages]
        self.page_addresses: List[int] = [page["Address"] for page in pages]
        self.code_ranges = list(code_ranges)
        self.ivar_offsets = list(ivar_offsets)
        self.media_mappings = list(media_mappings)

        self.classes: Dict[str, ClassInfo] = {}
        self.class_names: Dict[int, str] = {}
        self.methods: Dict[str, int] = {}
        for item in profile.get("Classes") or []:
            info = ClassInfo(item["Name"], item.get("Address") or 0, item.get("MetaAddress") or 0,
                             item.get("Super") or "", item.get("Size") or 0, item.get("Ivars") or {})
            self.classes[info.name] = info
            self.class_names[info.address] = info.name
            if info.meta_address:
                self.class_names[info.meta_address] = info.name
            for method in item.get("Methods") or []:
                key = ("+" if method.get("ClassMethod") else "-") + "[" + info.name + " " + method["Selector"] + "]"
                self.methods[key] = method.get("Address") or 0

        # address -> (symbol, selector)
        self.calls: Dict[int, Tuple[str, str]] = {}
        self.selectors: Dict[int, str] = {}
        self.selector_addresses: Dict[str, int] = {}
        for call in list(profile.get("Calls") or []) + [
                {"Address": a, "Symbol": s, "Selector": sel} for a, s, sel in _EXTRA_CALLS]:
            selector = call.get("Selector") or ""
            self.calls[call["Address"]] = (call.get("Symbol") or "", selector)
            if selector:
                self.selectors[call.get("SelectorAddress") or 0] = selector
                self.selector_addresses[selector] = call.get("SelectorAddress") or 0

        # Template objects: strings and constants at their image addresses.
        self._objects: Dict[int, Tuple[str, Any]] = {}
        for key, value in (profile.get("Strings") or {}).items():
            self._objects[int(key)] = ("NSString", value)
        for key, value in (profile.get("Constants") or {}).items():
            kind = value.get("Kind") or ""
            data: Any = None
            if kind == "NSString":
                data = value.get("Text") or ""
            elif kind == "NSNumber":
                data = bool(value.get("Boolean")) if value.get("IsBoolean") else int(value.get("Number") or 0)
            elif kind == "NSDictionary":
                data = dict(value.get("Entries") or {})
            elif kind in ("NSArray", "NSSet"):
                data = list(value.get("Items") or [])
            self._objects[int(key)] = (kind, data)

    def new_objects(self) -> Dict[int, Any]:
        from .runtime import Obj

        objects = {}
        for address, (kind, value) in self._objects.items():
            if isinstance(value, dict):
                value = dict(value)
            elif isinstance(value, list):
                value = list(value)
            objects[address] = Obj(kind, value)
        return objects


class StoreProfile:
    def __init__(self, metadata: Metadata, pages: bytes, plugin: bytes) -> None:
        from ..sap import macho

        self.metadata = metadata
        self.pages = pages
        image = macho.Image("AMSAccountAuthenticationPlugin", plugin)
        self.plugin_image = [
            (s.address, s.size, bytes(image.data[s.file_offset:s.file_offset + s.file_size]))
            for s in image.segments if s.name != "__PAGEZERO" and s.size
        ]


_lock = threading.Lock()
_loaded: Optional[StoreProfile] = None


def load(path: Optional[Path] = None) -> StoreProfile:
    """The verified profile, decoded once per process."""
    global _loaded
    with _lock:
        if _loaded is not None and path is None:
            return _loaded
        source = Path(path) if path else PROFILE_FILE
        try:
            blob = source.read_bytes()
        except OSError as exc:
            raise ProfileError(f"the Store runtime profile is missing ({source.name})") from exc
        parts, extras = _decode(blob)
        metadata = Metadata(parts["metadata"], [tuple(r) for r in extras.get("code_ranges", [])],
                            [tuple(r) for r in extras.get("ivar_offsets", [])],
                            [tuple(r) for r in extras.get("media_mappings", [])])
        pages = parts["pages"]
        if len(metadata.page_offsets) == 0 or len(metadata.page_offsets) != len(pages) // 4096 or len(pages) % 4096:
            raise ProfileError("incomplete Store profile")
        for index, (address, offset) in enumerate(metadata.page_offsets):
            if address % 4096 or offset != index * 4096:
                raise ProfileError("invalid Store page index")
        profile = StoreProfile(metadata, pages, parts["plugin"])
        if path is None:
            _loaded = profile
        return profile


def _decode(blob: bytes) -> Tuple[Dict[str, bytes], Dict[str, Any]]:
    if not blob.startswith(MAGIC):
        raise ProfileError("the Store runtime profile has an unknown format")
    length = struct.unpack_from("<I", blob, len(MAGIC))[0]
    start = len(MAGIC) + 4
    header = json.loads(blob[start:start + length])
    position = start + length
    parts: Dict[str, bytes] = {}
    for entry in header["parts"]:
        name = entry["name"]
        compressed = blob[position:position + entry["length"]]
        position += entry["length"]
        expected = PARTS.get(name)
        if expected is None:
            continue
        size, digest = expected
        try:
            data = lzma.decompress(compressed, format=lzma.FORMAT_XZ, memlimit=1 << 30)
        except lzma.LZMAError as exc:
            raise ProfileError(f"the Store runtime profile is damaged ({name})") from exc
        if len(data) != size or hashlib.sha256(data).hexdigest() != digest:
            raise ProfileError(f"the Store runtime profile failed integrity verification ({name})")
        parts[name] = data
    missing = set(PARTS) - set(parts)
    if missing:
        raise ProfileError(f"the Store runtime profile is incomplete ({', '.join(sorted(missing))})")
    return parts, header.get("extras") or {}


def build(metadata: bytes, pages: bytes, plugin: bytes, code_ranges: List[Tuple[int, int]],
          ivar_offsets: List[Tuple[int, int]], media_mappings: List[Tuple[int, int]]) -> bytes:
    """The ``store_profile.bin`` container (used by tools/build_store_profile.py)."""
    entries = []
    payload = bytearray()
    for name, data in (("metadata", metadata), ("pages", pages), ("plugin", plugin)):
        size, digest = PARTS[name]
        if len(data) != size or hashlib.sha256(data).hexdigest() != digest:
            raise ProfileError(f"{name} doesn't match ipatool's pinned profile")
        compressed = lzma.compress(data, format=lzma.FORMAT_XZ, preset=9 | lzma.PRESET_EXTREME)
        entries.append({"name": name, "length": len(compressed)})
        payload += compressed
    header = json.dumps({"parts": entries, "extras": {"code_ranges": [list(r) for r in code_ranges],
                                                       "ivar_offsets": [list(r) for r in ivar_offsets],
                                                       "media_mappings": [list(r) for r in media_mappings]}},
                        separators=(",", ":")).encode("ascii")
    return MAGIC + struct.pack("<I", len(header)) + header + bytes(payload)
