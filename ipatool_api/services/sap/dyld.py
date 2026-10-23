"""Pull one image out of an arm64e dyld shared cache (port of the parts of
ipatool internal/sap/assets/dyld.go that matter here).

ipatool exports the image as a standalone Mach-O (go-macho) and then writes
the cache's slide-info pointers into it. The emulator only needs the image's
segments at their cache addresses (pointers already "slid" to their
unslid targets), its sections (to find the instruction ranges) and a few
exported symbols - so that is what this module produces, as a small
self-describing blob (``PrelinkedImage``) instead of a rebuilt Mach-O.
"""
from __future__ import annotations

import json
import struct
from typing import Callable, Dict, List, Optional, Sequence, Tuple

_HEADER_SIZE = 568
_MAPPING_SIZE = 56
_IMAGE_INFO_SIZE = 32
_SUBCACHE_ENTRY_SIZE = 56
_MAX_MAPPINGS = 64
_MAX_IMAGES = 100_000
_MAX_SUBCACHES = 128
_LC_SEGMENT_64 = 0x19
_LC_SYMTAB = 0x2
_LC_DYLD_INFO = 0x22
_LC_DYLD_INFO_ONLY = 0x80000022
_LC_DYLD_EXPORTS_TRIE = 0x80000033
_MAX_CHAIN = 1 << 16

BLOB_MAGIC = b"PYIPATOOL-DYLD1\x00"


class DyldError(ValueError):
    pass


class _Mapping:
    __slots__ = ("member", "address", "size", "file_offset", "slide_offset", "slide_size")

    def __init__(self, member, address, size, file_offset, slide_offset, slide_size):
        self.member = member
        self.address = address
        self.size = size
        self.file_offset = file_offset
        self.slide_offset = slide_offset
        self.slide_size = slide_size


class _Member:
    def __init__(self, reader, header: bytes) -> None:
        self.reader = reader
        self.uuid = header[88:104]
        offset, count = struct.unpack_from("<II", header, 312)
        if count == 0 or count > _MAX_MAPPINGS or offset + count * _MAPPING_SIZE > reader.size:
            raise DyldError("shared-cache member has an invalid mapping table")
        table = reader.read_at(offset, count * _MAPPING_SIZE)
        self.mappings: List[_Mapping] = []
        for i in range(count):
            address, size, file_offset, slide_offset, slide_size = struct.unpack_from("<5Q", table, i * _MAPPING_SIZE)
            if size == 0 or file_offset + size > reader.size or (slide_size and slide_offset + slide_size > reader.size):
                raise DyldError("shared-cache member has an invalid mapping")
            self.mappings.append(_Mapping(self, address, size, file_offset, slide_offset, slide_size))


class DyldCache:
    def __init__(self, opener: Callable[[str], object]) -> None:
        """``opener(suffix)`` returns a read_at()/size reader for the cache
        file with that suffix ("" for the main file, ".01", ...)."""
        primary = opener("")
        header = primary.read_at(0, _HEADER_SIZE)
        if header[:16].rstrip(b"\x00") != b"dyld_v1  arm64e":
            raise DyldError(f"unsupported shared-cache format {header[:16]!r}")
        self.primary = _Member(primary, header)
        self.header = header
        self.members = [self.primary]
        sub_offset, sub_count = struct.unpack_from("<II", header, 392)
        if sub_count > _MAX_SUBCACHES:
            raise DyldError("shared cache has an invalid subcache table")
        entries = primary.read_at(sub_offset, sub_count * _SUBCACHE_ENTRY_SIZE) if sub_count else b""
        for i in range(sub_count):
            entry = entries[i * _SUBCACHE_ENTRY_SIZE:(i + 1) * _SUBCACHE_ENTRY_SIZE]
            suffix = entry[24:56].rstrip(b"\x00").decode("ascii", "replace")
            if not suffix or "/" in suffix or "\\" in suffix:
                raise DyldError("shared cache has an invalid subcache suffix")
            reader = opener(suffix)
            member = _Member(reader, reader.read_at(0, _HEADER_SIZE))
            if member.uuid != entry[:16]:
                raise DyldError(f"shared-cache member {suffix} has an unexpected UUID")
            self.members.append(member)
        self.value_add: Optional[int] = None
        for member in self.members:
            for mapping in member.mappings:
                if not mapping.slide_size:
                    continue
                version, page_size, _count, _pad, value_add = struct.unpack(
                    "<IIIIQ", mapping.member.reader.read_at(mapping.slide_offset, 24))
                if version != 5:
                    raise DyldError(f"unsupported shared-cache slide version {version}")
                if self.value_add is None:
                    self.value_add = value_add
                elif self.value_add != value_add:
                    raise DyldError("shared-cache members use incompatible slide information")
        if self.value_add is None:
            raise DyldError("shared cache has no slide information")

    # -- addressing ----------------------------------------------------------

    def mapping_for(self, address: int) -> _Mapping:
        for member in self.members:
            for mapping in member.mappings:
                if mapping.address <= address < mapping.address + mapping.size:
                    return mapping
        raise DyldError(f"address {address:#x} is outside the shared cache")

    def read_address(self, address: int, length: int) -> bytes:
        out = bytearray()
        while len(out) < length:
            mapping = self.mapping_for(address)
            take = min(length - len(out), mapping.address + mapping.size - address)
            out += mapping.member.reader.read_at(mapping.file_offset + address - mapping.address, take)
            address += take
        return bytes(out)

    def _decode(self, pointer: int) -> int:
        target = pointer & ((1 << 34) - 1)
        if pointer >> 63 == 0:
            target |= ((pointer >> 34) & 0xFF) << 56
        return self.value_add + target

    def rebases(self, mapping: _Mapping, start_page: int, end_page: int) -> List[Tuple[int, int]]:
        reader = mapping.member.reader
        version, page_size, count, _pad, _value_add = struct.unpack("<IIIIQ", reader.read_at(mapping.slide_offset, 24))
        starts = struct.unpack(f"<{count}H", reader.read_at(mapping.slide_offset + 24, count * 2)) if count else ()
        end_page = min(end_page, len(starts)) if end_page else len(starts)
        result = []
        for page in range(start_page, end_page):
            start = starts[page]
            if start == 0xFFFF:
                continue
            page_data = reader.read_at(mapping.file_offset + page * page_size, page_size)
            page_address = mapping.address + page * page_size
            offset = start
            for _ in range(_MAX_CHAIN):
                if offset + 8 > page_size:
                    raise DyldError("shared-cache slide chain leaves its page")
                pointer = struct.unpack_from("<Q", page_data, offset)[0]
                result.append((page_address + offset, self._decode(pointer)))
                step = (pointer >> 52) & 0x7FF
                if not step:
                    break
                offset += step * 8
            else:
                raise DyldError("shared-cache slide chain is too long")
        return result

    # -- images --------------------------------------------------------------

    def image_address(self, path: str) -> int:
        offset, count = struct.unpack_from("<II", self.header, 448)
        if count == 0 or count > _MAX_IMAGES:
            raise DyldError("shared cache has an invalid image table")
        table = self.primary.reader.read_at(offset, count * _IMAGE_INFO_SIZE)
        wanted = path.encode()
        for i in range(count):
            address = struct.unpack_from("<Q", table, i * _IMAGE_INFO_SIZE)[0]
            path_offset = struct.unpack_from("<I", table, i * _IMAGE_INFO_SIZE + 24)[0]
            name = self.primary.reader.read_at(path_offset, min(len(wanted) + 1, self.primary.reader.size - path_offset))
            if name == wanted + b"\x00":
                return address
        raise DyldError(f"{path} was not found in the shared cache")

    def extract(self, path: str, export_names: Sequence[str]) -> bytes:
        """The image as a PrelinkedImage blob (see module doc)."""
        base = self.image_address(path)
        header = self.read_address(base, 32)
        magic, _cpu, _subtype, _filetype, ncmds, sizeofcmds = struct.unpack_from("<IiiIII", header)
        if magic != 0xFEEDFACF:
            raise DyldError("image has an invalid Mach-O magic")
        commands = self.read_address(base + 32, sizeofcmds)
        segments, sections = [], []
        exports_trie = None
        symtab = None
        linkedit = None
        offset = 0
        for _ in range(ncmds):
            cmd, size = struct.unpack_from("<II", commands, offset)
            if cmd == _LC_SEGMENT_64:
                name = commands[offset + 8:offset + 24].rstrip(b"\x00").decode()
                vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<4Q", commands, offset + 24)
                nsects = struct.unpack_from("<I", commands, offset + 64)[0]
                segments.append({"name": name, "address": vmaddr, "size": vmsize, "fileoff": fileoff, "filesize": filesize})
                if name == "__LINKEDIT":
                    linkedit = (vmaddr, fileoff)
                for s in range(nsects):
                    at = offset + 72 + s * 80
                    sectname = commands[at:at + 16].rstrip(b"\x00").decode()
                    segname = commands[at + 16:at + 32].rstrip(b"\x00").decode()
                    addr, sect_size = struct.unpack_from("<QQ", commands, at + 32)
                    flags = struct.unpack_from("<I", commands, at + 64)[0]
                    sections.append({"segment": segname, "name": sectname, "address": addr, "size": sect_size, "flags": flags})
            elif cmd == _LC_SYMTAB:
                symtab = struct.unpack_from("<4I", commands, offset + 8)
            elif cmd == _LC_DYLD_EXPORTS_TRIE:
                exports_trie = struct.unpack_from("<II", commands, offset + 8)
            elif cmd in (_LC_DYLD_INFO, _LC_DYLD_INFO_ONLY) and exports_trie is None:
                export_off, export_size = struct.unpack_from("<II", commands, offset + 40)
                if export_size:
                    exports_trie = (export_off, export_size)
            offset += size

        exports: Dict[str, int] = {}
        if exports_trie and linkedit:
            trie = self.read_address(linkedit[0] + exports_trie[0] - linkedit[1], exports_trie[1])
            from .macho import parse_export_trie
            for name, image_offset in parse_export_trie(trie).items():
                if name in export_names:
                    exports[name] = base + image_offset
        missing = [name for name in export_names if name not in exports]
        if missing and symtab and linkedit:
            # Not exported: private-extern symbols, as go-macho's
            # FindSymbolAddress also finds them, from the image's symbol table
            # (nlist entries and string pool live in the cache's LINKEDIT).
            symoff, nsyms, stroff, strsize = symtab
            entries = self.read_address(linkedit[0] + symoff - linkedit[1], nsyms * 16)
            wanted = {name.encode() + b"\x00": name for name in missing}
            longest = max(len(key) for key in wanted)
            for index in range(nsyms):
                strx, n_type, _sect, _desc, value = struct.unpack_from("<IBBHQ", entries, index * 16)
                if n_type & 0x0E != 0x0E or strx >= strsize:  # defined in a section
                    continue
                text = self.read_address(linkedit[0] + stroff + strx - linkedit[1], min(longest, strsize - strx))
                name = wanted.get(text[:text.find(b"\x00") + 1]) if b"\x00" in text else None
                if name and name not in exports:
                    exports[name] = value
                    if all(n in exports for n in export_names):
                        break
            missing = [name for name in export_names if name not in exports]
        if missing:
            raise DyldError(f"{path} doesn't export {', '.join(missing)}")

        data = bytearray()
        described = []
        for segment in segments:
            if segment["name"] == "__LINKEDIT" or segment["filesize"] == 0:
                described.append(dict(segment, data_offset=0, data_size=0))
                continue
            # Like the go-macho export: the whole vmsize, as the cache holds it.
            content = bytearray(self.read_address(segment["address"], segment["size"]))
            mapping = self.mapping_for(segment["address"])
            if mapping.slide_size:
                page_size = struct.unpack("<I", mapping.member.reader.read_at(mapping.slide_offset + 4, 4))[0]
                start = (segment["address"] - mapping.address) // page_size
                end = (segment["address"] + segment["size"] - mapping.address + page_size) // page_size
                for address, target in self.rebases(mapping, start, end):
                    inside = address - segment["address"]
                    if 0 <= inside <= len(content) - 8:
                        struct.pack_into("<Q", content, inside, target)
            described.append(dict(segment, data_offset=len(data), data_size=len(content)))
            data += content
        metadata = json.dumps({"path": path, "base": base, "segments": described, "sections": sections,
                               "exports": exports}, sort_keys=True).encode()
        return BLOB_MAGIC + struct.pack("<I", len(metadata)) + metadata + bytes(data)
