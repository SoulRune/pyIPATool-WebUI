"""Minimal arm64 Mach-O image loader.

Port of ipatool internal/sap/machimage (since 0259df3, arm64) together with
the parts of github.com/blacktop/go-macho it relies on: arm64e slices of
universal binaries, segments and sections, symbol table and export tries,
classic rebase/bind opcode streams and chained fixups. Pointer
authentication instructions are rewritten to their plain forms, because the
emulator has no keys to authenticate with.

Images taken from the dyld shared cache come as a ``PrelinkedImage`` blob
(see dyld.py): they stay at their cache addresses, and pointers into other
cache images are redirected to the emulator's services.
"""
from __future__ import annotations

import json
import struct
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Tuple

from .errors import SAPError

PAGE_SIZE = 0x1000
MAX_IMAGE_SPAN = 1 << 30
POINTER_SIZE = 8
U64 = (1 << 64) - 1

CPU_TYPE_ARM64 = 0x0100000C
CPU_SUBTYPE_MASK = 0x00FFFFFF
CPU_SUBTYPE_ARM64E = 2
MH_MAGIC_64 = 0xFEEDFACF
FAT_MAGIC = 0xCAFEBABE
FAT_MAGIC_64 = 0xCAFEBABF

LC_SEGMENT_64 = 0x19
LC_SYMTAB = 0x2
LC_DYLD_INFO = 0x22
LC_DYLD_INFO_ONLY = 0x80000022
LC_DYLD_EXPORTS_TRIE = 0x80000033
LC_DYLD_CHAINED_FIXUPS = 0x80000034

S_ATTR_PURE_INSTRUCTIONS = 0x80000000
S_ATTR_SOME_INSTRUCTIONS = 0x00000400

REBASE_TYPE_POINTER = 1
BIND_TYPE_POINTER = 1

BIND_OPCODE_MASK = 0xF0
BIND_IMMEDIATE_MASK = 0x0F
BIND_OPCODE_DONE = 0x00
BIND_OPCODE_SET_DYLIB_ORDINAL_IMM = 0x10
BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB = 0x20
BIND_OPCODE_SET_DYLIB_SPECIAL_IMM = 0x30
BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM = 0x40
BIND_OPCODE_SET_TYPE_IMM = 0x50
BIND_OPCODE_SET_ADDEND_SLEB = 0x60
BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB = 0x70
BIND_OPCODE_ADD_ADDR_ULEB = 0x80
BIND_OPCODE_DO_BIND = 0x90
BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB = 0xA0
BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED = 0xB0
BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB = 0xC0

REBASE_OPCODE_MASK = 0xF0
REBASE_IMMEDIATE_MASK = 0x0F
REBASE_OPCODE_DONE = 0x00
REBASE_OPCODE_SET_TYPE_IMM = 0x10
REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB = 0x20
REBASE_OPCODE_ADD_ADDR_ULEB = 0x30
REBASE_OPCODE_ADD_ADDR_IMM_SCALED = 0x40
REBASE_OPCODE_DO_REBASE_IMM_TIMES = 0x50
REBASE_OPCODE_DO_REBASE_ULEB_TIMES = 0x60
REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB = 0x70
REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB = 0x80

# Chained fixup pointer formats (mach-o/fixup-chains.h)
PTR_ARM64E = 1
PTR_64 = 2
PTR_64_OFFSET = 6
PTR_ARM64E_USERLAND = 9
PTR_ARM64E_USERLAND24 = 12
_ARM64E_FORMATS = (PTR_ARM64E, PTR_ARM64E_USERLAND, PTR_ARM64E_USERLAND24)

KIND_BIND, KIND_WEAK, KIND_LAZY = 0, 1, 2


@dataclass
class Segment:
    name: str
    address: int
    size: int
    file_offset: int
    file_size: int


@dataclass
class Section:
    segment: str
    name: str
    address: int
    size: int
    offset: int
    flags: int


@dataclass
class Rebase:
    segment: str
    offset: int
    type: int
    value: int


@dataclass
class Bind:
    name: str
    segment: str
    seg_offset: int
    type: int
    addend: int
    kind: int


class _Stream:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.pos = 0

    def eof(self) -> bool:
        return self.pos >= len(self.data)

    def byte(self) -> int:
        value = self.data[self.pos]
        self.pos += 1
        return value

    def uleb(self) -> int:
        result = 0
        shift = 0
        while True:
            byte = self.byte()
            result |= (byte & 0x7F) << shift
            if byte < 0x80:
                return result & U64
            shift += 7
            if shift > 63:
                raise SAPError("ULEB128 value overflows")

    def sleb(self) -> int:
        result = 0
        shift = 0
        while True:
            byte = self.byte()
            result |= (byte & 0x7F) << shift
            shift += 7
            if byte < 0x80:
                if byte & 0x40:
                    result -= 1 << shift
                return result
            if shift > 63:
                raise SAPError("SLEB128 value overflows")

    def cstring(self) -> str:
        end = self.data.index(b"\0", self.pos)
        text = self.data[self.pos : end].decode("utf-8", "replace")
        self.pos = end + 1
        return text


def parse_export_trie(trie: bytes) -> Dict[str, int]:
    """{symbol: image offset} from an export trie (re-exports skipped)."""
    result: Dict[str, int] = {}
    stack = [(0, "")]
    seen = set()
    while stack:
        node, prefix = stack.pop()
        if node in seen or node >= len(trie):
            continue
        seen.add(node)
        r = _Stream(trie)
        r.pos = node
        terminal = r.uleb()
        children_at = r.pos + terminal
        if terminal:
            flags = r.uleb()
            if not flags & 0x08:  # not a re-export
                result[prefix] = r.uleb()
        r.pos = children_at
        count = r.byte()
        for _ in range(count):
            edge = r.cstring()
            child = r.uleb()
            stack.append((child, prefix + edge))
    return result


def _arm64e_slice(data: bytes) -> bytes:
    if len(data) < 8:
        raise SAPError("file too small for Mach-O")
    magic = struct.unpack(">I", data[:4])[0]
    if magic not in (FAT_MAGIC, FAT_MAGIC_64):
        return bytes(data)
    count = struct.unpack(">I", data[4:8])[0]
    entry_size = 20 if magic == FAT_MAGIC else 32
    for index in range(count):
        base = 8 + index * entry_size
        if magic == FAT_MAGIC:
            cpu, sub, offset, size, _align = struct.unpack(">iiIII", data[base : base + 20])
        else:
            cpu, sub, offset, size, _align, _res = struct.unpack(">iiQQII", data[base : base + 32])
        if cpu == CPU_TYPE_ARM64 and sub & CPU_SUBTYPE_MASK == CPU_SUBTYPE_ARM64E:
            if offset + size > len(data):
                raise SAPError("arm64e slice exceeds input size")
            return bytes(data[offset : offset + size])
    raise SAPError("universal binary has no arm64e slice")


def _strip_pointer_authentication(data: bytearray, sections: List[Tuple[int, int]]) -> None:
    """machimage removePointerAuthentication: braa/blraa/retaa and friends
    become br/blr/ret, PAC/AUT/XPAC instructions become NOPs."""
    nop = 0xD503201F
    hint_nops = {0xD503211F, 0xD503215F, 0xD503219F, 0xD50321DF, 0xD503233F, 0xD503237F, 0xD50323BF,
                 0xD50323FF, 0xD50320FF}
    pac_data = {0xDAC10000, 0xDAC10400, 0xDAC10800, 0xDAC10C00, 0xDAC11000, 0xDAC11400, 0xDAC11800, 0xDAC11C00}
    pac_zero = {0xDAC123E0, 0xDAC127E0, 0xDAC12BE0, 0xDAC12FE0, 0xDAC133E0, 0xDAC137E0, 0xDAC13BE0,
                0xDAC13FE0, 0xDAC143E0, 0xDAC147E0}
    for start, end in sections:
        if end > len(data):
            raise SAPError("instruction section exceeds the image")
        words = list(struct.unpack_from(f"<{(end - start) // 4}I", data, start))
        changed = False
        for index, instruction in enumerate(words):
            replacement = 0
            top = instruction & 0xFFFFFC00
            if top in (0xD71F0800, 0xD71F0C00, 0xD61F0800, 0xD61F0C00):
                replacement = 0xD61F0000 | (instruction & 0x3E0)  # br xN
            elif top in (0xD73F0800, 0xD73F0C00, 0xD63F0800, 0xD63F0C00):
                replacement = 0xD63F0000 | (instruction & 0x3E0)  # blr xN
            elif top in pac_data:
                replacement = nop
            elif instruction in (0xD65F0BFF, 0xD65F0FFF):
                replacement = 0xD65F03C0  # ret
            elif instruction in hint_nops:
                replacement = nop
            elif instruction & 0xFFFFFFE0 in pac_zero:
                replacement = nop
            if replacement:
                words[index] = replacement
                changed = True
        if changed:
            struct.pack_into(f"<{len(words)}I", data, start, *words)


def _sign_extend(value: int, bits: int) -> int:
    return value - (1 << bits) if value & (1 << (bits - 1)) else value


class Image:
    """A Mach-O file image (CoreFP, commerce)."""

    def __init__(self, name: str, raw: bytes) -> None:
        self.name = name
        self.data = bytearray(_arm64e_slice(raw))
        self.relocated = False
        self.loaded_base = 0
        self.segments: List[Segment] = []
        self.sections: List[Section] = []
        self._symbols: List[Tuple[str, int]] = []
        self._dyld: Optional[Tuple[int, ...]] = None
        self._exports_trie: Optional[Tuple[int, int]] = None
        self._chained: Optional[Tuple[int, int]] = None
        self._parse_header()
        self.base = next((s.address for s in self.segments if s.name == "__TEXT"), 0)
        self._validate_segments()
        _strip_pointer_authentication(self.data, [
            (s.offset, s.offset + s.size) for s in self.sections
            if s.flags & (S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS)
        ])
        self.rebases: List[Rebase] = []
        self.binds: List[Bind] = []
        if self._chained is None:
            self.rebases = self._parse_rebases()
            self.binds = self._parse_binds()

    # -- parsing --------------------------------------------------------

    def _parse_header(self) -> None:
        data = self.data
        magic, cpu, _sub, _filetype, ncmds, _sizeofcmds, _flags, _res = struct.unpack_from("<IiiIIIII", data, 0)
        if magic != MH_MAGIC_64:
            raise SAPError(f"{self.name}: not a 64-bit Mach-O")
        if cpu != CPU_TYPE_ARM64:
            raise SAPError(f"{self.name}: expected an arm64 Mach-O")
        offset = 32
        symtab = None
        for _ in range(ncmds):
            cmd, size = struct.unpack_from("<II", data, offset)
            if cmd == LC_SEGMENT_64:
                segname = data[offset + 8 : offset + 24].split(b"\0", 1)[0].decode()
                vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<QQQQ", data, offset + 24)
                nsects = struct.unpack_from("<I", data, offset + 64)[0]
                self.segments.append(Segment(segname, vmaddr, vmsize, fileoff, filesize))
                for index in range(nsects):
                    at = offset + 72 + index * 80
                    sectname = data[at : at + 16].split(b"\0", 1)[0].decode()
                    sect_segment = data[at + 16 : at + 32].split(b"\0", 1)[0].decode()
                    addr, sect_size = struct.unpack_from("<QQ", data, at + 32)
                    sect_offset = struct.unpack_from("<I", data, at + 48)[0]
                    flags = struct.unpack_from("<I", data, at + 64)[0]
                    self.sections.append(Section(sect_segment, sectname, addr, sect_size, sect_offset, flags))
            elif cmd == LC_SYMTAB:
                symtab = struct.unpack_from("<IIII", data, offset + 8)
            elif cmd in (LC_DYLD_INFO, LC_DYLD_INFO_ONLY):
                self._dyld = struct.unpack_from("<10I", data, offset + 8)
            elif cmd == LC_DYLD_EXPORTS_TRIE:
                self._exports_trie = struct.unpack_from("<II", data, offset + 8)
            elif cmd == LC_DYLD_CHAINED_FIXUPS:
                self._chained = struct.unpack_from("<II", data, offset + 8)
            offset += size
        if symtab is not None:
            symoff, nsyms, stroff, strsize = symtab
            strings = bytes(data[stroff : stroff + strsize])
            for index in range(nsyms):
                strx, _type, _sect, _desc, value = struct.unpack_from("<IBBHQ", data, symoff + index * 16)
                end = strings.find(b"\0", strx)
                name = strings[strx:end].decode("utf-8", "replace") if strx < len(strings) else ""
                self._symbols.append((name, value))

    def _validate_segments(self) -> None:
        for s in self.segments:
            if s.file_size > s.size:
                raise SAPError(f"segment {s.name} file data exceeds its memory size in {self.name}")
            if s.file_offset + s.file_size > len(self.data):
                raise SAPError(f"segment {s.name} data exceeds {self.name}")

    def _segment_by_index(self, index: int) -> Segment:
        if index >= len(self.segments):
            raise SAPError(f"{self.name}: segment index {index} out of range")
        return self.segments[index]

    def _segment(self, name: str) -> Segment:
        for s in self.segments:
            if s.name == name:
                return s
        raise SAPError(f"fixup references unknown segment {name} in {self.name}")

    def _read_pointer_at(self, segment: str, offset: int) -> int:
        s = self._segment(segment)
        return struct.unpack_from("<Q", self.data, s.file_offset + offset)[0]

    def _parse_rebases(self) -> List[Rebase]:
        if self._dyld is None:
            return []
        rebase_off, rebase_size = self._dyld[0], self._dyld[1]
        out: List[Rebase] = []
        if not rebase_size:
            return out
        r = _Stream(bytes(self.data[rebase_off : rebase_off + rebase_size]))
        rtype = 0
        segment: Optional[Segment] = None
        offset = 0

        def emit() -> None:
            if segment is None:
                raise SAPError(f"{self.name}: rebase before segment was set")
            out.append(Rebase(segment.name, offset, rtype, self._read_pointer_at(segment.name, offset)))

        while not r.eof():
            byte = r.byte()
            opcode = byte & REBASE_OPCODE_MASK
            imm = byte & REBASE_IMMEDIATE_MASK
            if opcode == REBASE_OPCODE_DONE:
                break
            if opcode == REBASE_OPCODE_SET_TYPE_IMM:
                rtype = imm
            elif opcode == REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
                segment = self._segment_by_index(imm)
                offset = r.uleb()
            elif opcode == REBASE_OPCODE_ADD_ADDR_ULEB:
                offset = (offset + r.uleb()) & U64
            elif opcode == REBASE_OPCODE_ADD_ADDR_IMM_SCALED:
                offset += imm * POINTER_SIZE
            elif opcode == REBASE_OPCODE_DO_REBASE_IMM_TIMES:
                for _ in range(imm):
                    emit()
                    offset += POINTER_SIZE
            elif opcode == REBASE_OPCODE_DO_REBASE_ULEB_TIMES:
                for _ in range(r.uleb()):
                    emit()
                    offset += POINTER_SIZE
            elif opcode == REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB:
                emit()
                offset = (offset + r.uleb() + POINTER_SIZE) & U64
            elif opcode == REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB:
                count = r.uleb()
                skip = r.uleb()
                for _ in range(count):
                    emit()
                    offset = (offset + skip + POINTER_SIZE) & U64
            else:
                raise SAPError(f"{self.name}: unknown rebase opcode {opcode:#x}")
        return out

    def _parse_binds(self) -> List[Bind]:
        if self._dyld is None:
            return []
        d = self._dyld
        out: List[Bind] = []
        for off, size, kind in ((d[2], d[3], KIND_BIND), (d[4], d[5], KIND_WEAK), (d[6], d[7], KIND_LAZY)):
            if size:
                out.extend(self._parse_bind_stream(bytes(self.data[off : off + size]), kind))
        return out

    def _parse_bind_stream(self, data: bytes, kind: int) -> List[Bind]:
        r = _Stream(data)
        out: List[Bind] = []
        name = ""
        btype = 0
        addend = 0
        segment: Optional[Segment] = None
        offset = 0

        def emit() -> None:
            if segment is None:
                raise SAPError(f"{self.name}: bind before segment was set")
            out.append(Bind(name, segment.name, offset, btype, addend, kind))

        while not r.eof():
            byte = r.byte()
            opcode = byte & BIND_OPCODE_MASK
            imm = byte & BIND_IMMEDIATE_MASK
            if opcode == BIND_OPCODE_DONE:
                if kind != KIND_LAZY:
                    break
                continue  # lazy streams are a sequence of DONE-terminated records
            if opcode in (BIND_OPCODE_SET_DYLIB_ORDINAL_IMM, BIND_OPCODE_SET_DYLIB_SPECIAL_IMM):
                pass
            elif opcode == BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB:
                r.uleb()
            elif opcode == BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM:
                name = r.cstring()
            elif opcode == BIND_OPCODE_SET_TYPE_IMM:
                btype = imm
            elif opcode == BIND_OPCODE_SET_ADDEND_SLEB:
                addend = r.sleb()
            elif opcode == BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
                segment = self._segment_by_index(imm)
                offset = r.uleb()
            elif opcode == BIND_OPCODE_ADD_ADDR_ULEB:
                offset = (offset + r.uleb()) & U64
            elif opcode == BIND_OPCODE_DO_BIND:
                emit()
                offset += POINTER_SIZE
            elif opcode == BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB:
                emit()
                offset = (offset + r.uleb() + POINTER_SIZE) & U64
            elif opcode == BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED:
                emit()
                offset += imm * POINTER_SIZE + POINTER_SIZE
            elif opcode == BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB:
                count = r.uleb()
                skip = r.uleb()
                for _ in range(count):
                    emit()
                    offset = (offset + skip + POINTER_SIZE) & U64
            else:
                raise SAPError(f"{self.name}: unknown bind opcode {opcode:#x}")
        return out

    # -- symbols ----------------------------------------------------------

    def _exports(self) -> Dict[str, int]:
        if self._exports_trie is not None:
            off, size = self._exports_trie
        elif self._dyld is not None:
            off, size = self._dyld[8], self._dyld[9]
        else:
            return {}
        if not size:
            return {}
        return {name: self.base + offset for name, offset in parse_export_trie(bytes(self.data[off : off + size])).items()}

    def find_symbol_address(self, symbol: str) -> int:
        """Same lookup order as go-macho's FindSymbolAddress: symbol table
        first (case-insensitive, first match), then the export trie."""
        lowered = symbol.lower()
        for name, value in self._symbols:
            if name.lower() == lowered:
                return value
        for name, value in self._exports().items():
            if name.lower() == lowered:
                return value
        raise SAPError(f"find {symbol} in {self.name}: symbol not found")

    def export(self, symbol: str, load_base: int) -> int:
        address = self.find_symbol_address(symbol)
        if address < self.base:
            raise SAPError(f"symbol {symbol} in {self.name} precedes image base")
        return load_base + (address - self.base)

    # -- relocation / loading ---------------------------------------------

    def _segment_file_offset(self, name: str, offset: int, size: int) -> int:
        s = self._segment(name)
        end = offset + size
        if end > s.size:
            raise SAPError(f"fixup at {offset:#x} exceeds segment {name} in {self.name}")
        if end > s.file_size:
            raise SAPError(f"fixup at {offset:#x} exceeds file data for segment {name} in {self.name}")
        return s.file_offset + offset

    def relocate(self, load_base: int, resolve: Callable[[str], int]) -> None:
        if self.relocated:
            raise SAPError(f"{self.name} is already relocated")
        pack = struct.pack_into
        for rebase in self.rebases:
            if rebase.type != REBASE_TYPE_POINTER:
                raise SAPError(f"{self.name} uses unsupported rebase type {rebase.type}")
            if rebase.value < self.base:
                raise SAPError(f"{self.name} contains a rebase below its image base")
            offset = self._segment_file_offset(rebase.segment, rebase.offset, POINTER_SIZE)
            pack("<Q", self.data, offset, (load_base + rebase.value - self.base) & U64)
        for bind in self.binds:
            if bind.type not in (0, BIND_TYPE_POINTER):
                raise SAPError(f"{self.name} uses unsupported bind type {bind.type} for {bind.name}")
            offset = self._segment_file_offset(bind.segment, bind.seg_offset, POINTER_SIZE)
            address = resolve(bind.name) + bind.addend
            if address < 0 or address > U64:
                raise SAPError(f"apply addend for {bind.name} in {self.name}: address out of range")
            pack("<Q", self.data, offset, address)
        if self._chained is not None:
            self._relocate_chained(load_base, resolve)
        self.relocated = True
        self.loaded_base = load_base

    def _imports(self, fixups: bytes, header) -> List[Tuple[str, int]]:
        _version, _starts, imports_offset, symbols_offset, count, imports_format, symbols_format = header
        if symbols_format != 0:
            raise SAPError(f"{self.name}: compressed chained-fixup symbol names aren't supported")
        out = []
        for index in range(count):
            if imports_format == 1:
                value = struct.unpack_from("<I", fixups, imports_offset + index * 4)[0]
                name_offset, addend = value >> 9, 0
            elif imports_format == 2:
                value, addend = struct.unpack_from("<Ii", fixups, imports_offset + index * 8)
                name_offset = value >> 9
            elif imports_format == 3:
                value, addend = struct.unpack_from("<Qq", fixups, imports_offset + index * 16)
                name_offset = value >> 32
            else:
                raise SAPError(f"{self.name}: unknown chained import format {imports_format}")
            start = symbols_offset + name_offset
            end = fixups.index(b"\0", start)
            out.append((fixups[start:end].decode("utf-8", "replace"), addend))
        return out

    def _relocate_chained(self, load_base: int, resolve: Callable[[str], int]) -> None:
        off, size = self._chained
        fixups = bytes(self.data[off : off + size])
        header = struct.unpack_from("<7I", fixups, 0)
        imports = self._imports(fixups, header)
        starts = header[1]
        seg_count = struct.unpack_from("<I", fixups, starts)[0]
        resolved: Dict[int, int] = {}
        for seg_index in range(seg_count):
            seg_info = struct.unpack_from("<I", fixups, starts + 4 + seg_index * 4)[0]
            if not seg_info:
                continue
            at = starts + seg_info
            _size, page_size, pointer_format, _segment_offset, _max_valid, page_count = struct.unpack_from(
                "<IHHQIH", fixups, at)
            page_starts = struct.unpack_from(f"<{page_count}H", fixups, at + 22)
            segment = self._segment_by_index(seg_index)
            arm64e = pointer_format in _ARM64E_FORMATS
            if not arm64e and pointer_format not in (PTR_64, PTR_64_OFFSET):
                raise SAPError(f"{self.name}: unsupported chained pointer format {pointer_format}")
            stride = 8 if arm64e else 4
            for page, start in enumerate(page_starts):
                if start == 0xFFFF:
                    continue
                if start & 0x8000:
                    raise SAPError(f"{self.name}: multi-start chained fixup pages aren't supported")
                offset = segment.file_offset + page * page_size + start
                while True:
                    if offset + 8 > len(self.data):
                        raise SAPError(f"chained fixup at {offset:#x} exceeds {self.name}")
                    raw = struct.unpack_from("<Q", self.data, offset)[0]
                    value, step = self._chained_value(raw, pointer_format, imports, load_base, resolve, resolved, offset)
                    struct.pack_into("<Q", self.data, offset, value & U64)
                    if not step:
                        break
                    offset += step * stride

    def _chained_value(self, raw, pointer_format, imports, load_base, resolve, resolved, offset):
        def bind(ordinal: int, addend: int) -> int:
            if ordinal >= len(imports):
                raise SAPError(f"{self.name}: chained bind ordinal {ordinal} out of range")
            name, import_addend = imports[ordinal]
            if ordinal not in resolved:
                resolved[ordinal] = resolve(name)
            return resolved[ordinal] + addend + import_addend

        if pointer_format in _ARM64E_FORMATS:
            step = (raw >> 51) & 0x7FF
            auth = raw >> 63
            is_bind = (raw >> 62) & 1
            if is_bind:
                ordinal = raw & (0xFFFFFF if pointer_format == PTR_ARM64E_USERLAND24 else 0xFFFF)
                addend = 0 if auth else _sign_extend((raw >> 32) & 0x7FFFF, 19)
                return bind(ordinal, addend), step
            if auth:
                target = raw & 0xFFFFFFFF
            elif pointer_format == PTR_ARM64E:
                absolute = raw & ((1 << 43) - 1)
                if absolute < self.base:
                    raise SAPError(f"chained rebase at {offset:#x} precedes the base of {self.name}")
                target = absolute - self.base
            else:
                target = raw & ((1 << 43) - 1)
            return load_base + target, step
        step = (raw >> 51) & 0xFFF
        if raw >> 63:
            return bind(raw & 0xFFFFFF, (raw >> 24) & 0xFF), step
        target = (raw & ((1 << 36) - 1)) | (((raw >> 36) & 0xFF) << 56)
        if pointer_format == PTR_64:
            target -= self.base
        return load_base + target, step

    def load(self, uc) -> None:
        if not self.relocated:
            raise SAPError(f"{self.name} must be relocated before loading")
        _map_and_write(uc, self.name, [
            (self.loaded_base + s.address - self.base, s.size,
             bytes(self.data[s.file_offset : s.file_offset + s.file_size]))
            for s in self.segments if s.name != "__PAGEZERO" and s.size
        ])


def _map_and_write(uc, name: str, items: List[Tuple[int, int, bytes]]) -> None:
    ranges = []
    for address, size, _data in items:
        start = address - address % PAGE_SIZE
        end = (address + size + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1)
        ranges.append([start, end])
    if not ranges:
        raise SAPError(f"{name} has no loadable segments")
    ranges.sort()
    merged = []
    for start, end in ranges:
        if merged and start <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    total = 0
    for start, end in merged:
        total += end - start
        if total > MAX_IMAGE_SPAN:
            raise SAPError(f"mapped segments make {name} too large")
        uc.mem_map(start, end - start)
    for address, _size, data in items:
        if data:
            uc.mem_write(address, data)


class PrelinkedImage:
    """An image extracted from the dyld shared cache (dyld.py blob)."""

    def __init__(self, name: str, blob: bytes) -> None:
        from .dyld import BLOB_MAGIC

        if not blob.startswith(BLOB_MAGIC):
            raise SAPError(f"{name}: not an extracted shared-cache image")
        length = struct.unpack_from("<I", blob, len(BLOB_MAGIC))[0]
        start = len(BLOB_MAGIC) + 4
        meta = json.loads(blob[start : start + length])
        self.name = name
        self.data = bytearray(blob[start + length :])
        self.base = meta["base"]
        self.segments = [Segment(s["name"], s["address"], s["size"], s["data_offset"], s["data_size"])
                         for s in meta["segments"]]
        self._exports = meta["exports"]
        self.relocated = False
        instruction_ranges = []
        for section in meta["sections"]:
            if not section["flags"] & (S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS):
                continue
            for s in self.segments:
                if s.file_size and s.address <= section["address"] and section["address"] + section["size"] <= s.address + s.file_size:
                    start = s.file_offset + section["address"] - s.address
                    instruction_ranges.append((start, start + section["size"]))
        _strip_pointer_authentication(self.data, instruction_ranges)

    def export(self, symbol: str, _load_base: int = 0) -> int:
        if symbol not in self._exports:
            raise SAPError(f"find {symbol} in {self.name}: symbol not found")
        return self._exports[symbol]

    def prepare_prelinked(self, external: Dict[int, str], resolve: Callable[[str], int]) -> None:
        """machimage PreparePrelinked: pointers to other cache images'
        functions are redirected to the emulator's implementations."""
        if self.relocated:
            raise SAPError(f"{self.name} is already relocated")
        patched = {address: resolve(name) for address, name in external.items()}
        for s in self.segments:
            if s.name in ("__TEXT", "__LINKEDIT") or s.file_size < POINTER_SIZE:
                continue
            start = s.file_offset
            if s.address % POINTER_SIZE:
                start += POINTER_SIZE - s.address % POINTER_SIZE
            count = (s.file_offset + s.file_size - start) // POINTER_SIZE
            values = list(struct.unpack_from(f"<{count}Q", self.data, start))
            changed = False
            for index, value in enumerate(values):
                replacement = patched.get(value)
                if replacement is not None:
                    values[index] = replacement
                    changed = True
            if changed:
                struct.pack_into(f"<{count}Q", self.data, start, *values)
        self.relocated = True

    def load(self, uc) -> None:
        if not self.relocated:
            raise SAPError(f"{self.name} must be prepared before loading")
        _map_and_write(uc, self.name, [
            (s.address, s.size, bytes(self.data[s.file_offset : s.file_offset + s.file_size]))
            for s in self.segments if s.name != "__LINKEDIT" and s.size
        ])
