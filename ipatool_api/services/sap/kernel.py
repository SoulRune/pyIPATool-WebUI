"""FairPlayIOKit out of the restore image's kernel collection.

Port of ipatool ``internal/sap/assets/kernel.go`` (ipatool 2.8, MIT). The
kernel extension only exists inside the prelinked kernel collection
(``kernelcache.release.mac13j``: an IM4P container around an LZFSE-compressed
MH_FILESET Mach-O). Its segments are copied out unchanged - their pointers
stay in the collection's fixed-up form, which machine.py rewrites at load
time (``relocate_kernel_cache_pointers``) - and its undefined symbols are
resolved against the other kexts' exports, as ipatool does.

ipatool writes the result with go-macho's exporter; this module writes a
smaller Mach-O (segments laid out the same way, the symbol table, no other
link-edit data), so its digest is pinned separately in assets.py. The
loaded segment contents are the same.
"""
from __future__ import annotations

import struct
from typing import Dict, List, Tuple

from .errors import SAPError

KERNEL_CACHE_NAME = "kernelcache.release.mac13j"
KERNEL_CACHE_COMPRESSED_SIZE = 33043908
KERNEL_CACHE_ARCHIVE_SIZE = 33096787
# SHA-256 of the IM4P as stored in the restore image, checked before unpacking.
KERNEL_CACHE_ARCHIVE_SHA256 = "a066d0e7ab2178bd79decf2465ac0828c34f39098d8c1a471281c0b340c74c64"
KERNEL_CACHE_PAYLOAD_SIZE = 33096384
KERNEL_CACHE_IMAGE_SIZE = 124354560
FAIRPLAY_KEXT_IDENTIFIER = "com.apple.driver.FairPlayIOKit"
_MAX_SYMBOLS = 1 << 20

_MH_MAGIC_64 = 0xFEEDFACF
_MH_FILESET = 12
_MH_DYLIB_IN_CACHE = 0x80000000
_LC_SEGMENT_64 = 0x19
_LC_SYMTAB = 0x2
_LC_UUID = 0x1B
_LC_FILESET_ENTRY = 0x80000035
_N_EXT = 0x01
_N_TYPE = 0x0E
_N_ABS = 0x02
_EXPORT_PAGE = 0x4000


def _der_header(data: bytes, offset: int) -> Tuple[int, int, int]:
    """(tag, content offset, content length) of the DER item at ``offset``."""
    if offset + 2 > len(data):
        raise SAPError("truncated IM4P container")
    tag = data[offset]
    length = data[offset + 1]
    offset += 2
    if length & 0x80:
        count = length & 0x7F
        if count == 0 or count > 8 or offset + count > len(data):
            raise SAPError("invalid IM4P length")
        length = int.from_bytes(data[offset : offset + count], "big")
        offset += count
    if offset + length > len(data):
        raise SAPError("truncated IM4P container")
    return tag, offset, length


def im4p_payload(data: bytes) -> bytes:
    """The kernel payload of an IM4P (SEQUENCE "IM4P", "krnl", description,
    OCTET STRING payload, ...)."""
    tag, offset, length = _der_header(data, 0)
    if tag != 0x30 or offset + length != len(data):
        raise SAPError("invalid IM4P container")
    end = offset + length
    fields: List[Tuple[int, bytes]] = []
    while offset < end and len(fields) < 4:
        field_tag, content, field_length = _der_header(data, offset)
        fields.append((field_tag, data[content : content + field_length]))
        offset = content + field_length
    if (len(fields) != 4 or fields[0] != (0x16, b"IM4P") or fields[1] != (0x16, b"krnl")
            or fields[3][0] != 0x04):
        raise SAPError("invalid IM4P kernel payload")
    return fields[3][1]


class _Member:
    def __init__(self, image: bytes, offset: int) -> None:
        if offset + 32 > len(image):
            raise SAPError("kernel collection member exceeds the image")
        magic, cpu, subtype, filetype, ncmds, sizeofcmds, flags, _reserved = struct.unpack_from("<8I", image, offset)
        if magic != _MH_MAGIC_64:
            raise SAPError("kernel collection member is not a 64-bit Mach-O")
        self.header = (cpu, subtype, filetype, flags)
        self.segments: List[Tuple[bytes, int]] = []  # (raw command, command offset in image)
        self.uuid = b""
        self.symtab = None
        position = offset + 32
        if position + sizeofcmds > len(image):
            raise SAPError("kernel collection member commands exceed the image")
        for _ in range(ncmds):
            command, size = struct.unpack_from("<II", image, position)
            if size < 8 or position + size > offset + 32 + sizeofcmds:
                raise SAPError("invalid kernel collection member command")
            raw = image[position : position + size]
            if command == _LC_SEGMENT_64:
                self.segments.append((raw, position))
            elif command == _LC_UUID:
                self.uuid = raw
            elif command == _LC_SYMTAB:
                self.symtab = struct.unpack_from("<4I", raw, 8)
            position += size

    def symbols(self, image: bytes) -> List[Tuple[str, int, int, int, int]]:
        """(name, type, section, description, value) in table order."""
        if self.symtab is None:
            return []
        symoff, nsyms, stroff, strsize = self.symtab
        if nsyms > _MAX_SYMBOLS or symoff + nsyms * 16 > len(image) or stroff + strsize > len(image):
            raise SAPError("kernel collection symbol table exceeds the image")
        strings = image[stroff : stroff + strsize]
        out = []
        for index in range(nsyms):
            strx, kind, section, desc, value = struct.unpack_from("<IBBHQ", image, symoff + index * 16)
            end = strings.find(b"\0", strx)
            name = strings[strx:end].decode("utf-8", "replace") if 0 <= strx < len(strings) and end >= 0 else ""
            out.append((name, kind, section, desc, value))
        return out


def _fileset_entries(image: bytes) -> List[Tuple[str, int]]:
    magic, _cpu, _subtype, filetype, ncmds, sizeofcmds, _flags, _reserved = struct.unpack_from("<8I", image, 0)
    if magic != _MH_MAGIC_64:
        raise SAPError("pinned kernel collection is not a 64-bit Mach-O")
    if filetype != _MH_FILESET:
        raise SAPError("pinned kernel collection is not a fileset")
    entries = []
    position = 32
    for _ in range(ncmds):
        command, size = struct.unpack_from("<II", image, position)
        if size < 8 or position + size > 32 + sizeofcmds:
            raise SAPError("invalid kernel collection command")
        if command == _LC_FILESET_ENTRY:
            _vmaddr, fileoff, name_offset = struct.unpack_from("<QQI", image, position + 8)
            end = image.find(b"\0", position + name_offset, position + size)
            if end < 0:
                raise SAPError("invalid kernel collection entry name")
            entries.append((image[position + name_offset : end].decode("utf-8", "replace"), fileoff))
        position += size
    return entries


def _round(value: int) -> int:
    return (value + _EXPORT_PAGE - 1) & ~(_EXPORT_PAGE - 1)


def extract_fairplay_kext(image: bytes) -> bytes:
    """A standalone Mach-O of FairPlayIOKit from the decompressed collection."""
    if len(image) != KERNEL_CACHE_IMAGE_SIZE:
        raise SAPError(f"pinned kernel image has size {len(image)}, expected {KERNEL_CACHE_IMAGE_SIZE}")
    entries = _fileset_entries(image)
    exported: Dict[str, int] = {}
    target = None
    for name, fileoff in entries:
        try:
            member = _Member(image, fileoff)
        except SAPError:
            continue
        if name == FAIRPLAY_KEXT_IDENTIFIER:
            target = member
        for symbol, kind, _section, _desc, value in member.symbols(image):
            if kind & _N_EXT and kind & _N_TYPE != 0 and value != 0:
                exported[symbol] = value
                if len(exported) > _MAX_SYMBOLS:
                    raise SAPError("pinned kernel symbol table exceeds the limit")
    if target is None:
        raise SAPError("FairPlayIOKit is missing from the pinned kernel collection")

    symbols = target.symbols(image)
    for symbol, kind, _section, desc, _value in list(symbols):
        if kind & _N_TYPE == 0 and symbol and symbol in exported:
            symbols.append((symbol, _N_ABS | _N_EXT, 0, desc, exported[symbol]))

    # Segments in file order, each padded to a 16 KB boundary as go-macho's
    # exporter does; the padding is zero.
    commands = bytearray()
    body = bytearray()
    segment_count = 0
    first_section = 0
    for raw, _position in target.segments:
        name = raw[8:24].split(b"\0", 1)[0]
        if name == b"__LINKEDIT":
            continue
        vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<4Q", raw, 24)
        if fileoff + filesize > len(image):
            raise SAPError("FairPlayIOKit segment exceeds the kernel collection")
        data = image[fileoff : fileoff + filesize]
        padded = _round(filesize)
        offset = len(body)
        body += data + bytes(padded - filesize)
        updated = bytearray(raw)
        struct.pack_into("<4Q", updated, 24, vmaddr, max(vmsize, padded), offset, padded)
        nsects = struct.unpack_from("<I", raw, 64)[0]
        for index in range(nsects):
            at = 72 + index * 80
            address = struct.unpack_from("<Q", raw, at + 32)[0]
            section_offset = struct.unpack_from("<I", raw, at + 48)[0]
            if section_offset:
                struct.pack_into("<I", updated, at + 48, offset + address - vmaddr)
                if offset == 0 and (first_section == 0 or address - vmaddr < first_section):
                    first_section = address - vmaddr
        commands += updated
        segment_count += 1

    strings = bytearray(b"\0")
    table = bytearray()
    for symbol, kind, section, desc, value in symbols:
        index = len(strings)
        strings += symbol.encode("utf-8") + b"\0"
        table += struct.pack("<IBBHQ", index, kind, section, desc, value)
    while len(strings) % 8:
        strings += b"\0"

    header_size = 32 + len(commands) + 24 + len(target.uuid)
    if header_size > first_section:
        raise SAPError("FairPlayIOKit load commands don't fit before its first section")
    # The header is written over the start of __TEXT (as in the collection).
    symoff = len(body)
    stroff = symoff + len(table)
    commands += struct.pack("<IIIIII", _LC_SYMTAB, 24, symoff, len(symbols), stroff, len(strings))
    commands += target.uuid
    cpu, subtype, filetype, flags = target.header
    header = struct.pack("<8I", _MH_MAGIC_64, cpu, subtype, filetype, segment_count + 1 + (1 if target.uuid else 0),
                         len(commands), flags & ~_MH_DYLIB_IN_CACHE, 0)
    output = bytearray(body)
    output[: len(header) + len(commands)] = header + commands
    output += table + strings
    return bytes(output)
