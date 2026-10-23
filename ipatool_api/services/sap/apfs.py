"""Read-only access to single files of an APFS image (port of the parts of
ipatool internal/sap/assets/apfs.go and go-apfs it needs).

Enough of APFS to open a file by path in the restore image's sealed system
volumes: container superblock and object map, the volume's object map and
filesystem tree (sealed trees: header-less, hash-verified nodes), file extents
(from the filesystem tree or the separate extent tree of sealed volumes) and
transparent compression (decmpfs types 8 LZVN, 12 LZFSE, 14 LZBITMAP, data in
the resource fork).
"""
from __future__ import annotations

import bisect
import hashlib
import struct
import threading
from collections import OrderedDict
from typing import List, Tuple

from . import codecs

BLOCK_SIZE = 4096
_MAX_DEPTH = 32

_BTNODE_ROOT = 0x1
_BTNODE_LEAF = 0x2
_BTNODE_FIXED = 0x4
_BTNODE_HASHED = 0x8
_BTREE_INFO_SIZE = 40

_TYPE_INODE = 3
_TYPE_XATTR = 4
_TYPE_FILE_EXTENT = 8
_TYPE_DIR_REC = 9
_OBJ_ID_MASK = (1 << 60) - 1
_FSROOT_OID = 2
_INO_EXT_TYPE_DSTREAM = 8
_XATTR_DATA_STREAM = 0x1
_XATTR_DATA_EMBEDDED = 0x2

_DECMPFS_LZVN = 8
_DECMPFS_LZFSE = 12
_DECMPFS_LZBITMAP = 14
_DECMPFS_BLOCK = 64 << 10


class APFSError(ValueError):
    pass


class _Node:
    __slots__ = ("flags", "level", "entries")

    def __init__(self, flags: int, level: int, entries: List[Tuple[bytes, bytes]]) -> None:
        self.flags = flags
        self.level = level
        self.entries = entries

    @property
    def leaf(self) -> bool:
        return bool(self.flags & _BTNODE_LEAF)


def _parse_node(block: bytes, fixed_key: int = 16, fixed_value: int = 16) -> _Node:
    flags, level, nkeys = struct.unpack_from("<HHI", block, 32)
    toc_offset, toc_length = struct.unpack_from("<HH", block, 40)
    data_start = 56
    key_start = data_start + toc_offset + toc_length
    value_end = BLOCK_SIZE - (_BTREE_INFO_SIZE if flags & _BTNODE_ROOT else 0)
    entries = []
    toc = data_start + toc_offset
    for i in range(nkeys):
        if flags & _BTNODE_FIXED:
            k_off, v_off = struct.unpack_from("<HH", block, toc + i * 4)
            k_len = fixed_key
            v_len = fixed_value if flags & _BTNODE_LEAF else 8
        else:
            k_off, k_len, v_off, v_len = struct.unpack_from("<HHHH", block, toc + i * 8)
        key = block[key_start + k_off:key_start + k_off + k_len]
        value = block[value_end - v_off:value_end - v_off + v_len] if v_off != 0xFFFF else b""
        entries.append((key, value))
    return _Node(flags, level, entries)


class _ExtentReader:
    """read_at() over a file's extents ([(logical, physical block, length)])."""

    def __init__(self, device, extents, size: int) -> None:
        extents = sorted(extents)
        position = 0
        for logical, physical, length in extents:
            if length == 0 or logical != position:
                raise APFSError("file has invalid or sparse extents")
            position += length
        if position < size:
            raise APFSError(f"file extents cover {position} bytes, expected {size}")
        self._device = device
        self._extents = extents
        self._starts = [e[0] for e in extents]
        self.size = size

    def read_at(self, offset: int, length: int) -> bytes:
        if offset < 0 or offset + length > self.size:
            raise APFSError("read outside the file")
        out = bytearray()
        position, end = offset, offset + length
        while position < end:
            index = bisect.bisect_right(self._starts, position) - 1
            logical, physical, extent_length = self._extents[index]
            take = min(end - position, logical + extent_length - position)
            out += self._device.read_at(physical * BLOCK_SIZE + position - logical, take)
            position += take
        return bytes(out)


class _DecmpfsReader:
    """read_at() over a transparently compressed file (resource-fork data)."""

    def __init__(self, source, method: int, output_size: int) -> None:
        if method not in (_DECMPFS_LZVN, _DECMPFS_LZFSE, _DECMPFS_LZBITMAP):
            raise APFSError(f"unsupported compression type {method}")
        blocks = (output_size + _DECMPFS_BLOCK - 1) // _DECMPFS_BLOCK
        table_size = (blocks + 1) * 4
        first = struct.unpack("<I", source.read_at(0, 4))[0]
        if first != table_size or table_size > source.size:
            raise APFSError(f"compression index has size {first}, expected {table_size}")
        offsets = struct.unpack(f"<{blocks + 1}I", source.read_at(0, table_size))
        for i in range(blocks):
            if offsets[i] < table_size or offsets[i + 1] <= offsets[i] or offsets[i + 1] > source.size \
                    or offsets[i + 1] - offsets[i] > _DECMPFS_BLOCK + 1:
                raise APFSError(f"compressed block {i} has an invalid range")
        if offsets[-1] != source.size:
            raise APFSError("compressed blocks don't end at the end of the resource fork")
        self._source = source
        self._method = method
        self._offsets = offsets
        self.size = output_size
        self._cache: "OrderedDict[int, bytes]" = OrderedDict()
        self._lock = threading.Lock()

    def _block(self, index: int) -> bytes:
        with self._lock:
            cached = self._cache.get(index)
            if cached is not None:
                self._cache.move_to_end(index)
                return cached
        start, end = self._offsets[index], self._offsets[index + 1]
        data = self._source.read_at(start, end - start)
        expected = min(_DECMPFS_BLOCK, self.size - index * _DECMPFS_BLOCK)
        method = self._method
        if method == _DECMPFS_LZVN:
            plain = data[1:] if data[0] == 0x06 else codecs.lzvn_decompress(data, expected)
        elif method == _DECMPFS_LZFSE:
            plain = data[1:] if data[0] != ord("b") else codecs.lzfse_decompress(data, expected)
        else:
            plain = data[1:] if data[0] == 0xFF else codecs.lzbitmap_decompress(data, expected)
        if len(plain) != expected:
            raise APFSError(f"compressed block {index} decoded to {len(plain)} bytes, expected {expected}")
        with self._lock:
            self._cache[index] = plain
            while len(self._cache) > 128:
                self._cache.popitem(last=False)
        return plain

    def read_at(self, offset: int, length: int) -> bytes:
        if offset < 0 or offset + length > self.size:
            raise APFSError("read outside the compressed file")
        out = bytearray()
        position, end = offset, offset + length
        while position < end:
            index = position // _DECMPFS_BLOCK
            block = self._block(index)
            inside = position - index * _DECMPFS_BLOCK
            take = min(end - position, len(block) - inside)
            out += block[inside:inside + take]
            position += take
        return bytes(out)


class APFS:
    def __init__(self, device) -> None:
        """``device``: read_at()/size of the raw APFS container image."""
        self._device = device
        superblock = self._block(0)
        if superblock[32:36] != b"NXSB":
            raise APFSError("not an APFS container")
        block_size = struct.unpack_from("<I", superblock, 36)[0]
        if block_size != BLOCK_SIZE:
            raise APFSError(f"unsupported APFS block size {block_size}")
        container_omap = struct.unpack_from("<Q", superblock, 160)[0]
        volume_oid = struct.unpack_from("<Q", superblock, 184)[0]
        container_xid = struct.unpack_from("<Q", superblock, 16)[0]
        self._container_omap_root = self._omap_root(container_omap)
        volume_block = self._omap_lookup(self._container_omap_root, volume_oid, container_xid)
        volume = self._block(volume_block)
        if volume[32:36] != b"APSB":
            raise APFSError("APFS volume superblock not found")
        volume_omap, root_tree = struct.unpack_from("<QQ", volume, 128)
        self._fext_tree = struct.unpack_from("<Q", volume, 1032)[0]
        omap_block = self._block(volume_omap)
        self._volume_xid = struct.unpack_from("<Q", omap_block, 16)[0]
        self._volume_omap_root = self._omap_root(volume_omap)
        self._root_tree_base = root_tree
        root_block = self._omap_lookup(self._volume_omap_root, root_tree, self._volume_xid)
        self._fs_root = _parse_node(self._block(root_block))

    # -- blocks and object maps -------------------------------------------

    def _block(self, number: int) -> bytes:
        return self._device.read_at(number * BLOCK_SIZE, BLOCK_SIZE)

    def _omap_root(self, omap_oid: int) -> _Node:
        omap = self._block(omap_oid)
        tree = struct.unpack_from("<Q", omap, 48)[0]
        return _parse_node(self._block(tree))

    def _omap_lookup(self, node: _Node, oid: int, xid: int) -> int:
        for _ in range(_MAX_DEPTH):
            best = None
            for key, value in node.entries:
                key_oid, key_xid = struct.unpack_from("<QQ", key)
                if node.leaf:
                    if key_oid == oid and key_xid <= xid and (best is None or key_xid > best[0]):
                        best = (key_xid, struct.unpack_from("<Q", value, 8)[0])
                elif (key_oid, key_xid) <= (oid, xid):
                    best = (key_xid, struct.unpack_from("<Q", value)[0])
            if best is None:
                raise APFSError(f"object {oid:#x} is not in the object map")
            if node.leaf:
                return best[1]
            node = _parse_node(self._block(best[1]))
        raise APFSError("object map is too deep")

    # -- filesystem tree ---------------------------------------------------

    def _child(self, node: _Node, value: bytes) -> Tuple[_Node, int]:
        if node.flags & _BTNODE_HASHED:
            child_oid = struct.unpack_from("<Q", value)[0]
            expected = value[8:40]
            block_number = self._omap_lookup(self._volume_omap_root, self._root_tree_base + child_oid, self._volume_xid)
            raw = self._block(block_number)
            if hashlib.sha256(raw).digest() != expected:
                raise APFSError(f"filesystem node {child_oid:#x} failed SHA-256 verification")
            return _parse_node(raw), block_number
        child_oid = struct.unpack_from("<Q", value)[0]
        block_number = self._omap_lookup(self._volume_omap_root, child_oid, self._volume_xid)
        return _parse_node(self._block(block_number)), block_number

    def _records(self, object_id: int) -> List[Tuple[bytes, bytes]]:
        records: List[Tuple[bytes, bytes]] = []
        visited = set()

        def walk(node: _Node, depth: int) -> None:
            if depth > _MAX_DEPTH:
                raise APFSError("filesystem tree is too deep")
            if node.leaf:
                for key, value in node.entries:
                    if struct.unpack_from("<Q", key)[0] & _OBJ_ID_MASK == object_id:
                        records.append((key, value))
                return
            ids = [struct.unpack_from("<Q", key)[0] & _OBJ_ID_MASK for key, _ in node.entries]
            for index, (key, value) in enumerate(node.entries):
                lower = ids[index]
                upper = ids[index + 1] if index + 1 < len(ids) else (1 << 64) - 1
                if object_id < lower or object_id > upper:
                    continue
                child, address = self._child(node, value)
                if address in visited:
                    continue
                visited.add(address)
                walk(child, depth + 1)

        walk(self._fs_root, 0)
        return records

    def _resolve(self, path: str) -> List[Tuple[bytes, bytes]]:
        object_id = _FSROOT_OID
        for name in path.strip("/").split("/"):
            wanted = name.encode("utf-8")
            found = None
            for key, value in self._records(object_id):
                header = struct.unpack_from("<Q", key)[0]
                if header >> 60 != _TYPE_DIR_REC:
                    continue
                name_info = struct.unpack_from("<I", key, 8)[0]
                length = name_info & 0x3FF
                if key[12:12 + length].rstrip(b"\x00") == wanted:
                    found = struct.unpack_from("<Q", value)[0]
                    break
            if found is None:
                raise APFSError(f"path component {name!r} was not found")
            object_id = found
        return self._records(object_id)

    def _data_extents(self, object_id: int) -> List[Tuple[int, int, int]]:
        if self._fext_tree:
            return self._physical_extents(object_id)
        extents = []
        for key, value in self._records(object_id):
            if struct.unpack_from("<Q", key)[0] >> 60 == _TYPE_FILE_EXTENT:
                logical = struct.unpack_from("<Q", key, 8)[0]
                length_flags, physical = struct.unpack_from("<QQ", value)
                extents.append((logical, physical, length_flags & ((1 << 56) - 1)))
        return sorted(extents)

    def _physical_extents(self, object_id: int) -> List[Tuple[int, int, int]]:
        extents = []
        visited = set()

        def walk(node: _Node, depth: int) -> None:
            if depth > _MAX_DEPTH:
                raise APFSError("extent tree is too deep")
            if node.leaf:
                for key, value in node.entries:
                    private_id, logical = struct.unpack_from("<QQ", key)
                    if private_id == object_id:
                        length_flags, physical = struct.unpack_from("<QQ", value)
                        extents.append((logical, physical, length_flags & ((1 << 56) - 1)))
                return
            ids = [struct.unpack_from("<Q", key)[0] for key, _ in node.entries]
            for index, (key, value) in enumerate(node.entries):
                lower = ids[index]
                upper = ids[index + 1] if index + 1 < len(ids) else (1 << 64) - 1
                if object_id < lower or object_id > upper:
                    continue
                address = struct.unpack_from("<Q", value)[0]
                if address in visited:
                    continue
                visited.add(address)
                walk(_parse_node(self._block(address)), depth + 1)

        walk(_parse_node(self._block(self._fext_tree)), 0)
        return sorted(extents)

    # -- files ---------------------------------------------------------------

    def open(self, path: str):
        """read_at()/size reader for the file at ``path``."""
        records = self._resolve(path)
        inode = None
        compression = None
        resource = None
        extents = []
        for key, value in records:
            kind = struct.unpack_from("<Q", key)[0] >> 60
            if kind == _TYPE_INODE:
                inode = value
            elif kind == _TYPE_FILE_EXTENT:
                logical = struct.unpack_from("<Q", key, 8)[0]
                length_flags, physical = struct.unpack_from("<QQ", value)
                extents.append((logical, physical, length_flags & ((1 << 56) - 1)))
            elif kind == _TYPE_XATTR:
                name_length = struct.unpack_from("<H", key, 8)[0]
                name = key[10:10 + name_length].rstrip(b"\x00").decode("utf-8", "replace")
                flags, data_length = struct.unpack_from("<HH", value)
                data = value[4:4 + data_length]
                if name == "com.apple.decmpfs":
                    if not flags & _XATTR_DATA_EMBEDDED or data[:4] != b"fpmc":
                        raise APFSError("unsupported compression metadata")
                    method, size = struct.unpack_from("<IQ", data, 4)
                    compression = (method, size)
                elif name == "com.apple.ResourceFork" and flags & _XATTR_DATA_STREAM:
                    stream_id, stream_size = struct.unpack_from("<QQ", data)
                    resource = (stream_id, stream_size)
        if inode is None:
            raise APFSError("file has no inode record")
        if compression is not None:
            if resource is None:
                raise APFSError("compressed file has no resource fork")
            fork = _ExtentReader(self._device, self._data_extents(resource[0]), resource[1])
            return _DecmpfsReader(fork, compression[0], compression[1])
        private_id = struct.unpack_from("<Q", inode, 8)[0]
        size = struct.unpack_from("<Q", inode, 84)[0]
        size = _dstream_size(inode, size)
        if not extents and size:
            extents = self._data_extents(private_id)
        return _ExtentReader(self._device, extents, size)


def _dstream_size(inode: bytes, default: int) -> int:
    """The file size from the inode's DSTREAM extended field, if any."""
    if len(inode) < 96:
        return default
    count, used = struct.unpack_from("<HH", inode, 92)
    headers = 96
    data = headers + 4 * count
    for i in range(count):
        kind, _flags, size = struct.unpack_from("<BBH", inode, headers + 4 * i)
        if kind == _INO_EXT_TYPE_DSTREAM:
            return struct.unpack_from("<Q", inode, data)[0]
        data += (size + 7) & ~7
    return default
