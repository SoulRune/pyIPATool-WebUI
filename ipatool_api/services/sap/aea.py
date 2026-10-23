"""Apple Encrypted Archive (AEA1) reader with random access.

Port of ipatool internal/sap/assets/aea.go. The restore image's disk images
are AEA files: symmetric profile, LZFSE-compressed 1 MiB segments grouped in
clusters, each segment authenticated (HMAC-SHA256), encrypted (AES-256-CTR)
and checksummed (SHA-256). The archive key is wrapped with HPKE for a P-256
key that Apple publishes on wkms-public.apple.com (URL in the archive's
metadata) - restore-image key material, not a user credential.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import struct
import threading
from collections import OrderedDict
from typing import Dict, List, Optional
from urllib.parse import urlsplit

from . import aecrypto, codecs

_MAGIC = b"AEA1"
_SYMMETRIC_PROFILE = 1
_MAX_AUTH_DATA = 1 << 20
_MAX_KEY_RESPONSE = 64 << 10
_SEGMENT_CACHE = 64
_SEGMENT_HEADER = 8 + 32


class AEAError(ValueError):
    pass


def _parse_metadata(data: bytes) -> Dict[str, bytes]:
    metadata: Dict[str, bytes] = {}
    pos = 0
    while pos < len(data):
        if pos + 4 > len(data):
            raise AEAError("truncated AEA metadata")
        length = struct.unpack_from("<I", data, pos)[0]
        if length < 5 or pos + length > len(data):
            raise AEAError(f"invalid AEA metadata record length {length}")
        record = data[pos + 4:pos + length]
        key, sep, value = record.partition(b"\x00")
        if not sep or not key:
            raise AEAError("invalid AEA metadata record")
        metadata[key.decode("utf-8", "replace")] = value
        pos += length
    return metadata


def _header_key(key: bytes, info: bytes):
    derived = aecrypto.hkdf(key, None, info, 80)
    return derived[:32], derived[32:64], derived[64:80]  # mac key, AES key, IV


def _mac(key: bytes, data: bytes, salt: bytes) -> bytes:
    return aecrypto.hmac_sha256(key, salt, data, struct.pack("<Q", len(salt)))


def _symmetric_key(metadata: Dict[str, bytes], fetch) -> bytes:
    url = metadata.get("com.apple.wkms.fcs-key-url")
    if not url:
        raise AEAError("AEA metadata has no FCS key URL")
    url_text = url.decode("ascii", "replace")
    parts = urlsplit(url_text)
    if parts.scheme != "https" or parts.hostname != "wkms-public.apple.com":
        raise AEAError(f"unexpected Apple FCS key URL {url_text!r}")
    pem = fetch(url_text)
    if len(pem) > _MAX_KEY_RESPONSE:
        raise AEAError("Apple FCS key response is too large")
    private = aecrypto.p256_private_key_from_pem(pem)
    response = metadata.get("com.apple.wkms.fcs-response")
    if not response:
        raise AEAError("AEA metadata has no FCS response")
    wrapped = json.loads(response)
    encapsulated = base64.b64decode(wrapped["enc-request"])
    sealed = base64.b64decode(wrapped["wrapped-key"])
    return aecrypto.hpke_open(private, encapsulated, sealed)


class AEAReader:
    """read_at() over the decrypted, decompressed archive contents."""

    def __init__(self, source, fetch_key) -> None:
        """``source``: read_at()/size of the encrypted archive.
        ``fetch_key(url) -> bytes``: downloads the PEM key."""
        self._source = source
        header = source.read_at(0, 12)
        magic, profile, auth_length = struct.unpack("<4sII", header)
        if magic != _MAGIC:
            raise AEAError(f"invalid AEA magic {magic!r}")
        if profile & 0xFFFFFF != _SYMMETRIC_PROFILE:
            raise AEAError(f"unsupported AEA profile {profile & 0xFFFFFF}")
        if auth_length > _MAX_AUTH_DATA:
            raise AEAError("AEA authentication data is too large")
        auth_data = source.read_at(12, auth_length)
        symmetric = _symmetric_key(_parse_metadata(auth_data), fetch_key)

        salt_offset = 12 + auth_length
        main_salt = source.read_at(salt_offset, 32)
        self._main_key = aecrypto.hkdf(symmetric, main_salt, b"AEA_AMK" + struct.pack("<I", profile), len(symmetric))

        root_offset = salt_offset + 32
        encrypted_root = source.read_at(root_offset, 32 + 48 + 32)
        root_mac, root_data, cluster_mac = encrypted_root[:32], encrypted_root[32:80], encrypted_root[80:112]
        mac_key, aes_key, iv = _header_key(self._main_key, b"AEA_RHEK")
        if not hmac.compare_digest(root_mac, _mac(mac_key, root_data, cluster_mac + auth_data)):
            raise AEAError("AEA root header failed authentication (wrong key?)")
        root = aecrypto.aes_ctr(aes_key, iv, root_data)
        file_size, encrypted_size, segment_size, per_cluster, compression, checksum = struct.unpack_from("<QQIIBB", root)
        if file_size == 0 or encrypted_size != source.size or segment_size == 0 or per_cluster == 0:
            raise AEAError("invalid AEA root header")
        if compression != ord("e") or checksum != 2:
            raise AEAError(f"unsupported AEA encoding (compression {compression}, checksum {checksum})")
        self.size = file_size
        self._segment_size = segment_size
        count = (file_size + segment_size - 1) // segment_size
        # Per segment: (input offset, compressed size, decompressed size,
        # checksum, mac, cluster, index)
        self._segments: List[Optional[tuple]] = [None] * count
        self._cache: "OrderedDict[int, bytes]" = OrderedDict()
        self._lock = threading.Lock()
        self._index_clusters(root_offset + 112, cluster_mac, file_size, segment_size, per_cluster)

    def _cluster_key(self, cluster: int) -> bytes:
        return aecrypto.hkdf(self._main_key, None, b"AEA_CK" + struct.pack("<I", cluster), len(self._main_key))

    def _index_clusters(self, offset: int, cluster_mac: bytes, file_size: int, segment_size: int, per_cluster: int) -> None:
        header_size = _SEGMENT_HEADER * per_cluster + 32 + 32 * per_cluster
        produced = 0
        cluster = 0
        source_size = self._source.size
        while produced < file_size:
            if header_size > source_size - offset:
                raise AEAError("AEA cluster header extends beyond the archive")
            header = self._source.read_at(offset, header_size)
            mac_key, aes_key, iv = _header_key(self._cluster_key(cluster), b"AEA_CHEK")
            encrypted_size = _SEGMENT_HEADER * per_cluster
            encrypted = header[:encrypted_size]
            next_mac = header[encrypted_size:encrypted_size + 32]
            segment_macs = header[encrypted_size + 32:]
            if not hmac.compare_digest(cluster_mac, _mac(mac_key, encrypted, next_mac + segment_macs)):
                raise AEAError(f"AEA cluster {cluster} failed authentication")
            headers = aecrypto.aes_ctr(aes_key, iv, encrypted)
            data_offset = offset + header_size
            for index in range(per_cluster):
                decompressed, compressed = struct.unpack_from("<II", headers, index * _SEGMENT_HEADER)
                digest = headers[index * _SEGMENT_HEADER + 8:(index + 1) * _SEGMENT_HEADER]
                if decompressed == 0:
                    if compressed:
                        raise AEAError("AEA segment has data but no output")
                    continue
                if decompressed > segment_size or compressed == 0 or compressed > source_size - data_offset:
                    raise AEAError(f"AEA cluster {cluster} segment {index} has invalid sizes")
                global_index = cluster * per_cluster + index
                if global_index >= len(self._segments):
                    raise AEAError("AEA segment outside the declared output")
                if global_index * segment_size + decompressed > file_size:
                    raise AEAError("AEA segment extends beyond the declared output")
                self._segments[global_index] = (
                    data_offset, compressed, decompressed, digest, segment_macs[index * 32:(index + 1) * 32], cluster, index,
                )
                data_offset += compressed
                produced += decompressed
                if produced > file_size:
                    raise AEAError("AEA segments exceed the declared output size")
            offset = data_offset
            cluster_mac = next_mac
            cluster += 1
        if produced != file_size:
            raise AEAError(f"AEA segments hold {produced} bytes, expected {file_size}")

    def _segment(self, number: int) -> bytes:
        with self._lock:
            cached = self._cache.get(number)
            if cached is not None:
                self._cache.move_to_end(number)
                return cached
        entry = self._segments[number]
        if entry is None:
            raise AEAError(f"AEA segment {number} is missing")
        offset, compressed, decompressed, digest, mac, cluster, index = entry
        encrypted = self._source.read_at(offset, compressed)
        mac_key, aes_key, iv = _header_key(self._cluster_key(cluster), b"AEA_SK" + struct.pack("<I", index))
        if not hmac.compare_digest(mac, _mac(mac_key, encrypted, b"")):
            raise AEAError(f"AEA cluster {cluster} segment {index} failed authentication")
        plain = aecrypto.aes_ctr(aes_key, iv, encrypted)
        if compressed != decompressed:
            plain = codecs.lzfse_decompress(plain, decompressed)
            if len(plain) != decompressed:
                raise AEAError(f"AEA segment {number} decompressed to {len(plain)} bytes, expected {decompressed}")
        if hashlib.sha256(plain).digest() != digest:
            raise AEAError(f"AEA segment {number} failed checksum verification")
        with self._lock:
            self._cache[number] = plain
            while len(self._cache) > _SEGMENT_CACHE:
                self._cache.popitem(last=False)
        return plain

    def read_at(self, offset: int, length: int) -> bytes:
        if offset < 0 or offset + length > self.size:
            raise AEAError(f"read {offset}+{length} outside the archive contents")
        out = bytearray()
        position, end = offset, offset + length
        while position < end:
            number = position // self._segment_size
            segment = self._segment(number)
            inside = position - number * self._segment_size
            take = min(end - position, len(segment) - inside)
            if take <= 0:
                raise AEAError("AEA segment is shorter than expected")
            out += segment[inside:inside + take]
            position += take
        return bytes(out)
