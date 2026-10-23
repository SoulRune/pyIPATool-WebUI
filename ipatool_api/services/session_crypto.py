"""Authenticated encryption for session cookies: AES-256-GCM when the
``cryptography`` package is installed, otherwise standard library only
(HMAC-SHA256 CTR, encrypt-then-MAC). Both formats are always readable.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import struct
import zlib

try:  # pragma: no cover - depends on the environment
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # type: ignore
except Exception:  # noqa: BLE001 - ImportError, or a broken native build
    AESGCM = None  # type: ignore[assignment]

_V_AESGCM = 1
_V_HMAC_CTR = 2


class SessionDecryptError(Exception):
    pass


def _derive(key: bytes, label: bytes) -> bytes:
    return hmac.new(key, b"pyipatool-session|" + label, hashlib.sha256).digest()


def _keystream_xor(key: bytes, nonce: bytes, data: bytes) -> bytes:
    blocks = []
    for counter in range((len(data) + 31) // 32):
        blocks.append(hmac.new(key, nonce + struct.pack(">Q", counter), hashlib.sha256).digest())
    stream = b"".join(blocks)[: len(data)]
    return (int.from_bytes(data, "big") ^ int.from_bytes(stream, "big")).to_bytes(len(data), "big")


class SessionCipher:
    def __init__(self, secret: bytes, stdlib_only: bool = False) -> None:
        """``stdlib_only``: always write the pure-stdlib format (readable by
        any Python, with or without ``cryptography``) - the master-password
        vault uses it so its files open on every platform."""
        if len(secret) < 32:
            raise ValueError("session secret must be at least 32 bytes")
        self._stdlib_only = stdlib_only
        self._aead_key = _derive(secret, b"aesgcm")
        self._ctr_key = _derive(secret, b"ctr")
        self._mac_key = _derive(secret, b"mac")

    @property
    def backend(self) -> str:
        if AESGCM is not None and not self._stdlib_only:
            return "AES-256-GCM"
        return "HMAC-SHA256-CTR + HMAC-SHA256 (stdlib)"

    def seal(self, plaintext: bytes) -> bytes:
        data = zlib.compress(plaintext, 9)
        if AESGCM is not None and not self._stdlib_only:
            nonce = secrets.token_bytes(12)
            header = bytes([_V_AESGCM])
            return header + nonce + AESGCM(self._aead_key).encrypt(nonce, data, header)
        nonce = secrets.token_bytes(16)
        header = bytes([_V_HMAC_CTR])
        ciphertext = _keystream_xor(self._ctr_key, nonce, data)
        tag = hmac.new(self._mac_key, header + nonce + ciphertext, hashlib.sha256).digest()
        return header + nonce + ciphertext + tag

    def open(self, blob: bytes) -> bytes:
        if not blob:
            raise SessionDecryptError("empty")
        version = blob[0]
        if version == _V_AESGCM:
            if AESGCM is None:
                raise SessionDecryptError("AES-GCM session but 'cryptography' is not installed")
            if len(blob) < 1 + 12 + 16:
                raise SessionDecryptError("truncated")
            try:
                data = AESGCM(self._aead_key).decrypt(blob[1:13], blob[13:], blob[:1])
            except Exception as exc:  # noqa: BLE001 - InvalidTag and friends
                raise SessionDecryptError("authentication failed") from exc
        elif version == _V_HMAC_CTR:
            if len(blob) < 1 + 16 + 32:
                raise SessionDecryptError("truncated")
            nonce, ciphertext, tag = blob[1:17], blob[17:-32], blob[-32:]
            expected = hmac.new(self._mac_key, blob[:17] + ciphertext, hashlib.sha256).digest()
            if not hmac.compare_digest(tag, expected):
                raise SessionDecryptError("authentication failed")
            data = _keystream_xor(self._ctr_key, nonce, ciphertext)
        else:
            raise SessionDecryptError("unknown format")
        try:
            return zlib.decompress(data)
        except zlib.error as exc:
            raise SessionDecryptError("corrupt payload") from exc
