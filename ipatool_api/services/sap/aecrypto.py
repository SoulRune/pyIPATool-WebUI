"""Cryptography for reading Apple Encrypted Archives (AEA) - no hard dependency.

What ipatool's assets/aea.go needs from Go's standard library, here:

- HKDF-SHA256 and HMAC-SHA256 (stdlib ``hmac``/``hashlib``);
- AES-256-CTR over a few hundred MB of archive segments - this has to be
  native code, so the first available of: the ``cryptography`` package,
  Apple's CommonCrypto (macOS / jailbroken iOS), OpenSSL's libcrypto
  (Linux, Android/Termux), Windows CNG (bcrypt.dll); a pure-Python AES is the
  last resort (correct, but far too slow for the full asset download);
- HPKE (RFC 9180) base-mode "open" with DHKEM(P-256, HKDF-SHA256) and
  AES-256-GCM, to unwrap the archive key with the private key Apple publishes
  for it - one small operation, done in pure Python;
- reading that PEM / PKCS#8 P-256 private key.
"""
from __future__ import annotations

import base64
import ctypes
import ctypes.util
import hashlib
import hmac
import logging
import os
import sys
from typing import Callable, Optional

logger = logging.getLogger(__name__)


class CryptoError(ValueError):
    pass


# ---------------------------------------------------------------------------
# HKDF / HMAC
# ---------------------------------------------------------------------------


def hkdf_extract(salt: Optional[bytes], ikm: bytes) -> bytes:
    return hmac.new(salt or b"\x00" * 32, ikm, hashlib.sha256).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    output, block, counter = b"", b"", 1
    while len(output) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        output += block
        counter += 1
    return output[:length]


def hkdf(key: bytes, salt: Optional[bytes], info: bytes, length: int) -> bytes:
    return hkdf_expand(hkdf_extract(salt, key), info, length)


def hmac_sha256(key: bytes, *parts: bytes) -> bytes:
    mac = hmac.new(key, digestmod=hashlib.sha256)
    for part in parts:
        mac.update(part)
    return mac.digest()


# ---------------------------------------------------------------------------
# Pure-Python AES (encryption direction only - CTR and GCM need nothing else)
# ---------------------------------------------------------------------------


def _build_tables():
    sbox = [0] * 256
    p = q = 1
    while True:
        p = p ^ ((p << 1) & 0xFF) ^ (0x1B if p & 0x80 else 0)
        q ^= q << 1
        q ^= q << 2
        q ^= q << 4
        q &= 0xFF
        if q & 0x80:
            q ^= 0x09
        x = q ^ (q << 1 | q >> 7) ^ (q << 2 | q >> 6) ^ (q << 3 | q >> 5) ^ (q << 4 | q >> 4)
        sbox[p] = (x ^ 0x63) & 0xFF
        if p == 1:
            break
    sbox[0] = 0x63

    def xtime(v):
        return ((v << 1) ^ 0x1B) & 0xFF if v & 0x80 else v << 1

    t0 = []
    for value in sbox:
        two = xtime(value)
        three = two ^ value
        t0.append((two << 24) | (value << 16) | (value << 8) | three)
    t1 = [((w >> 8) | (w << 24)) & 0xFFFFFFFF for w in t0]
    t2 = [((w >> 16) | (w << 16)) & 0xFFFFFFFF for w in t0]
    t3 = [((w >> 24) | (w << 8)) & 0xFFFFFFFF for w in t0]
    return sbox, t0, t1, t2, t3


_SBOX, _T0, _T1, _T2, _T3 = _build_tables()


class _PureAES:
    def __init__(self, key: bytes) -> None:
        if len(key) not in (16, 24, 32):
            raise CryptoError("AES key must be 16, 24 or 32 bytes")
        nk = len(key) // 4
        self._rounds = nk + 6
        words = [int.from_bytes(key[i:i + 4], "big") for i in range(0, len(key), 4)]
        rcon = 1
        for i in range(nk, 4 * (self._rounds + 1)):
            temp = words[i - 1]
            if i % nk == 0:
                temp = ((temp << 8) | (temp >> 24)) & 0xFFFFFFFF
                temp = (_SBOX[temp >> 24] << 24) | (_SBOX[(temp >> 16) & 0xFF] << 16) | (_SBOX[(temp >> 8) & 0xFF] << 8) | _SBOX[temp & 0xFF]
                temp ^= rcon << 24
                rcon = ((rcon << 1) ^ 0x11B) if rcon & 0x80 else rcon << 1
            elif nk > 6 and i % nk == 4:
                temp = (_SBOX[temp >> 24] << 24) | (_SBOX[(temp >> 16) & 0xFF] << 16) | (_SBOX[(temp >> 8) & 0xFF] << 8) | _SBOX[temp & 0xFF]
            words.append(words[i - nk] ^ temp)
        self._keys = words

    def encrypt_block(self, block: bytes) -> bytes:
        k = self._keys
        s0 = int.from_bytes(block[0:4], "big") ^ k[0]
        s1 = int.from_bytes(block[4:8], "big") ^ k[1]
        s2 = int.from_bytes(block[8:12], "big") ^ k[2]
        s3 = int.from_bytes(block[12:16], "big") ^ k[3]
        t0, t1, t2, t3 = _T0, _T1, _T2, _T3
        for r in range(1, self._rounds):
            o = 4 * r
            s0, s1, s2, s3 = (
                t0[s0 >> 24] ^ t1[(s1 >> 16) & 0xFF] ^ t2[(s2 >> 8) & 0xFF] ^ t3[s3 & 0xFF] ^ k[o],
                t0[s1 >> 24] ^ t1[(s2 >> 16) & 0xFF] ^ t2[(s3 >> 8) & 0xFF] ^ t3[s0 & 0xFF] ^ k[o + 1],
                t0[s2 >> 24] ^ t1[(s3 >> 16) & 0xFF] ^ t2[(s0 >> 8) & 0xFF] ^ t3[s1 & 0xFF] ^ k[o + 2],
                t0[s3 >> 24] ^ t1[(s0 >> 16) & 0xFF] ^ t2[(s1 >> 8) & 0xFF] ^ t3[s2 & 0xFF] ^ k[o + 3],
            )
        o = 4 * self._rounds
        sb = _SBOX
        out = b""
        for a, b, c, d, kk in ((s0, s1, s2, s3, k[o]), (s1, s2, s3, s0, k[o + 1]), (s2, s3, s0, s1, k[o + 2]), (s3, s0, s1, s2, k[o + 3])):
            word = (sb[a >> 24] << 24) | (sb[(b >> 16) & 0xFF] << 16) | (sb[(c >> 8) & 0xFF] << 8) | sb[d & 0xFF]
            out += (word ^ kk).to_bytes(4, "big")
        return out


def _counter_blocks(iv: bytes, count: int) -> bytes:
    start = int.from_bytes(iv, "big")
    mask = (1 << 128) - 1
    return b"".join(((start + i) & mask).to_bytes(16, "big") for i in range(count))


def _xor(data: bytes, keystream: bytes) -> bytes:
    n = len(data)
    return (int.from_bytes(data, "little") ^ int.from_bytes(keystream[:n], "little")).to_bytes(n, "little")


def _pure_ctr(key: bytes, iv: bytes, data: bytes) -> bytes:
    aes = _PureAES(key)
    blocks = (len(data) + 15) // 16
    counters = _counter_blocks(iv, blocks)
    stream = b"".join(aes.encrypt_block(counters[i:i + 16]) for i in range(0, len(counters), 16))
    return _xor(data, stream)


# ---------------------------------------------------------------------------
# Native AES-CTR backends
# ---------------------------------------------------------------------------


def _cryptography_ctr() -> Optional[Callable[[bytes, bytes, bytes], bytes]]:
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # type: ignore
    except Exception:  # noqa: BLE001 - not installed / broken native build
        return None

    def ctr(key: bytes, iv: bytes, data: bytes) -> bytes:
        decryptor = Cipher(algorithms.AES(key), modes.CTR(iv)).decryptor()
        return decryptor.update(data) + decryptor.finalize()

    return ctr


def _commoncrypto_ctr() -> Optional[Callable[[bytes, bytes, bytes], bytes]]:
    if sys.platform not in ("darwin", "ios"):
        return None
    try:
        lib = ctypes.CDLL(ctypes.util.find_library("System") or "/usr/lib/libSystem.B.dylib")
        create = lib.CCCryptorCreateWithMode
        update = lib.CCCryptorUpdate
        release = lib.CCCryptorRelease
    except (OSError, AttributeError):
        return None
    create.restype = ctypes.c_int32
    create.argtypes = [ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_char_p,
                       ctypes.c_char_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int,
                       ctypes.c_uint32, ctypes.POINTER(ctypes.c_void_p)]
    update.restype = ctypes.c_int32
    update.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t,
                       ctypes.POINTER(ctypes.c_size_t)]
    release.argtypes = [ctypes.c_void_p]

    k_cc_encrypt, k_cc_mode_ctr, k_cc_aes, cc_no_padding, k_ctr_be = 0, 4, 0, 0, 2

    def ctr(key: bytes, iv: bytes, data: bytes) -> bytes:
        ref = ctypes.c_void_p()
        status = create(k_cc_encrypt, k_cc_mode_ctr, k_cc_aes, cc_no_padding, iv, key, len(key), None, 0, 0,
                        k_ctr_be, ctypes.byref(ref))
        if status != 0:
            raise CryptoError(f"CommonCrypto AES-CTR setup failed ({status})")
        try:
            out = ctypes.create_string_buffer(len(data))
            moved = ctypes.c_size_t()
            status = update(ref, data, len(data), out, len(data), ctypes.byref(moved))
            if status != 0 or moved.value != len(data):
                raise CryptoError(f"CommonCrypto AES-CTR failed ({status})")
            return out.raw
        finally:
            release(ref)

    return ctr


def _libcrypto_ctr() -> Optional[Callable[[bytes, bytes, bytes], bytes]]:
    if sys.platform == "win32":
        return None
    if sys.platform in ("darwin", "ios"):
        # Never the system /usr/lib/libcrypto.dylib: macOS aborts processes
        # that load it. Only Procursus / Homebrew OpenSSL.
        names = ["/var/jb/usr/lib/libcrypto.3.dylib", "/usr/lib/libcrypto.3.dylib" if os.path.isdir("/var/mobile") else None,
                 "/opt/homebrew/opt/openssl@3/lib/libcrypto.3.dylib", "/usr/local/opt/openssl@3/lib/libcrypto.3.dylib"]
    else:
        names = [ctypes.util.find_library("crypto"), "libcrypto.so.3", "libcrypto.so.1.1", "libcrypto.so"]
    prefix = os.environ.get("PREFIX")  # Termux
    if prefix:
        names += [os.path.join(prefix, "lib", "libcrypto.so.3"), os.path.join(prefix, "lib", "libcrypto.so")]
    lib = None
    for name in names:
        if not name:
            continue
        try:
            lib = ctypes.CDLL(name)
            lib.EVP_aes_256_ctr  # noqa: B018 - probe
            break
        except (OSError, AttributeError):
            lib = None
    if lib is None:
        return None
    lib.EVP_CIPHER_CTX_new.restype = ctypes.c_void_p
    lib.EVP_CIPHER_CTX_free.argtypes = [ctypes.c_void_p]
    lib.EVP_aes_256_ctr.restype = ctypes.c_void_p
    lib.EVP_aes_128_ctr.restype = ctypes.c_void_p
    lib.EVP_EncryptInit_ex.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]
    lib.EVP_EncryptInit_ex.restype = ctypes.c_int
    lib.EVP_EncryptUpdate.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_int), ctypes.c_char_p, ctypes.c_int]
    lib.EVP_EncryptUpdate.restype = ctypes.c_int

    def ctr(key: bytes, iv: bytes, data: bytes) -> bytes:
        cipher = lib.EVP_aes_256_ctr() if len(key) == 32 else lib.EVP_aes_128_ctr()
        context = lib.EVP_CIPHER_CTX_new()
        if not context:
            raise CryptoError("libcrypto: cannot allocate a cipher context")
        try:
            if lib.EVP_EncryptInit_ex(context, cipher, None, key, iv) != 1:
                raise CryptoError("libcrypto AES-CTR setup failed")
            out = ctypes.create_string_buffer(len(data) + 16)
            written = ctypes.c_int()
            if lib.EVP_EncryptUpdate(context, out, ctypes.byref(written), data, len(data)) != 1:
                raise CryptoError("libcrypto AES-CTR failed")
            return out.raw[:written.value]
        finally:
            lib.EVP_CIPHER_CTX_free(context)

    return ctr


def _bcrypt_ctr() -> Optional[Callable[[bytes, bytes, bytes], bytes]]:
    if sys.platform != "win32":
        return None
    try:
        bcrypt = ctypes.WinDLL("bcrypt")
    except OSError:
        return None
    handle = ctypes.c_void_p
    bcrypt.BCryptOpenAlgorithmProvider.argtypes = [ctypes.POINTER(handle), ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_ulong]
    bcrypt.BCryptSetProperty.argtypes = [handle, ctypes.c_wchar_p, ctypes.c_void_p, ctypes.c_ulong, ctypes.c_ulong]
    bcrypt.BCryptGenerateSymmetricKey.argtypes = [handle, ctypes.POINTER(handle), ctypes.c_void_p, ctypes.c_ulong,
                                                  ctypes.c_char_p, ctypes.c_ulong, ctypes.c_ulong]
    bcrypt.BCryptEncrypt.argtypes = [handle, ctypes.c_char_p, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_void_p,
                                     ctypes.c_ulong, ctypes.c_void_p, ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong), ctypes.c_ulong]
    bcrypt.BCryptDestroyKey.argtypes = [handle]
    algorithm = handle()
    if bcrypt.BCryptOpenAlgorithmProvider(ctypes.byref(algorithm), "AES", None, 0) != 0:
        return None
    mode = ctypes.create_unicode_buffer("ChainingModeECB")
    if bcrypt.BCryptSetProperty(algorithm, "ChainingMode", mode, ctypes.sizeof(mode), 0) != 0:
        return None

    def ctr(key: bytes, iv: bytes, data: bytes) -> bytes:
        key_handle = handle()
        if bcrypt.BCryptGenerateSymmetricKey(algorithm, ctypes.byref(key_handle), None, 0, key, len(key), 0) != 0:
            raise CryptoError("CNG: cannot create the AES key")
        try:
            counters = _counter_blocks(iv, (len(data) + 15) // 16)
            out = ctypes.create_string_buffer(len(counters))
            done = ctypes.c_ulong()
            if bcrypt.BCryptEncrypt(key_handle, counters, len(counters), None, None, 0, out, len(counters),
                                    ctypes.byref(done), 0) != 0:
                raise CryptoError("CNG AES encryption failed")
            return _xor(data, out.raw)
        finally:
            bcrypt.BCryptDestroyKey(key_handle)

    return ctr


_CTR_IMPL: Optional[Callable[[bytes, bytes, bytes], bytes]] = None
_CTR_NAME = ""


def _select_ctr():
    global _CTR_IMPL, _CTR_NAME
    if _CTR_IMPL is not None:
        return _CTR_IMPL
    probe_key, probe_iv = bytes(range(32)), bytes(range(16, 32))
    expected = _pure_ctr(probe_key, probe_iv, b"pyIPATool AES-CTR self-test, 2 blocks+")
    for name, factory in (("cryptography", _cryptography_ctr), ("CommonCrypto", _commoncrypto_ctr),
                          ("libcrypto", _libcrypto_ctr), ("Windows CNG", _bcrypt_ctr)):
        try:
            impl = factory()
            if impl is not None and impl(probe_key, probe_iv, b"pyIPATool AES-CTR self-test, 2 blocks+") == expected:
                _CTR_IMPL, _CTR_NAME = impl, name
                logger.debug("AES-CTR backend: %s", name)
                return impl
        except Exception as exc:  # noqa: BLE001 - try the next backend
            logger.debug("AES backend %s unusable: %s", name, exc)
    logger.warning("no native AES found (install the 'cryptography' package); using a very slow pure-Python AES")
    _CTR_IMPL, _CTR_NAME = _pure_ctr, "pure Python"
    return _pure_ctr


def aes_ctr(key: bytes, iv: bytes, data: bytes) -> bytes:
    """AES-CTR (whole 16-byte IV as the big-endian counter block, like Go's cipher.NewCTR)."""
    if not data:
        return b""
    return _select_ctr()(key, iv, data)


def aes_backend() -> str:
    _select_ctr()
    return _CTR_NAME


# ---------------------------------------------------------------------------
# AES-GCM decryption (small messages only)
# ---------------------------------------------------------------------------


def _gf_mult(x: int, y: int) -> int:
    r = 0xE1 << 120
    z = 0
    for i in range(127, -1, -1):
        if (y >> i) & 1:
            z ^= x
        x = (x >> 1) ^ r if x & 1 else x >> 1
    return z


def _ghash(h: int, aad: bytes, ciphertext: bytes) -> int:
    def blocks(data: bytes):
        for i in range(0, len(data), 16):
            yield data[i:i + 16].ljust(16, b"\x00")

    y = 0
    for block in list(blocks(aad)) + list(blocks(ciphertext)):
        y = _gf_mult(y ^ int.from_bytes(block, "big"), h)
    lengths = (len(aad) * 8).to_bytes(8, "big") + (len(ciphertext) * 8).to_bytes(8, "big")
    return _gf_mult(y ^ int.from_bytes(lengths, "big"), h)


def aes_gcm_open(key: bytes, nonce: bytes, sealed: bytes, aad: bytes = b"") -> bytes:
    if len(nonce) != 12 or len(sealed) < 16:
        raise CryptoError("invalid AES-GCM input")
    ciphertext, tag = sealed[:-16], sealed[-16:]
    aes = _PureAES(key)
    h = int.from_bytes(aes.encrypt_block(b"\x00" * 16), "big")
    j0 = nonce + b"\x00\x00\x00\x01"
    expected = (_ghash(h, aad, ciphertext) ^ int.from_bytes(aes.encrypt_block(j0), "big")).to_bytes(16, "big")
    if not hmac.compare_digest(expected, tag):
        raise CryptoError("AES-GCM authentication failed")
    counter = (int.from_bytes(j0, "big") + 1).to_bytes(16, "big")
    return _pure_ctr(key, counter, ciphertext)


# ---------------------------------------------------------------------------
# P-256
# ---------------------------------------------------------------------------

_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
_A = _P - 3
_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
_G = (0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
      0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5)


def _point_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2:
        if (y1 + y2) % _P == 0:
            return None
        slope = (3 * x1 * x1 + _A) * pow(2 * y1, -1, _P) % _P
    else:
        slope = (y2 - y1) * pow(x2 - x1, -1, _P) % _P
    x3 = (slope * slope - x1 - x2) % _P
    return x3, (slope * (x1 - x3) - y1) % _P


def _scalar_mult(k: int, point):
    result = None
    addend = point
    while k:
        if k & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        k >>= 1
    return result


def _decode_point(data: bytes):
    if len(data) != 65 or data[0] != 4:
        raise CryptoError("expected an uncompressed P-256 point")
    x, y = int.from_bytes(data[1:33], "big"), int.from_bytes(data[33:], "big")
    if (y * y - (x * x * x + _A * x + _B)) % _P:
        raise CryptoError("point is not on P-256")
    return x, y


def _encode_point(point) -> bytes:
    return b"\x04" + point[0].to_bytes(32, "big") + point[1].to_bytes(32, "big")


# ---------------------------------------------------------------------------
# PEM / PKCS#8 (just enough DER for an EC private key)
# ---------------------------------------------------------------------------


def _der_read(data: bytes, offset: int):
    tag = data[offset]
    length = data[offset + 1]
    offset += 2
    if length & 0x80:
        count = length & 0x7F
        length = int.from_bytes(data[offset:offset + count], "big")
        offset += count
    return tag, data[offset:offset + length], offset + length


def _der_children(data: bytes):
    offset, children = 0, []
    while offset < len(data):
        tag, value, offset = _der_read(data, offset)
        children.append((tag, value))
    return children


_OID_EC_PUBLIC_KEY = bytes.fromhex("2a8648ce3d0201")
_OID_P256 = bytes.fromhex("2a8648ce3d030107")


def p256_private_key_from_pem(pem: bytes) -> int:
    text = pem.decode("ascii", "replace")
    if "-----BEGIN" not in text:
        raise CryptoError("key is not PEM encoded")
    body = "".join(line for line in text.splitlines() if line and not line.startswith("-----"))
    der = base64.b64decode(body)
    tag, value, _ = _der_read(der, 0)
    if tag != 0x30:
        raise CryptoError("invalid PKCS#8 key")
    items = _der_children(value)
    if len(items) >= 3 and items[1][0] == 0x30:  # PKCS#8 PrivateKeyInfo
        algorithm = _der_children(items[1][1])
        if not algorithm or algorithm[0][1] != _OID_EC_PUBLIC_KEY or len(algorithm) < 2 or algorithm[1][1] != _OID_P256:
            raise CryptoError("key is not a P-256 key")
        tag, ec_key, _ = _der_read(items[2][1], 0)
        items = _der_children(ec_key)
    # ECPrivateKey: version, privateKey OCTET STRING, ...
    if len(items) < 2 or items[1][0] != 0x04:
        raise CryptoError("invalid EC private key")
    scalar = int.from_bytes(items[1][1], "big")
    if not 0 < scalar < _N:
        raise CryptoError("invalid EC private key scalar")
    return scalar


# ---------------------------------------------------------------------------
# HPKE base mode, DHKEM(P-256, HKDF-SHA256) / HKDF-SHA256 / AES-256-GCM
# ---------------------------------------------------------------------------

_KEM_ID, _KDF_ID, _AEAD_ID = 0x0010, 0x0001, 0x0002


def _labeled_extract(suite: bytes, salt: bytes, label: bytes, ikm: bytes) -> bytes:
    return hkdf_extract(salt, b"HPKE-v1" + suite + label + ikm)


def _labeled_expand(suite: bytes, prk: bytes, label: bytes, info: bytes, length: int) -> bytes:
    return hkdf_expand(prk, length.to_bytes(2, "big") + b"HPKE-v1" + suite + label + info, length)


def hpke_open(private_scalar: int, encapsulated: bytes, sealed: bytes, info: bytes = b"", aad: bytes = b"") -> bytes:
    kem_suite = b"KEM" + _KEM_ID.to_bytes(2, "big")
    ephemeral = _decode_point(encapsulated)
    shared = _scalar_mult(private_scalar, ephemeral)
    if shared is None:
        raise CryptoError("invalid HPKE encapsulation")
    dh = shared[0].to_bytes(32, "big")
    recipient = _encode_point(_scalar_mult(private_scalar, _G))
    kem_context = encapsulated + recipient
    eae_prk = _labeled_extract(kem_suite, b"", b"eae_prk", dh)
    shared_secret = _labeled_expand(kem_suite, eae_prk, b"shared_secret", kem_context, 32)

    suite = b"HPKE" + _KEM_ID.to_bytes(2, "big") + _KDF_ID.to_bytes(2, "big") + _AEAD_ID.to_bytes(2, "big")
    psk_id_hash = _labeled_extract(suite, b"", b"psk_id_hash", b"")
    info_hash = _labeled_extract(suite, b"", b"info_hash", info)
    context = b"\x00" + psk_id_hash + info_hash
    secret = _labeled_extract(suite, shared_secret, b"secret", b"")
    key = _labeled_expand(suite, secret, b"key", context, 32)
    nonce = _labeled_expand(suite, secret, b"base_nonce", context, 12)
    return aes_gcm_open(key, nonce, sealed, aad)
