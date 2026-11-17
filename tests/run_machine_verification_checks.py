"""Machine verification (ipatool 2.8) building blocks that run without Apple's
files: the shipped Store profile, AES-CBC for the emulated IOAES service,
pointer-authentication stripping, IM4P parsing and the Swift hasher.
Run: python tests/run_machine_verification_checks.py  (prints MACHINE VERIFICATION OK)
"""
import os
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from ipatool_api.services.sap import kernel, macho  # noqa: E402
from ipatool_api.services.sap.aecrypto import aes_cbc_decrypt, aes_cbc_encrypt  # noqa: E402
from ipatool_api.services.sap.errors import SAPError  # noqa: E402
from ipatool_api.services.sap.shim_platform import COMMERCE_AES_HANDLE, emulate_ioaes  # noqa: E402
from ipatool_api.services.store_emulator import profile  # noqa: E402
from ipatool_api.services.store_emulator.goutil import GoURL, canonical_header_key, path_clean  # noqa: E402
from ipatool_api.services.store_emulator.gotypes import GoTime  # noqa: E402

# Store profile: ipatool's pinned parts, decoded and verified
loaded = profile.load()
assert loaded.metadata.classes and loaded.metadata.calls and loaded.metadata.code_ranges
assert 0x1A2D0FB94 in loaded.metadata.calls  # the lazy-import thunk added at load
assert len(loaded.pages) == len(loaded.metadata.page_offsets) * 4096

# AES-CBC (FIPS-197 / SP 800-38A F.2.1 vector)
key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
plain = bytes.fromhex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51")
cipher = bytes.fromhex("7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b2")
assert aes_cbc_encrypt(key, iv, plain) == cipher and aes_cbc_decrypt(key, iv, cipher) == plain
handle = b"\0" * 36 + struct.pack("<I", COMMERCE_AES_HANDLE)
out, next_iv = emulate_ioaes(plain, iv, 0, handle)
assert out == aes_cbc_encrypt(bytes(16), iv, plain) and next_iv == out[-16:]
assert emulate_ioaes(out, iv, 1, handle) == (plain, out[-16:])
try:
    emulate_ioaes(plain, iv, 0, b"\0" * 40)
    raise SystemExit("accepted an unknown IOAES key handle")
except SAPError:
    pass

# pointer authentication: the regex prefilter finds every rewritten instruction
words = [0xD71F0A11, 0xD73F0C00, 0xDAC10800, 0xD65F0BFF, 0xD503237F, 0xDAC143E5, 0xD61F0200, 0xAA0103E0]
data = bytearray(b"\0\0\0\0" + struct.pack(f"<{len(words)}I", *words))
macho._strip_pointer_authentication(data, [(4, len(data))])
assert list(struct.unpack_from(f"<{len(words)}I", data, 4)) == [macho.without_pointer_authentication(w) for w in words]
assert struct.unpack_from("<I", data, 4)[0] == 0xD61F0200  # braa x16, x17 -> br x16
assert struct.unpack_from("<I", data, 4 + 4 * 7)[0] == 0xAA0103E0  # unrelated instruction untouched

# IM4P container
payload = b"payload-bytes"
fields = b"".join(bytes([tag, len(value)]) + value for tag, value in
                  ((0x16, b"IM4P"), (0x16, b"krnl"), (0x16, b"desc"), (0x04, payload)))
assert kernel.im4p_payload(bytes([0x30, len(fields)]) + fields) == payload
try:
    kernel.im4p_payload(bytes([0x30, len(fields) + 1]) + fields)
    raise SystemExit("accepted a truncated IM4P")
except SAPError:
    pass

# Go behaviour the bridge reproduces
assert canonical_header_key("x-apple-amd-m") == "X-Apple-Amd-M"
assert path_clean("/a/./b/../c//") == "/a/c"
url = GoURL.parse("https://auth.itunes.apple.com/auth/v1/native?x=1")
assert (url.scheme, url.hostname(), url.path, url.raw_query) == ("https", "auth.itunes.apple.com", "/auth/v1/native", "x=1")
assert url.string() == "https://auth.itunes.apple.com/auth/v1/native?x=1"
assert GoTime.date(4001, 1, 1).seconds == 64092211200
assert GoTime(1762845306, 5).http_date() == "Tue, 11 Nov 2025 07:15:06 GMT"
print("MACHINE VERIFICATION OK")
