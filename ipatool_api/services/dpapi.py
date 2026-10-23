"""Windows DPAPI via ctypes: data readable only by the same user on the same
machine. ``available()`` is False elsewhere."""
from __future__ import annotations

import sys

_ENTROPY = b"pyipatool-keychain-v1"
_CRYPTPROTECT_UI_FORBIDDEN = 0x01


class DPAPIError(OSError):
    pass


def available() -> bool:
    return sys.platform == "win32"


def _api():
    import ctypes
    from ctypes import wintypes

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    p_blob = ctypes.POINTER(DATA_BLOB)
    crypt32.CryptProtectData.argtypes = [
        p_blob, wintypes.LPCWSTR, p_blob, ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, p_blob,
    ]
    crypt32.CryptProtectData.restype = wintypes.BOOL
    crypt32.CryptUnprotectData.argtypes = [
        p_blob, ctypes.c_void_p, p_blob, ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, p_blob,
    ]
    crypt32.CryptUnprotectData.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p
    return ctypes, DATA_BLOB, crypt32, kernel32


def _call(fn_name: str, data: bytes) -> bytes:
    ctypes, DATA_BLOB, crypt32, kernel32 = _api()
    in_buf = ctypes.create_string_buffer(data, len(data))
    ent_buf = ctypes.create_string_buffer(_ENTROPY, len(_ENTROPY))
    blob_in = DATA_BLOB(len(data), ctypes.cast(in_buf, ctypes.POINTER(ctypes.c_char)))
    blob_ent = DATA_BLOB(len(_ENTROPY), ctypes.cast(ent_buf, ctypes.POINTER(ctypes.c_char)))
    blob_out = DATA_BLOB()
    if fn_name == "protect":
        ok = crypt32.CryptProtectData(
            ctypes.byref(blob_in), "pyIPATool", ctypes.byref(blob_ent), None, None,
            _CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(blob_out),
        )
    else:
        ok = crypt32.CryptUnprotectData(
            ctypes.byref(blob_in), None, ctypes.byref(blob_ent), None, None,
            _CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(blob_out),
        )
    if not ok:
        raise DPAPIError(f"DPAPI {fn_name} failed (Windows error {ctypes.get_last_error()})")
    try:
        return ctypes.string_at(blob_out.pbData, blob_out.cbData)
    finally:
        kernel32.LocalFree(ctypes.cast(blob_out.pbData, ctypes.c_void_p))


def protect(data: bytes) -> bytes:
    return _call("protect", data)


def unprotect(data: bytes) -> bytes:
    return _call("unprotect", data)
