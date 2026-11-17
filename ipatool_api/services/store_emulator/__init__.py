"""AppleMediaServices emulation for the Store's machine-verification proof.

Port of the parts of ipatool ``internal/store`` (ipatool 2.8, MIT) needed for
``StoreAMDHeaders``: AppleMediaServices' type-2 anisette provider computes the
X-Apple-AMD / X-Apple-AMD-M headers that sign-in and commerce downloads must
carry. Its XPC requests to com.apple.adid are answered by the emulated
CoreADI daemon (``sap.modern_adi``).
"""
from __future__ import annotations

from typing import Callable, Dict

from .runtime import EmulatorError, Runtime

__all__ = ["EmulatorError", "amd_headers"]


def amd_headers(media_image, endpoint: str, hardware_id: bytes,
                xpc_handler: Callable[[str, bytes], bytes]) -> Dict[str, str]:
    """anisette.go StoreAMDHeaders: run ``+[AMSAnisette _headersForRequest:
    account:type:]`` (type 2) for a request to ``endpoint``.

    ``media_image``: the AppleMediaServices segments as (address, size, data)
    tuples; ``xpc_handler(service, request) -> reply`` answers the
    framework's com.apple.adid messages."""
    from . import profile as profile_module
    from .goutil import GoURL

    try:
        parsed = GoURL.parse(endpoint)
    except ValueError as exc:
        raise EmulatorError("invalid Store AMD endpoint") from exc
    if parsed.scheme != "https" or not parsed.host:
        raise EmulatorError("invalid Store AMD endpoint")
    if len(hardware_id) != 6:
        raise EmulatorError("invalid Store AMD hardware identity")

    runtime = Runtime(media_image, profile_module.load())
    try:
        runtime.hardware_id = bytes(hardware_id)
        runtime.xpc_sync_handler = xpc_handler
        try:
            runtime.install_store_amd_adapter()
            url = runtime.new("NSURL", parsed.string())
        except Exception as exc:  # noqa: BLE001 - setup panics, as upstream's recover
            raise EmulatorError(f"prepare Store AMD request: {exc}") from exc
        try:
            request = runtime.invoke(runtime.class_address("NSURLRequest"), "requestWithURL:", url)
        except EmulatorError as exc:
            raise EmulatorError(f"create Store AMD request: {exc}") from exc
        try:
            value = runtime.invoke(runtime.class_address("AMSAnisette"), "_headersForRequest:account:type:", request, 0, 2)
        except EmulatorError as exc:
            raise EmulatorError(f"generate Store AMD proof: {exc}") from exc
        exported = runtime.export(value)
        if not isinstance(exported, dict):
            raise EmulatorError(f"AppleMediaServices returned no Store AMD proof ({type(exported).__name__})")
        result = {}
        for key in ("X-Apple-AMD", "X-Apple-AMD-M"):
            text = exported.get(key)
            if not isinstance(text, str) or not text or len(text) > 8192 or "\r" in text or "\n" in text:
                raise EmulatorError("AppleMediaServices returned an incomplete Store AMD proof")
            result[key] = text
        return result
    finally:
        runtime.close()
