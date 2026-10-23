"""SAP action signer: the public entry point of this package.

Port of ``internal/sap/signer.go`` + ``signer_local.go`` (ipatool v2.6.0,
MIT). Creating a Signer loads the Apple frameworks into the emulator and runs
the setup handshake; ``sign(body)`` then returns the ``X-Apple-ActionSignature``
value for that request body. One Signer is single-use per login and must be
closed afterwards.
"""
from __future__ import annotations

import logging
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .assets import Bundle, load as load_assets
from .errors import SAPError, SAPUnavailableError

logger = logging.getLogger(__name__)

SUPPORTED_VERSION = 200


def unicorn_install_hint() -> str:
    """How to get Unicorn on *this* platform - prebuilt wheels exist only for
    Windows, macOS and glibc/musl Linux on x86/x86_64/aarch64."""
    import os
    import platform
    import sys

    machine = (platform.machine() or "").lower()
    if "com.termux" in os.environ.get("PREFIX", "") or sys.platform == "android":
        return ("on Android/Termux install the build tools ('pkg install clang cmake make') and run "
                "'pip install -r requirements-android.txt' from the project folder - it builds Unicorn from vendor/unicorn")
    if sys.platform == "ios" or machine.startswith(("iphone", "ipad", "ipod")):
        return ("on jailbroken iOS run 'python3 vendor/unicorn/ios/check_deps.py' (lists the packages to install "
                "and their repositories), then 'pip install -r requirements-ios.txt' from the project folder")
    if sys.platform.startswith("linux") and machine.startswith(("armv6", "armv7", "arm")) and "64" not in machine:
        return ("32-bit ARM Linux (e.g. older Raspberry Pi OS) has no prebuilt Unicorn on PyPI: "
                "install build tools ('sudo apt install cmake build-essential') and run "
                "'pip install unicorn' (it compiles from source - this can take a long time)")
    if sys.platform.startswith("linux"):
        return ("run 'pip install unicorn'; if no prebuilt build matches this system, install cmake "
                "and a C compiler first (e.g. 'sudo apt install cmake build-essential')")
    return "run 'pip install unicorn'"


def unicorn_available() -> bool:
    try:
        import unicorn  # noqa: F401
    except Exception:  # noqa: BLE001 - ImportError or a broken native build
        return False
    return True


@dataclass
class SignerConfig:
    setup_url: str
    certificate_url: str
    version: int
    hardware_id: bytes


class Signer:
    def __init__(self, config: SignerConfig, cache_dir: Optional[Path] = None, verify=True) -> None:
        _validate_config(config)
        if not unicorn_available():
            raise SAPUnavailableError(
                "App Store sign-in needs the 'unicorn' package, which isn't installed: " + unicorn_install_hint()
            )

        # Imported lazily so the rest of the app runs without unicorn installed.
        from .machine import Machine
        from .protocol import SetupProtocol

        self._lock = threading.Lock()
        self._closed = False
        self._hardware = bytes(config.hardware_id)
        self._machine: Optional[Machine] = None
        self._context = 0

        bundle: Bundle = load_assets(cache_dir=cache_dir, verify=verify)

        machine = Machine(bundle)
        complete = False
        try:
            self._machine = machine
            self._context = machine.initialize(self._hardware)

            protocol = SetupProtocol(verify=verify)
            certificate = protocol.certificate(config.certificate_url)

            request, state = machine.exchange(config.version, self._hardware, self._context, certificate)
            if state != 1:
                raise SAPError(f"SAP setup entered unexpected state {state}")
            if not request:
                raise SAPError("SAP setup message is empty")

            reply = protocol.exchange(config.setup_url, request)

            _, state = machine.exchange(config.version, self._hardware, self._context, reply)
            if state != 0:
                raise SAPError(f"SAP setup completed in unexpected state {state}")

            complete = True
        finally:
            if not complete:
                self.close()

    def sign(self, data: bytes) -> bytes:
        with self._lock:
            if self._closed or self._machine is None:
                raise SAPError("SAP signer is closed")
            signature = self._machine.sign(self._context, bytes(data))
        if not signature:
            raise SAPError("sign Apple request: signature is empty")
        return signature

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            machine = self._machine
            context = self._context
            self._machine = None
            self._context = 0
        if machine is not None:
            try:
                if context:
                    machine.teardown(context)
            except Exception:  # noqa: BLE001
                pass
            machine.close()

    def __enter__(self) -> "Signer":
        return self

    def __exit__(self, *_exc) -> None:
        self.close()


def _validate_config(config: SignerConfig) -> None:
    if config.version != SUPPORTED_VERSION:
        raise SAPError(f"unsupported SAP version {config.version}")
    if not config.hardware_id or len(config.hardware_id) > 20:
        raise SAPError("SAP hardware ID must contain between 1 and 20 bytes")
    for label, value in (("setup", config.setup_url), ("certificate", config.certificate_url)):
        if not isinstance(value, str) or not value.startswith("https://"):
            raise SAPError(f"SAP {label} URL must be an absolute HTTPS URL")
