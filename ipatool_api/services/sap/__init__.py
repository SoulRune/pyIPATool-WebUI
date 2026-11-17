"""Apple SAP action signing (``X-Apple-ActionSignature``) and kbsync.

Python port of ``internal/sap`` from majd/ipatool (v2.6.0, then ``main`` up to
b352566: macOS 27 assets, arm64 emulation, machine verification; MIT License,
Copyright (c) Majd Alfhaily). Module layout mirrors upstream so future upstream fixes can be
carried over by diffing:

    upstream (Go)                               here
    internal/sap/assets (assets, http_range,    assets.py, remote.py, aea.py,
      remote, aea, apfs, dyld)                  aecrypto.py, codecs.py,
                                                apfs.py, dyld.py
    internal/sap/assets/kernel.go               kernel.py
    internal/sap/machimage                      macho.py
    internal/sap/machine                        machine.py
    internal/sap/machine/modern_adi.go          modern_adi.py
    internal/sap/machine (shim_platform,        shim_platform.py
      ioaes)
    internal/sap/unicorn (clock,                engine.py
      engine_config)
    internal/sap/protocol.go                    protocol.py
    internal/sap/signer*.go                     signer.py

The rest of upstream's internal/sap/unicorn (downloading and dlopen-ing
libunicorn for each OS) has no counterpart: the ``unicorn`` package from PyPI
(or the vendored build on iOS/Android) provides the emulator.

Since August 2026 Apple requires a SAP signature on sign-in, and since
November 2026 machine verification as well. Both are computed by Apple's own
code: macOS framework, daemon and kernel extension files, read once from
Apple's restore image and verified against pinned digests, run in a Unicorn
arm64 emulator.
Nothing Apple-owned is shipped with this project.
"""
from __future__ import annotations

from .errors import SAPError, SAPUnavailableError
from .signer import Signer, SignerConfig, unicorn_available, unicorn_install_hint

__all__ = ["SAPError", "SAPUnavailableError", "Signer", "SignerConfig", "unicorn_available"]

# Ported from majd/ipatool (MIT License, Copyright (c) Majd Alfhaily).
