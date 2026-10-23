"""Apple SAP action signing (``X-Apple-ActionSignature``) and kbsync.

Python port of ``internal/sap`` from majd/ipatool (v2.6.0, then ``main`` up to
b0fe32d: macOS 27 assets, arm64 emulation; MIT License, Copyright (c) Majd
Alfhaily). Module layout mirrors upstream so future upstream fixes can be
carried over by diffing:

    upstream (Go)                               here
    internal/sap/assets (assets, http_range,    assets.py, remote.py, aea.py,
      remote, aea, apfs, dyld)                  aecrypto.py, codecs.py,
                                                apfs.py, dyld.py
    internal/sap/machimage                      macho.py
    internal/sap/machine                        machine.py
    internal/sap/protocol.go                    protocol.py
    internal/sap/signer*.go                     signer.py

Upstream's internal/sap/unicorn (downloading and dlopen-ing libunicorn for
each OS) has no counterpart: the ``unicorn`` package from PyPI (or the
vendored build on iOS/Android) provides the emulator.

Since August 2026 Apple requires a SAP signature on sign-in. It is computed
by Apple's own code: four macOS framework files, read once from Apple's restore
image and verified against pinned digests, run in a Unicorn arm64 emulator.
Nothing Apple-owned is shipped with this project.
"""
from __future__ import annotations

from .errors import SAPError, SAPUnavailableError
from .signer import Signer, SignerConfig, unicorn_available, unicorn_install_hint

__all__ = ["SAPError", "SAPUnavailableError", "Signer", "SignerConfig", "unicorn_available"]

# Ported from majd/ipatool (MIT License, Copyright (c) Majd Alfhaily).
