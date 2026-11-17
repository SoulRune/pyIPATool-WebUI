#!/usr/bin/env python3
"""Build ipatool_api/services/store_emulator/store_profile.bin.

The profile is ipatool's (internal/store/profile/data_generated.go, MIT),
generated there from the pinned macOS 27.0.1 images. Its three parts are
decoded with ipatool itself (``profile.Load``) and written as files:

    metadata.json  pages.bin  plugin.bin

Then:

    python tools/build_store_profile.py DIR APPLE_MEDIA_SERVICES

where APPLE_MEDIA_SERVICES is ipatool's export of the framework (its asset
cache, ``apple-assets-macos-27-26A434-arm64-v4/AppleMediaServices``). The
instruction ranges and Objective-C ivar offsets the runtime needs are read
from it and from the plugin image; the parts are checked against ipatool's
pinned digests before they are written.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ipatool_api.services.sap import macho  # noqa: E402
from ipatool_api.services.store_emulator import profile  # noqa: E402

_INSTRUCTIONS = macho.S_ATTR_PURE_INSTRUCTIONS | macho.S_ATTR_SOME_INSTRUCTIONS


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__)
        return 2
    directory, media_path = Path(sys.argv[1]), Path(sys.argv[2])
    metadata = (directory / "metadata.json").read_bytes()
    pages = (directory / "pages.bin").read_bytes()
    plugin = (directory / "plugin.bin").read_bytes()
    classes = {item["Name"]: item for item in json.loads(metadata).get("Classes") or []}

    code_ranges = []
    ivar_offsets = []
    media = macho.Image("AppleMediaServices", media_path.read_bytes())
    # ipatool maps the framework as its exporter wrote it: segments padded to
    # 16 KB and its own link-edit data. The runtime maps these ranges (zeroed)
    # before it loads the framework, so the guest's address space matches.
    mappings = [(segment.address, segment.size) for segment in media.segments if segment.size]
    for image in (media, macho.Image("plugin", plugin)):
        for section in image.sections:
            if section.flags & _INSTRUCTIONS:
                code_ranges.append((section.address, section.address + section.size))
        for name, value in image._symbols:
            if not name.startswith("_OBJC_IVAR_$_"):
                continue
            owner, _, ivar = name[len("_OBJC_IVAR_$_"):].partition(".")
            offset = ((classes.get(owner) or {}).get("Ivars") or {}).get(ivar)
            if ivar and offset is not None:
                ivar_offsets.append((value, offset))

    output = ROOT / "ipatool_api" / "services" / "store_emulator" / "store_profile.bin"
    output.write_bytes(profile.build(metadata, pages, plugin, code_ranges, ivar_offsets, mappings))
    print(f"wrote {output} ({output.stat().st_size} bytes, {len(code_ranges)} code ranges, "
          f"{len(ivar_offsets)} ivar offsets)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
