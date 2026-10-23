"""Platform selection (iPhone / iPad / Apple TV), from ipatool's platform.go.

Universal apps share one id across platforms; the MDM lookup
(``lookup_latest_external_version_id``) picks a platform's build.
"""
from __future__ import annotations

from typing import Optional

PLATFORM_IPHONE = "iphone"
PLATFORM_IPAD = "ipad"
PLATFORM_APPLETV = "appletv"
PLATFORM_VISIONOS = "visionos"
# Apple Watch is a search filter only: watch apps ship inside iPhone packages.
PLATFORM_WATCH = "watch"

_ALIASES = {
    "": "",
    "iphone": PLATFORM_IPHONE,
    "ios": PLATFORM_IPHONE,
    "ipad": PLATFORM_IPAD,
    "appletv": PLATFORM_APPLETV,
    "apple-tv": PLATFORM_APPLETV,
    "atv": PLATFORM_APPLETV,
    "tvos": PLATFORM_APPLETV,
    "vision": PLATFORM_VISIONOS,
    "visionos": PLATFORM_VISIONOS,
    "visionpro": PLATFORM_VISIONOS,
    "xros": PLATFORM_VISIONOS,
    "realitydevice": PLATFORM_VISIONOS,
    "watch": PLATFORM_WATCH,
    "watchos": PLATFORM_WATCH,
    "applewatch": PLATFORM_WATCH,
    "apple-watch": PLATFORM_WATCH,
}


def parse_platform(value: Optional[str]) -> str:
    """Normalize a user-supplied platform string. Empty/None means 'default'
    (iPhone + iPad combined, matching the tool's original behavior)."""
    if not value:
        return ""
    key = value.strip().lower()
    if key not in _ALIASES:
        raise ValueError(f"invalid platform {value!r}: must be iphone, ipad, appletv, visionos or watch")
    return _ALIASES[key]


def search_entity(platform: str) -> str:
    """iTunes Search API 'entity' parameter for this platform.

    Matches Platform.searchEntity() in platform.go exactly.
    """
    if platform == "":
        return "software,iPadSoftware"
    if platform == PLATFORM_IPHONE:
        return "software"
    if platform == PLATFORM_IPAD:
        return "iPadSoftware"
    if platform == PLATFORM_APPLETV:
        return "software,tvSoftware"
    if platform == PLATFORM_WATCH:
        # ipatool 4484b55: watch apps share the software catalog with iOS
        # apps; watchSoftware adds watch-only ones.
        return "software,watchSoftware"
    if platform == PLATFORM_VISIONOS:
        return "xrosSoftware"
    raise ValueError(f"invalid platform {platform!r}")


def download_platform(platform: str) -> str:
    """Platform for versions/downloads: a watch app ships inside the iPhone
    package, so Apple Watch maps to iPhone."""
    return PLATFORM_IPHONE if platform == PLATFORM_WATCH else platform


def has_watch_app(item: dict) -> bool:
    """iTunes Search/Lookup result lists Apple Watch models (e.g. "Watch4-Watch4")
    in supportedDevices when the app has a watch app."""
    devices = item.get("supportedDevices") or []
    return any(str(device).lower().startswith("watch") for device in devices)


def metadata_platform(platform: str) -> str:
    """'platform' parameter of the MDM lookup (ipatool metadataPlatform())."""
    if platform in (PLATFORM_IPHONE, PLATFORM_IPAD):
        return "enterprisestore"
    if platform == PLATFORM_APPLETV:
        return "atv9"
    if platform == PLATFORM_VISIONOS:
        return "realityDevice"
    raise ValueError(f"invalid platform {platform!r} for metadata lookup")
