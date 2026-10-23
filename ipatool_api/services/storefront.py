"""App Store web storefront parsing - port of ipatool pkg/appstore/appstore_storefront.go.

visionOS apps aren't reachable through the iTunes Search API or Apple's
catalogs in a usable way, so ipatool reads the public apps.apple.com pages:
the page embeds its data as JSON in <script id="serialized-server-data">.

- search:  https://apps.apple.com/<cc>/vision/search?term=...
           -> "AppSearchResult" items that carry a vision purchase configuration
- version: https://apps.apple.com/<cc>/app/id<N>?platform=vision
           -> purchaseConfiguration{metricsPlatformDisplayStyle: "vision",
              appPlatforms: [... "vision" ...], buyParams: "...salableAdamId=N...&appExtVrsId=V"}
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Tuple
from urllib.parse import parse_qs, urlencode

SERIALIZED_SERVER_DATA_ID = "serialized-server-data"
MAX_VISIONOS_SEARCH_RESULTS = 12


class StorefrontError(ValueError):
    pass


def vision_search_url(term: str, country_code: str) -> str:
    return f"https://apps.apple.com/{country_code.lower()}/vision/search?{urlencode({'term': term})}"


def vision_product_url(app_id: int, country_code: str) -> str:
    return f"https://apps.apple.com/{country_code.lower()}/app/id{int(app_id)}?{urlencode({'platform': 'vision'})}"


def serialized_server_data(body: bytes) -> bytes:
    marker = body.find(f'id="{SERIALIZED_SERVER_DATA_ID}"'.encode())
    if marker == -1:
        marker = body.find(f"id='{SERIALIZED_SERVER_DATA_ID}'".encode())
    if marker == -1:
        raise StorefrontError("serialized server data was not found")
    if body.rfind(b"<script", 0, marker) == -1:
        raise StorefrontError("serialized server data script was not found")
    content_offset = body.find(b">", marker)
    if content_offset == -1:
        raise StorefrontError("serialized server data script is malformed")
    start = content_offset + 1
    end = body.find(b"</script>", start)
    if end == -1:
        raise StorefrontError("serialized server data script is not closed")
    return body[start:end].strip()


def _decode(body: bytes) -> Any:
    try:
        return json.loads(serialized_server_data(body))
    except json.JSONDecodeError as exc:
        raise StorefrontError(f"failed to decode serialized server data: {exc}") from exc


def vision_apps(body: bytes, limit: int) -> List[Dict[str, Any]]:
    """Apps from a vision search page: [{"id", "bundleId", "name"}], at most
    ``limit`` (capped at 12, as upstream), only those with a vision purchase
    configuration."""
    page = _decode(body)
    if limit <= 0:
        return []
    limit = min(limit, MAX_VISIONOS_SEARCH_RESULTS)
    apps: List[Dict[str, Any]] = []
    seen = set()
    for page_data in (page.get("data") or []) if isinstance(page, dict) else []:
        shelves = ((page_data or {}).get("data") or {}).get("shelves") or []
        for shelf in shelves:
            for item in (shelf or {}).get("items") or []:
                if not isinstance(item, dict) or item.get("$kind") != "AppSearchResult":
                    continue
                lockup = item.get("lockup") or {}
                try:
                    app_id = int(str(lockup.get("adamId", "")))
                except ValueError:
                    continue
                if app_id == 0 or app_id in seen:
                    continue
                if not find_vision_external_version_id(item, app_id)[1]:
                    continue
                seen.add(app_id)
                apps.append({"id": app_id, "bundleId": lockup.get("bundleId", ""), "name": lockup.get("title", "")})
                if len(apps) == limit:
                    return apps
    return apps


def vision_external_version_id(body: bytes, app_id: int) -> str:
    version_id, found = find_vision_external_version_id(_decode(body), app_id)
    if not found:
        raise StorefrontError("visionOS purchase configuration was not found")
    if not version_id:
        raise StorefrontError("visionOS purchase configuration has no external version id")
    return version_id


def find_vision_external_version_id(value: Any, app_id: int) -> Tuple[str, bool]:
    """(externalVersionId, matched) - depth-first like upstream: a matching
    configuration with an id wins; one without an id still counts as matched."""
    matched = False
    if isinstance(value, list):
        for item in value:
            version_id, found = find_vision_external_version_id(item, app_id)
            if found:
                if version_id:
                    return version_id, True
                matched = True
    elif isinstance(value, dict):
        configuration = value.get("purchaseConfiguration")
        if isinstance(configuration, dict):
            version_id, found = _from_vision_configuration(configuration, app_id)
            if found:
                if version_id:
                    return version_id, True
                matched = True
        for child in value.values():
            version_id, found = find_vision_external_version_id(child, app_id)
            if found:
                if version_id:
                    return version_id, True
                matched = True
    return "", matched


def _from_vision_configuration(configuration: Dict[str, Any], app_id: int) -> Tuple[str, bool]:
    if configuration.get("metricsPlatformDisplayStyle") != "vision":
        return "", False
    platforms = configuration.get("appPlatforms")
    if not isinstance(platforms, list) or "vision" not in platforms:
        return "", False
    buy_params = configuration.get("buyParams")
    if not isinstance(buy_params, str) or not buy_params:
        return "", False
    try:
        values = parse_qs(buy_params, keep_blank_values=True, strict_parsing=False)
    except ValueError:
        return "", False
    if (values.get("salableAdamId") or [""])[0] != str(int(app_id)):
        return "", False
    return (values.get("appExtVrsId") or [""])[0], True


