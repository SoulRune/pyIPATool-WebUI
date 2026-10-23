"""``IPATOOL_TRACE=<file>``: every request to Apple appended as a JSON line,
secrets replaced by their length."""
from __future__ import annotations

import datetime as _dt
import json
import os
import plistlib
import threading
from typing import Any, Dict, Optional
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

_lock = threading.Lock()

_SAFE_HEADERS = {
    "accept", "accept-encoding", "accept-language", "content-type", "content-encoding", "user-agent",
    "x-apple-store-front", "x-apple-client-application", "x-apple-client-versions", "x-apple-connection-type",
    "x-apple-i-timezone", "x-apple-i-locale", "x-apple-tz", "x-apple-partner", "x-apple-requesting-bundle-id",
    "x-apple-requesting-bundle-version", "content-length",
}
_SAFE_RESPONSE_HEADERS = {
    "content-type", "www-authenticate", "x-apple-application-site", "x-apple-application-instance",
    "x-apple-orig-url-path",
}
_SAFE_KEYS = {
    "salableAdamId", "appExtVrsId", "externalVersionId", "productType", "price", "pricingParameters",
    "buyWithoutAuthorization", "needDiversity", "hasAskedToFulfillPreorder", "hasBeenAuthedForBuy", "isInApp",
    "appAdamId", "adamId", "bundleId", "rebuy", "reason", "isUpdate", "generateBuyParams",
    "softwareVersionExternalIdentifier", "want-installable", "is-ios", "platform", "storefront", "itemId", "kind",
    "machineName", "rmp", "attempt", "createSession", "why",
}


def enabled() -> bool:
    return bool(os.environ.get("IPATOOL_TRACE"))


def _hidden(value: Any) -> str:
    return f"<hidden len={len(str(value))}>"


def _url(url: str) -> str:
    parts = urlsplit(url)
    query = []
    for key, value in parse_qsl(parts.query, keep_blank_values=True):
        if key in ("guid", "dsid") or "token" in key.lower():
            value = _hidden(value)
        query.append((key, value))
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), ""))


def _body(data: Optional[bytes]) -> Any:
    if not data:
        return None
    try:
        value = plistlib.loads(data)
    except Exception:  # noqa: BLE001
        try:
            value = json.loads(data)
        except Exception:  # noqa: BLE001
            return f"<non-plist body len={len(data)}>"
    if not isinstance(value, dict):
        return f"<body len={len(data)}>"
    return {k: (v if k in _SAFE_KEYS else _hidden(v)) for k, v in value.items()}


def _cookie_name(name: str) -> str:
    """Cookie names can carry the DSID (e.g. mz_at0-<dsid>): hide long numbers."""
    import re

    return re.sub(r"\d{5,}", "<id>", name)


def _write(entry: Dict[str, Any]) -> None:
    path = os.environ.get("IPATOOL_TRACE")
    if not path:
        return
    entry["time"] = _dt.datetime.now().astimezone().isoformat(timespec="seconds")
    line = json.dumps(entry, ensure_ascii=False, default=str) + "\n"
    with _lock:
        try:
            with open(path, "a", encoding="utf-8") as handle:
                handle.write(line)
        except OSError:
            pass


def record(response) -> None:
    """Trace one finished ``requests`` response (and the request it answered)."""
    if not enabled() or response is None:
        return
    request = response.request
    url = _url(request.url)
    headers = {}
    for key, value in request.headers.items():
        if key.lower() == "cookie":
            continue
        headers[key] = value if key.lower() in _SAFE_HEADERS else _hidden(value)
    body = request.body.encode("utf-8") if isinstance(request.body, str) else request.body
    _write({"dir": "request", "method": request.method, "url": url, "headers": headers, "body": _body(body)})
    cookie_header = request.headers.get("Cookie") or ""
    names = [_cookie_name(part.split("=", 1)[0].strip()) for part in cookie_header.split(";") if part.strip()]
    _write({"dir": "cookies", "url": url, "names": names})
    response_headers = {
        key: (value if key.lower() in _SAFE_RESPONSE_HEADERS else _hidden(value))
        for key, value in response.headers.items()
    }
    set_cookies = [_cookie_name(cookie.name) for cookie in response.cookies]
    raw_set_cookies = []
    try:
        raw_set_cookies = response.raw._original_response.msg.get_all("Set-Cookie") or []
    except AttributeError:
        pass
    # Attributes only (Domain, Path, Expires, Max-Age, flags) - never values.
    cookie_attributes = []
    for raw in raw_set_cookies:
        parts = [p.strip() for p in raw.split(";")]
        name = _cookie_name(parts[0].split("=", 1)[0]) if parts else ""
        attrs = [p for p in parts[1:] if p]
        cookie_attributes.append({"name": name, "attributes": attrs})
    _write({"dir": "response-headers", "url": url, "status": response.status_code, "headers": response_headers,
            "setCookies": set_cookies, "setCookieAttributes": cookie_attributes})
