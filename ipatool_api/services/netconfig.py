"""Outbound proxy for all traffic to Apple, set once at startup through the
standard proxy environment variables (``requests`` honours them everywhere).

http://host:port, https://host:port or socks5://host:port (DNS resolved by
the proxy), optionally with a user and password. SOCKS needs PySocks.
"""
from __future__ import annotations

import os
import re
from typing import Optional
from urllib.parse import quote, urlsplit, urlunsplit

_ENV_KEYS = ("HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "https_proxy", "http_proxy", "all_proxy")
_active_masked: Optional[str] = None


class ProxyConfigError(ValueError):
    pass


def build_proxy_url(
    proxy: str,
    proxy_type: str = "http",
    user: Optional[str] = None,
    password: Optional[str] = None,
) -> str:
    """Turn ``host:port`` (+ type, user, password) or a full URL into a proxy URL."""
    proxy = (proxy or "").strip()
    if not proxy:
        raise ProxyConfigError("empty proxy address")
    if "://" not in proxy:
        proxy = f"{proxy_type}://{proxy}"

    parts = urlsplit(proxy)
    scheme = parts.scheme.lower()
    if scheme in ("socks5", "socks"):
        scheme = "socks5h"  # resolve DNS through the proxy
    if scheme not in ("http", "https", "socks5h", "socks4", "socks4a"):
        raise ProxyConfigError(f"unsupported proxy type {parts.scheme!r} (use http, https or socks5)")
    if not parts.hostname:
        raise ProxyConfigError(f"proxy address {proxy!r} has no host")
    try:
        port = parts.port
    except ValueError as exc:
        raise ProxyConfigError(f"invalid proxy port in {proxy!r}") from exc
    if port is None:
        raise ProxyConfigError(f"proxy address {proxy!r} needs a port (host:port)")

    # Credentials given separately win over ones embedded in the URL.
    login = user if user is not None else parts.username
    secret = password if password is not None else parts.password
    host = parts.hostname
    if ":" in host:  # IPv6 literal
        host = f"[{host}]"
    netloc = f"{host}:{port}"
    if login:
        netloc = f"{quote(login, safe='')}:{quote(secret or '', safe='')}@{netloc}"
    return urlunsplit((scheme, netloc, "", "", ""))


def mask(url: Optional[str]) -> str:
    """Proxy URL for logs: password never shown, user reduced to a hint."""
    if not url:
        return "none"
    parts = urlsplit(url)
    if parts.username:
        user = parts.username
        hint = (user[:1] + "***") if user else "***"
        host = parts.hostname or "?"
        if ":" in host:
            host = f"[{host}]"
        return f"{parts.scheme}://{hint}:***@{host}:{parts.port}"
    return url


def configure(url: Optional[str]) -> None:
    """Route all outbound HTTP(S) through ``url`` (or clear it with None)."""
    global _active_masked
    if not url:
        return
    if url.startswith("socks"):
        try:
            import socks  # noqa: F401  (PySocks)
        except ImportError as exc:
            raise ProxyConfigError(
                "SOCKS proxies need the PySocks package: pip install PySocks"
            ) from exc
    for key in _ENV_KEYS:
        os.environ[key] = url
    # Nothing local should ever go through it.
    os.environ["NO_PROXY"] = os.environ["no_proxy"] = "localhost,127.0.0.1,::1"
    _active_masked = mask(url)


def active() -> Optional[str]:
    """Masked description of the configured proxy, or None."""
    return _active_masked


def resolve_password(cli_value: Optional[str], env_name: str = "IPATOOL_PROXY_PASSWORD") -> Optional[str]:
    """Password from the command line, else from the environment variable."""
    if cli_value is not None:
        return cli_value
    return os.environ.get(env_name)


_SECRET_IN_URL = re.compile(r"(\w+://[^:/@\s]+:)[^@\s]+@")


def scrub(text: str) -> str:
    """Remove passwords from any proxy URL embedded in text (e.g. error messages)."""
    return _SECRET_IN_URL.sub(r"\1***@", text)


def describe_error(exc: BaseException) -> str:
    """Short, human reason for a failed request through the proxy."""
    text = scrub(str(exc))
    match = re.search(r"Tunnel connection failed: (\d{3})[^'\")]*", text)
    if match:
        code = match.group(1)
        if code == "407":
            return "proxy rejected the login/password (HTTP 407)"
        return f"proxy refused the connection (HTTP {code})"
    lowered = text.lower()
    if "socks" in lowered:
        if "authentication" in lowered or "auth" in lowered:
            return "SOCKS proxy rejected the login/password"
        if "connection closed unexpectedly" in lowered:
            return "SOCKS proxy closed the connection (usually a wrong login/password)"
        if "general socks server failure" in lowered or "host unreachable" in lowered:
            return "SOCKS proxy could not reach Apple"
    if "connection refused" in lowered or "failed to establish" in lowered or "unable to connect to proxy" in lowered:
        return "cannot connect to the proxy (wrong address/port, or it is not running)"
    if "timed out" in lowered or "timeout" in lowered:
        return "proxy did not answer in time"
    if "ssl" in lowered or "certificate" in lowered:
        return "TLS through the proxy failed (does it intercept HTTPS?)"
    return text[:160]


def probe(timeout: float = 10.0):
    """One quick request through the configured proxy, no retries.
    Returns (ok, message)."""
    import requests

    session = requests.Session()  # proxies come from the environment set by configure()
    try:
        session.head("https://init.itunes.apple.com/", timeout=timeout, allow_redirects=False)
    except requests.RequestException as exc:
        return False, describe_error(exc)
    try:
        info = session.get("https://ipinfo.io/json", timeout=timeout).json()
        return True, f"exits in {info.get('country', '?')} ({info.get('org', '?')})"
    except Exception:  # noqa: BLE001 - location lookup is only informational
        return True, "reachable"
