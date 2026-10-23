"""Thin wrapper around ``requests`` that mimics the Go client semantics."""
from __future__ import annotations

import base64
import logging
import plistlib
import re
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, Mapping, MutableMapping, Optional, Tuple


# Patterns used to unwrap Apple's <Document> envelope in XML plist responses.
_DOCUMENT_XML_RE = re.compile(r"(?is)<Document\b[^>]*>(.*)</Document>")
_PLIST_XML_RE = re.compile(r"(?is)<plist\b[^>]*>.*?</plist>")
_DICT_XML_RE = re.compile(r"(?is)<dict\b[^>]*>.*</dict>")
_URL_RE = re.compile(rb"""https?://[^\s"'<>]+""")


def extract_urls(body: bytes) -> list[str]:
    return [match.decode("utf-8", errors="replace") for match in _URL_RE.findall(body)]


def _truncate_body(body: bytes, max_chars: int = 500) -> str:
    text = body.decode("utf-8", errors="replace").strip()
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + "..."


def _normalize_plist_body(body: bytes) -> bytes:
    """Unwrap Apple's <Document> / <Protocol> envelope into plist bytes
    (ipatool normalizeXMLPlistBody)."""
    normalized = body.strip()
    if not normalized:
        return normalized

    text = normalized.decode("utf-8", errors="replace")

    # 1. Extract inner content of <Document> wrapper if present.
    m = _DOCUMENT_XML_RE.search(text)
    if m:
        text = m.group(1).strip()

    # 2. If there is an embedded <plist> element, use it directly.
    m = _PLIST_XML_RE.search(text)
    if m:
        return m.group(0).encode("utf-8")

    # 3. If there is an embedded <dict> element, wrap it in a plist document.
    m = _DICT_XML_RE.search(text)
    if m:
        return (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<plist version="1.0">' + m.group(0) + "</plist>"
        ).encode("utf-8")

    # 4. If there are loose <key> tags, wrap the whole thing in <dict> + <plist>.
    if "<key>" in text:
        return (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<plist version="1.0"><dict>' + text + "</dict></plist>"
        ).encode("utf-8")

    return normalized

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from . import constants, trace
from .cookie_store import CookieStore

logger = logging.getLogger(__name__)
# Kept-alive connections unused this long are dropped before the next request.
IDLE_RESET_SECONDS = 60


class HTTPClientResponseError(RuntimeError):
    """Raised when the response cannot be parsed as requested."""

    def __init__(self, message: str, *, status_code: int, headers: Dict[str, str], body: bytes) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.headers = headers
        self.body = body


class ResponseDecodeError(RuntimeError):
    """Raised when Apple's XML/plist response cannot be decoded."""

    def __init__(
        self,
        message: str,
        *,
        cause: Exception,
        status_code: int,
        headers: Dict[str, str],
        body: bytes,
    ) -> None:
        super().__init__(message)
        self.__cause__ = cause
        self.cause = cause
        self.status_code = status_code
        self.headers = headers
        self.content_type = headers.get("Content-Type", "")
        self.body = _truncate_body(body)
        self.urls = extract_urls(body)


@dataclass
class HTTPRequest:
    method: str
    url: str
    headers: Mapping[str, str]
    payload: Optional["Payload"]
    response_format: str
    follow_redirects: bool = True
    # SAP signature of the body; signed requests are retried by the caller (re-signed).
    signer: Optional[Callable[[bytes], bytes]] = None
    # (connect, read) seconds; None = the client default.
    timeout: Optional[Tuple[float, float]] = None


@dataclass
class HTTPResult:
    status_code: int
    headers: Dict[str, str]
    data: Any

    def get_header(self, key: str) -> str:
        lowered = key.lower()
        for header_key, value in self.headers.items():
            if header_key.lower() == lowered:
                return value
        raise KeyError(key)


class Payload:
    def serialize(self) -> Tuple[bytes, str]:
        raise NotImplementedError


class XMLPayload(Payload):
    def __init__(self, content: Mapping[str, Any]) -> None:
        self._content = content

    def serialize(self) -> Tuple[bytes, str]:
        # Compact XML, as Apple's framework (and Go's plist encoder) writes it.
        return _compact_plist(dict(self._content)), "application/x-apple-plist"


_PLIST_HEADER = (
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
)


def _plist_escape(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _plist_value(value: Any) -> str:
    if isinstance(value, bool):
        return "<true/>" if value else "<false/>"
    if isinstance(value, int):
        return f"<integer>{value}</integer>"
    if isinstance(value, float):
        return f"<real>{value!r}</real>"
    if isinstance(value, str):
        return f"<string>{_plist_escape(value)}</string>" if value else "<string/>"
    if isinstance(value, Mapping):
        items = "".join(f"<key>{_plist_escape(str(k))}</key>{_plist_value(v)}" for k, v in sorted(value.items()))
        return f"<dict>{items}</dict>" if items else "<dict/>"
    if isinstance(value, (list, tuple)):
        items = "".join(_plist_value(v) for v in value)
        return f"<array>{items}</array>" if items else "<array/>"
    if isinstance(value, (bytes, bytearray)):
        import base64 as _b64
        return f"<data>{_b64.b64encode(bytes(value)).decode('ascii')}</data>"
    raise TypeError(f"unsupported plist value: {type(value).__name__}")


def _compact_plist(content: Mapping[str, Any]) -> bytes:
    return (_PLIST_HEADER + '<plist version="1.0">' + _plist_value(content) + "</plist>").encode("utf-8")


def _is_apple_store_host(url: str) -> bool:
    from urllib.parse import urlsplit

    host = (urlsplit(url).hostname or "").lower()
    return host == "apple.com" or host.endswith(".apple.com")


def _add_store_framework_headers(headers: MutableMapping[str, str]) -> None:
    """As Apple's framework sends Store requests with a body: its headers,
    its Accept-Encoding, and no generic Accept."""
    present = {k.lower() for k in headers.keys()}
    for key, value in constants.STORE_FRAMEWORK_HEADERS.items():
        if key.lower() not in present:
            headers[key] = value
    if "accept-encoding" not in present:
        try:
            import brotli  # noqa: F401 - requests decodes br only with it
            headers["Accept-Encoding"] = "br, gzip, deflate"
        except ImportError:
            headers["Accept-Encoding"] = "gzip, deflate"
    if "accept" not in present:
        headers["Accept"] = None  # drop requests' default "*/*"


class HTTPClient:
    def __init__(self, cookie_store: CookieStore, verify: bool | str = True) -> None:
        self._cookie_store = cookie_store
        self.session = requests.Session()
        self.session.headers.setdefault("User-Agent", constants.DEFAULT_USER_AGENT)
        self.session.verify = verify
        cookie_store.attach_to(self.session)

        # Transport-level retries, as ipatool-py.
        retry_strategy = Retry(
            connect=constants.RETRY_CONNECT,
            read=constants.RETRY_READ,
            status=constants.RETRY_STATUS,
            allowed_methods=None,  # retry POST too - Apple's plist calls are safe to resend
            status_forcelist=constants.RETRY_STATUS_FORCELIST,
            backoff_factor=constants.RETRY_BACKOFF_FACTOR,
            respect_retry_after_header=False,
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)

        # Signed requests: connection retries only, never a replayed signed body.
        self.signed_session = requests.Session()
        self.signed_session.headers.setdefault("User-Agent", constants.DEFAULT_USER_AGENT)
        self.signed_session.verify = verify
        cookie_store.attach_to(self.signed_session)
        signed_adapter = HTTPAdapter(
            max_retries=Retry(connect=constants.RETRY_CONNECT, read=0, status=0, redirect=0, other=0, allowed_methods=None)
        )
        self.signed_session.mount("https://", signed_adapter)
        self.signed_session.mount("http://", signed_adapter)

    def send(self, request: HTTPRequest) -> HTTPResult:
        data: Optional[bytes] = None
        headers: MutableMapping[str, str] = dict(request.headers)
        
        # Ensure User-Agent is set (mimics Go's AddHeaderTransport)
        if "User-Agent" not in headers and "user-agent" not in {k.lower() for k in headers.keys()}:
            headers["User-Agent"] = constants.DEFAULT_USER_AGENT

        if request.payload is not None:
            data, default_content_type = request.payload.serialize()
            # Only set Content-Type if not already specified in request headers
            if "Content-Type" not in headers and "content-type" not in {k.lower() for k in headers.keys()}:
                headers["Content-Type"] = default_content_type
            if _is_apple_store_host(request.url):
                _add_store_framework_headers(headers)

        self._reset_if_idle()
        for attempt in range(2):
            session = self.session
            if request.signer is not None:
                signature = request.signer(data or b"")
                headers[constants.HTTP_HEADER_ACTION_SIGNATURE] = base64.b64encode(signature).decode("ascii")
                session = self.signed_session
            try:
                response = session.request(
                    method=request.method,
                    url=request.url,
                    headers=headers,
                    data=data,
                    allow_redirects=request.follow_redirects,
                    timeout=request.timeout or (constants.DEFAULT_CONNECT_TIMEOUT, constants.DEFAULT_READ_TIMEOUT),
                )
                break
            except requests.ConnectionError:
                # Often stale kept-alive connections: drop them all and try once more.
                self.reset_connections("connection error")
                if attempt or request.signer is not None:
                    raise  # signed requests are retried by their caller, with a new signature
            except requests.Timeout:
                # A read timeout may have reached Apple: not resent. But the
                # connections it came over are likely dead - fresh ones next.
                self.reset_connections("timeout")
                raise
        self._last_used = time.monotonic()

        self._cookie_store.save()
        trace.record(response)  # IPATOOL_TRACE diagnostics; no-op otherwise

        raw_headers = dict(response.headers)
        raw_body = response.content

        parsed: Any
        if 300 <= response.status_code < 400:
            parsed = {}
        else:
            try:
                if request.response_format == constants.ResponseFormatJSON:
                    parsed = response.json()
                elif request.response_format == constants.ResponseFormatXML:
                    normalized_body = _normalize_plist_body(raw_body)
                    parsed = plistlib.loads(normalized_body)
                else:
                    raise HTTPClientResponseError(
                        f"Unsupported response format: {request.response_format}",
                        status_code=response.status_code,
                        headers=raw_headers,
                        body=raw_body,
                    )
            except (ValueError, plistlib.InvalidFileException) as exc:
                raise ResponseDecodeError(
                    f"failed to unmarshal xml: {exc}",
                    cause=exc,
                    status_code=response.status_code,
                    headers=raw_headers,
                    body=raw_body,
                ) from exc

        return HTTPResult(
            status_code=response.status_code,
            headers=raw_headers,
            data=parsed,
        )

    def reset_connections(self, reason: str = "") -> None:
        """Drop every kept-alive connection; the next request opens new ones."""
        for session in (self.session, self.signed_session):
            for adapter in session.adapters.values():
                try:
                    adapter.close()  # clears its connection pools; the adapter stays usable
                except Exception:  # noqa: BLE001
                    pass
        if reason:
            logger.info("network: new connections to Apple (%s)", reason)

    def _reset_if_idle(self) -> None:
        # Kept-alive connections often die silently during long pauses.
        last = getattr(self, "_last_used", None)
        if last is not None and time.monotonic() - last > IDLE_RESET_SECONDS:
            self.reset_connections()

    def raw_request(self, method: str, url: str, **kwargs) -> requests.Response:
        # The read timeout applies between chunks, so a stalled stream is detected.
        kwargs.setdefault("timeout", (constants.DEFAULT_CONNECT_TIMEOUT, constants.DOWNLOAD_READ_TIMEOUT))
        self._reset_if_idle()
        try:
            response = self.session.request(method=method, url=url, **kwargs)
        except requests.RequestException:
            self.reset_connections("connection error")
            raise
        self._last_used = time.monotonic()
        self._cookie_store.save()
        return response
