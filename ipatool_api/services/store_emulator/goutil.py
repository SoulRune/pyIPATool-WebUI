"""Go standard-library behaviour the bridge reproduces: net/url parsing,
path cleaning, header canonicalization and string helpers."""
from __future__ import annotations

import posixpath
import re
from typing import Optional, Tuple
from urllib.parse import quote, unquote


def glen(value: str) -> int:
    """len() of a Go string: its UTF-8 byte length."""
    return len(value.encode("utf-8", "surrogateescape"))


def utf16_length(value: str) -> int:
    """len(utf16.Encode([]rune(value)))"""
    return sum(2 if ord(c) > 0xFFFF else 1 for c in value)


def utf16_units(value: str) -> list:
    out = []
    for c in value:
        code = ord(c)
        if 0xD800 <= code <= 0xDFFF:
            code = 0xFFFD  # Go's []rune of invalid UTF-8 yields U+FFFD
        if code > 0xFFFF:
            code -= 0x10000
            out.extend((0xD800 + (code >> 10), 0xDC00 + (code & 0x3FF)))
        else:
            out.append(code)
    return out


def utf16_decode(units: list) -> str:
    out = []
    index = 0
    while index < len(units):
        unit = units[index]
        if 0xD800 <= unit < 0xDC00 and index + 1 < len(units) and 0xDC00 <= units[index + 1] < 0xE000:
            out.append(chr(0x10000 + ((unit - 0xD800) << 10) + (units[index + 1] - 0xDC00)))
            index += 2
            continue
        out.append("\ufffd" if 0xD800 <= unit < 0xE000 else chr(unit))
        index += 1
    return "".join(out)


def canonical_header_key(key: str) -> str:
    """net/http CanonicalHeaderKey."""
    if not key or any(c in " \t\r\n" or not ("!" <= c <= "~") for c in key):
        return key
    out = []
    upper = True
    for c in key:
        if upper and "a" <= c <= "z":
            c = c.upper()
        elif not upper and "A" <= c <= "Z":
            c = c.lower()
        out.append(c)
        upper = c == "-"
    return "".join(out)


def path_clean(value: str) -> str:
    """path.Clean"""
    if value == "":
        return "."
    rooted = value.startswith("/")
    parts = []
    for part in value.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            if parts and parts[-1] != "..":
                parts.pop()
            elif not rooted:
                parts.append("..")
            continue
        parts.append(part)
    cleaned = ("/" if rooted else "") + "/".join(parts)
    return cleaned or ("/" if rooted else ".")


def path_join(*elements: str) -> str:
    joined = "/".join(e for e in elements if e)
    return path_clean(joined) if joined else ""


def path_ext(value: str) -> str:
    index = len(value) - 1
    while index >= 0 and value[index] != "/":
        if value[index] == ".":
            return value[index:]
        index -= 1
    return ""


def path_base(value: str) -> str:
    if value == "":
        return "."
    value = value.rstrip("/")
    if value == "":
        return "/"
    return value.rsplit("/", 1)[-1]


_SCHEME = re.compile(r"^([A-Za-z][A-Za-z0-9+.\-]*):")


class GoURL:
    """The parts of net/url.URL the bridge uses."""

    def __init__(self, scheme: str = "", opaque: str = "", user: Optional[str] = None, host: str = "",
                 path: str = "", raw_path: str = "", raw_query: str = "", fragment: str = "",
                 force_query: bool = False) -> None:
        self.scheme = scheme
        self.opaque = opaque
        self.user = user
        self.host = host
        self.path = path
        self.raw_path = raw_path
        self.raw_query = raw_query
        self.fragment = fragment
        self.force_query = force_query

    @classmethod
    def parse(cls, raw: str) -> "GoURL":
        if any(ord(c) < 0x20 or ord(c) == 0x7F for c in raw):
            raise ValueError("invalid control character in URL")
        rest, _, fragment = raw.partition("#")
        url = cls(fragment=_unescape(fragment) if fragment else "")
        match = _SCHEME.match(rest)
        if match:
            url.scheme = match.group(1).lower()
            rest = rest[match.end():]
        if "?" in rest:
            rest, url.raw_query = rest.split("?", 1)
            url.force_query = url.raw_query == ""
        if url.scheme and not rest.startswith("/"):
            url.opaque = rest
            return url
        if rest.startswith("//"):
            authority, slash, path = rest[2:].partition("/")
            rest = slash + path
            if "@" in authority:
                url.user, authority = authority.rsplit("@", 1)
            url.host = _unescape(authority)
        url.path = _unescape(rest)
        escaped = _escape_path(url.path)
        url.raw_path = rest if rest != escaped else ""
        return url

    def hostname(self) -> str:
        host = self.host
        if host.startswith("["):
            return host[1:host.find("]")] if "]" in host else host
        return host.rsplit(":", 1)[0] if ":" in host else host

    def port(self) -> str:
        host = self.host
        if host.startswith("[") and "]" in host:
            host = host[host.find("]") + 1:]
            return host[1:] if host.startswith(":") else ""
        return host.rsplit(":", 1)[1] if ":" in host else ""

    def escaped_path(self) -> str:
        if self.raw_path and _unescape(self.raw_path) == self.path:
            return self.raw_path
        return _escape_path(self.path)

    def string(self) -> str:
        out = ""
        if self.scheme:
            out += self.scheme + ":"
        if self.opaque:
            out += self.opaque
        else:
            if self.scheme or self.host or self.user is not None:
                if self.host or self.path or self.user is not None:
                    out += "//"
                if self.user is not None:
                    out += self.user + "@"
                out += self.host
            path = self.escaped_path()
            if path and not path.startswith("/") and self.host:
                out += "/"
            if not out and ":" in path.split("/", 1)[0]:
                out += "./"
            out += path
        if self.force_query or self.raw_query:
            out += "?" + self.raw_query
        if self.fragment:
            out += "#" + quote(self.fragment, safe="!$&'()*+,;=:@/?~")
        return out

    def copy(self) -> "GoURL":
        return GoURL(self.scheme, self.opaque, self.user, self.host, self.path, self.raw_path, self.raw_query,
                     self.fragment, self.force_query)


def _unescape(value: str) -> str:
    if "%" not in value:
        return value
    if re.search(r"%(?![0-9A-Fa-f]{2})", value):
        raise ValueError("invalid URL escape")
    return unquote(value, errors="surrogateescape")


def _escape_path(value: str) -> str:
    return quote(value, safe="/;,$&+=:@!*'()~")


def url_join_path(base: str, *elements: str) -> str:
    """url.JoinPath"""
    url = GoURL.parse(base)
    if not elements:
        return url.string()
    joined = url.escaped_path()
    for element in elements:
        joined += "/" + element
    trailing = elements[-1].endswith("/")
    cleaned = path_clean(joined if joined.startswith("/") else "/" + joined) if joined else ""
    if not url.escaped_path().startswith("/") and not url.host and cleaned.startswith("/"):
        cleaned = cleaned[1:]
    if trailing and not cleaned.endswith("/"):
        cleaned += "/"
    url.raw_path = cleaned
    url.path = _unescape(cleaned)
    return url.string()


def query_escape(value: str) -> str:
    """url.QueryEscape"""
    return quote(value, safe="-_.~").replace("%20", "+")


def query_unescape(value: str) -> Tuple[str, bool]:
    try:
        return _unescape(value.replace("+", " ")), True
    except ValueError:
        return "", False


def path_unescape(value: str) -> str:
    return _unescape(value)


__all__ = ["glen", "GoURL", "posixpath"]
