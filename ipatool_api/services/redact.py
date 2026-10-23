"""Keep secrets (tokens, DSID, cookies, emails) out of logs and error payloads."""
from __future__ import annotations

import logging
import re
from typing import Any

_SENSITIVE_KEYS = {
    "password",
    "passwordtoken",
    "x-token",
    "dspersonid",
    "dsid",
    "x-dsid",
    "icloud-dsid",
    "directoryservicesidentifier",
    "cookie",
    "set-cookie",
    "authorization",
    "x-apple-actionsignature",
    "sinf",
    "sinfs",
    "apple-id",
    "appleid",
    "username",
    "email",
    "guid",
    "accountinfo",
    "xtoken",
    "token",
    "mz_at_ssl",
    "storefront-token",
}

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
# key=value / "key": "value" / 'key': 'value' forms, for free-form strings.
_INLINE_SECRET_RE = re.compile(
    r"""(?ix)
    (["']?(?:passwordToken|password|X-?Token|dsPersonId|dsid|guid|Set-Cookie|Cookie)["']?\s*[:=]\s*)
    (["']?)([^"',}\s;&]+)
    """
)
# Secrets inside URL query strings, e.g. Apple's dialog actions:
# ...accountSummary?xToken=AwIAAAI...&guid=7E07791F27D6 (seen in a real log).
_QUERY_SECRET_RE = re.compile(
    r"(?i)([?&;](?:xToken|x-token|token|passwordToken|password|pwd|guid|dsid|dsPersonId|mt-tid|mt-at)=)([^&#\s'\"]+)"
)

REDACTED = "***"


def redact(value: Any, _depth: int = 0) -> Any:
    """Return a copy of ``value`` with sensitive fields masked."""
    if _depth > 12:
        return REDACTED
    if isinstance(value, dict):
        out = {}
        for key, item in value.items():
            if str(key).lower() in _SENSITIVE_KEYS:
                out[key] = REDACTED
            else:
                out[key] = redact(item, _depth + 1)
        return out
    if isinstance(value, (list, tuple)):
        return [redact(item, _depth + 1) for item in value]
    if isinstance(value, bytes):
        return f"<{len(value)} bytes>"
    if isinstance(value, str):
        return redact_text(value)
    return value


_URL_CREDENTIALS_RE = re.compile(r"(\b[a-z][a-z0-9+.-]*://[^:/@\s]+:)[^@\s]+@", re.I)


# OTA install links carry a capability token in the path:
# /ota/<job id>/<token>/manifest.plist - anyone with it can fetch the IPA.
_OTA_TOKEN_RE = re.compile(r"(/ota/[0-9a-f]{8,}/|%2Fota%2F[0-9a-f]{8,}%2F)[A-Za-z0-9_\-]{16,}(/|%2F)", re.I)


def redact_text(text: str) -> str:
    text = _OTA_TOKEN_RE.sub(lambda m: f"{m.group(1)}{REDACTED}{m.group(2)}", text)
    text = _URL_CREDENTIALS_RE.sub(lambda m: f"{m.group(1)}{REDACTED}@", text)
    text = _QUERY_SECRET_RE.sub(lambda m: f"{m.group(1)}{REDACTED}", text)
    text = _INLINE_SECRET_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}{REDACTED}", text)
    return _EMAIL_RE.sub("<email>", text)


class RedactingFilter(logging.Filter):
    """Last line of defence: scrub anything that slipped into a log message."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:  # noqa: BLE001 - never break logging itself
            return True
        cleaned = redact_text(message)
        if cleaned != message:
            record.msg = cleaned
            record.args = ()
        return True
