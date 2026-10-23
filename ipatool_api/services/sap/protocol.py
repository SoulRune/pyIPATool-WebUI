"""The HTTP half of the SAP setup handshake.

Port of ``internal/sap/protocol.go`` (ipatool v2.6.0, MIT). Two calls against
Apple, whose endpoints come from the bag:

  * GET  the setup certificate            -> plist with key ``sign-sap-setup-cert``
  * POST the guest's setup message        -> plist with key ``sign-sap-setup-buffer``

Both bodies are Apple plists carrying raw bytes; ``plistlib`` handles them.
"""
from __future__ import annotations

import plistlib
from typing import Optional

import requests

from .errors import SAPError

_SETUP_CERT_KEY = "sign-sap-setup-cert"
_SETUP_BUFFER_KEY = "sign-sap-setup-buffer"
_MAX_SETUP_BODY = 1 << 20
from .. import constants as _constants

_USER_AGENT = _constants.DEFAULT_USER_AGENT


class SetupProtocol:
    def __init__(self, session: Optional[requests.Session] = None, verify=True, timeout: float = 30.0) -> None:
        self._session = session or requests.Session()
        self._verify = verify
        self._timeout = timeout

    def certificate(self, endpoint: str) -> bytes:
        response = self._session.get(
            endpoint,
            headers={"User-Agent": _USER_AGENT},
            timeout=self._timeout,
            verify=self._verify,
        )
        return _plist_bytes(self._body(response), _SETUP_CERT_KEY)

    def exchange(self, endpoint: str, message: bytes) -> bytes:
        envelope = plistlib.dumps({_SETUP_BUFFER_KEY: message}, fmt=plistlib.FMT_XML)
        response = self._session.post(
            endpoint,
            data=envelope,
            headers={"Content-Type": "application/x-plist", "User-Agent": _USER_AGENT},
            timeout=self._timeout,
            verify=self._verify,
        )
        return _plist_bytes(self._body(response), _SETUP_BUFFER_KEY)

    def _body(self, response: requests.Response) -> bytes:
        if response.status_code != 200:
            raise SAPError(f"Apple SAP setup returned HTTP {response.status_code}")
        body = response.content
        if len(body) > _MAX_SETUP_BODY:
            raise SAPError(f"Apple SAP setup response exceeds {_MAX_SETUP_BODY} bytes")
        return body


def _plist_bytes(document: bytes, key: str) -> bytes:
    try:
        values = plistlib.loads(document)
    except Exception as exc:  # noqa: BLE001
        raise SAPError(f"failed to decode Apple SAP plist: {exc}") from exc
    value = values.get(key) if isinstance(values, dict) else None
    if not isinstance(value, (bytes, bytearray)) or not value:
        raise SAPError(f"Apple SAP plist is missing {key}")
    return bytes(value)
