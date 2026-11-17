"""Apple's machine verification ("anisette") for App Store sign-in.

Port of ipatool ``internal/storeauth`` (ipatool 2.8, MIT). Since November 2026
the Store's sign-in endpoint wants machine-verification headers next to the
SAP signature:

1. ``anisette_headers``: a local software identity is provisioned with
   Apple's GSA service (``startMachineProvisioning`` /
   ``finishMachineProvisioning``) and the emulated ADI produces the
   X-Apple-I-MD one-time password for it.
2. ``provision_store_anisette``: when the sign-in answers with the ``SP``
   machine action, the Store-specific provisioning is completed against
   ``auth.itunes.apple.com``.
3. ``store_amd_headers``: AppleMediaServices' own proof (X-Apple-AMD...) for
   sign-in and the commerce download requests, computed by the emulated
   framework in ``store_emulator``.

The state that ties these together (a random 16-byte identity, the ADI
database and Apple's routing info) is kept per signed-in account, encrypted
with the rest of the session. It is JSON compatible with ipatool's
``anisette-v4`` keychain item.
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import plistlib
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional, Tuple

import requests

from .errors import AppStoreError

logger = logging.getLogger(__name__)

_LIMIT = 1 << 20
MACHINE_DSID = (1 << 64) - 2  # ^uint64(1)
STORE_DSID = (1 << 64) - 1  # ^uint64(0)
_START_URL = "https://gsa.apple.com/grandslam/MidService/startMachineProvisioning"
_FINISH_URL = "https://gsa.apple.com/grandslam/MidService/finishMachineProvisioning"
CLIENT_INFO = "<MacBookPro13,3> <Mac OS X;10.12.6;16G29> <com.apple.AuthKit/1 (com.apple.akd/1.0)>"
_USER_AGENT = "akd/1.0 CFNetwork/811.5.4 Darwin/16.7.0"
_TIMEOUT = (15, 30)

# gsa.apple.com is signed by Apple's own root, which public CA bundles don't
# carry. ipatool downloads it on demand; it's pinned here instead (SHA-256
# B0B1730E CBC7FF45 05142C49 F1295E6E DA6BCAED 7E2C68C5 BE91B5A1 1001F024).
APPLE_ROOT_CA = """-----BEGIN CERTIFICATE-----
MIIEuzCCA6OgAwIBAgIBAjANBgkqhkiG9w0BAQUFADBiMQswCQYDVQQGEwJVUzET
MBEGA1UEChMKQXBwbGUgSW5jLjEmMCQGA1UECxMdQXBwbGUgQ2VydGlmaWNhdGlv
biBBdXRob3JpdHkxFjAUBgNVBAMTDUFwcGxlIFJvb3QgQ0EwHhcNMDYwNDI1MjE0
MDM2WhcNMzUwMjA5MjE0MDM2WjBiMQswCQYDVQQGEwJVUzETMBEGA1UEChMKQXBw
bGUgSW5jLjEmMCQGA1UECxMdQXBwbGUgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkx
FjAUBgNVBAMTDUFwcGxlIFJvb3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
ggEKAoIBAQDkkakJH5HbHkdQ6wXtXnmELes2oldMVeyLGYne+Uts9QerIjAC6Bg+
+FAJ039BqJj50cpmnCRrEdCju+QbKsMflZ56DKRHi1vUFjczy8QPTc4UadHJGXL1
XQ7Vf1+b8iUDulWPTV0N8WQ1IxVLFVkds5T39pyez1C6wVhQZ48ItCD3y6wsIG9w
tj8BMIy3Q88PnT3zK0koGsj+zrW5DtleHNbLPbU6rfQPDgCSC7EhFi501TwN22IW
q6NxkkdTVcGvL0Gz+PvjcM3mo0xFfh9Ma1CWQYnEdGILEINBhzOKgbEwWOxaBDKM
aLOPHd5lc/9nXmW8Sdh2nzMUZaF3lMktAgMBAAGjggF6MIIBdjAOBgNVHQ8BAf8E
BAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUK9BpR5R2Cf70a40uQKb3
R01/CF4wHwYDVR0jBBgwFoAUK9BpR5R2Cf70a40uQKb3R01/CF4wggERBgNVHSAE
ggEIMIIBBDCCAQAGCSqGSIb3Y2QFATCB8jAqBggrBgEFBQcCARYeaHR0cHM6Ly93
d3cuYXBwbGUuY29tL2FwcGxlY2EvMIHDBggrBgEFBQcCAjCBthqBs1JlbGlhbmNl
IG9uIHRoaXMgY2VydGlmaWNhdGUgYnkgYW55IHBhcnR5IGFzc3VtZXMgYWNjZXB0
YW5jZSBvZiB0aGUgdGhlbiBhcHBsaWNhYmxlIHN0YW5kYXJkIHRlcm1zIGFuZCBj
b25kaXRpb25zIG9mIHVzZSwgY2VydGlmaWNhdGUgcG9saWN5IGFuZCBjZXJ0aWZp
Y2F0aW9uIHByYWN0aWNlIHN0YXRlbWVudHMuMA0GCSqGSIb3DQEBBQUAA4IBAQBc
NplMLXi37Yyb3PN3m/J20ncwT8EfhYOFG5k9RzfyqZtAjizUsZAS2L70c5vu0mQP
y3lPNNiiPvl4/2vIB+x9OYOLUyDTOMSxv5pPCmv/K/xZpwUJfBdAVhEedNO3iyM7
R6PVbyTi69G3cN8PReEnyvFteO3ntRcXqNx+IjXKJdXZD9Zr1KIkIxH3oayPc4Fg
xhtbCS+SsvhESPBgOJ4V9T0mZyCKM2r3DYLP3uujL/lTaltkwGMzd/c6ByxW69oP
IQ7aunMZT7XZNn/Bh1XZp5m5MkL72NVxnn6hUrcbvZNCJBIqxw8dtk2cXmPIS4AX
UKqK1drk/NAJBzewdXUh
-----END CERTIFICATE-----
"""

_ca_lock = threading.Lock()


class AnisetteError(AppStoreError):
    """Machine verification failed (provisioning, emulation or Apple's answer)."""


@dataclass
class AnisetteState:
    identifier: bytes
    provisioning: bytes = b""
    routing_info: int = 0

    @classmethod
    def decode(cls, encoded: Optional[bytes]) -> "AnisetteState":
        """decodeAnisetteState: an empty state is a new random identity."""
        if not encoded:
            return cls(identifier=os.urandom(16))
        try:
            raw = json.loads(encoded)
            identifier = base64.b64decode(raw.get("Identifier") or "")
            provisioning = base64.b64decode(raw.get("Provisioning") or "")
            routing = int(raw.get("RoutingInfo") or 0)
        except (ValueError, TypeError, AttributeError) as exc:
            raise AnisetteError("invalid persisted anisette state") from exc
        if len(identifier) != 16 or len(provisioning) > _LIMIT or not 0 <= routing < 1 << 64:
            raise AnisetteError("invalid persisted anisette state")
        return cls(identifier=identifier, provisioning=provisioning, routing_info=routing)

    def encode(self) -> bytes:
        return json.dumps({
            "Identifier": base64.b64encode(self.identifier).decode("ascii"),
            "Provisioning": base64.b64encode(self.provisioning).decode("ascii") if self.provisioning else None,
            "RoutingInfo": self.routing_info,
        }, separators=(",", ":")).encode("ascii")


def identity_headers(identifier: bytes) -> Tuple[str, str]:
    """(X-Apple-I-MD-LU, X-Mme-Device-Id) derived from the identity."""
    encoded = identifier.hex()
    device_id = f"{encoded[0:8]}-{encoded[8:12]}-{encoded[12:16]}-{encoded[16:20]}-{encoded[20:32]}"
    return hashlib.sha256(identifier).hexdigest(), device_id


def _headers_for(state: AnisetteState, otp: bytes, mid: bytes) -> Dict[str, str]:
    local_user, device_id = identity_headers(state.identifier)
    return {
        "X-Apple-I-Client-Time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "X-Apple-I-MD": base64.b64encode(otp).decode("ascii"),
        "X-Apple-I-MD-M": base64.b64encode(mid).decode("ascii"),
        "X-Apple-I-MD-RINFO": str(state.routing_info),
        "X-Apple-I-MD-LU": local_user,
        "X-Apple-I-SRL-NO": "0",
        # What ipatool sends: Go's name for the process's local zone.
        "X-Apple-I-TimeZone": "Local",
        "X-Apple-Locale": "en_US",
        "X-Mme-Device-Id": device_id,
        "X-MMe-Client-Info": CLIENT_INFO,
    }


def _header_value(value: object, limit: int) -> bool:
    return isinstance(value, str) and 0 < len(value) <= limit and all(" " <= c <= "~" for c in value)


def gsa_verify(verify, storage_dir: Path):
    """The ``verify`` argument for gsa.apple.com: the configured CA bundle
    (or the default one) plus Apple's root, written once next to the
    session data. ``False`` stays ``False``."""
    if verify is False:
        return False
    base = verify if isinstance(verify, str) and verify else None
    if base is None:
        # As requests does for verify=True.
        base = os.environ.get("REQUESTS_CA_BUNDLE") or os.environ.get("CURL_CA_BUNDLE") or None
    if base is None:
        try:
            import certifi

            base = certifi.where()
        except ImportError:
            base = requests.utils.DEFAULT_CA_BUNDLE_PATH
    with _ca_lock:
        try:
            content = Path(base).read_bytes()
        except OSError as exc:
            raise AnisetteError(f"the CA bundle for Apple's machine verification can't be read ({base}); "
                                "set a CA bundle file, not a directory") from exc
        if not content.endswith(b"\n"):
            content += b"\n"
        content += APPLE_ROOT_CA.encode("ascii")
        digest = hashlib.sha256(content).hexdigest()[:16]
        path = Path(storage_dir) / f"ca-apple-{digest}.pem"
        if not path.is_file():
            from .securefile import atomic_write_bytes

            path.parent.mkdir(parents=True, exist_ok=True)
            atomic_write_bytes(path, content)
            for old in path.parent.glob("ca-apple-*.pem"):
                if old != path:
                    try:
                        old.unlink()
                    except OSError:
                        pass
        return str(path)


def _send_machine_provisioning(session: requests.Session, verify, endpoint: str, identifier: bytes,
                               values: Dict[str, object]) -> Dict[str, object]:
    body = plistlib.dumps({"Header": {}, "Request": values}, fmt=plistlib.FMT_XML)
    local_user, device_id = identity_headers(identifier)
    headers = {
        "Accept": "*/*",
        "Connection": "close",
        "Content-Type": "text/x-xml-plist",
        "User-Agent": _USER_AGENT,
        "X-Apple-I-MD-LU": local_user,
        "X-MMe-Client-Info": CLIENT_INFO,
        "X-Mme-Device-Id": device_id,
    }
    step = endpoint.rsplit("/", 1)[-1]
    try:
        response = session.post(endpoint, data=body, headers=headers, timeout=_TIMEOUT, verify=verify,
                                allow_redirects=False, stream=True)
    except requests.RequestException as exc:
        raise AnisetteError(f"machine verification ({step}): {exc.__class__.__name__} connecting to "
                            "gsa.apple.com") from exc
    try:
        data = response.raw.read(_LIMIT + 1, decode_content=True)
    except Exception as exc:  # noqa: BLE001 - urllib3 read errors vary
        raise AnisetteError(f"machine verification ({step}): reading Apple's answer failed") from exc
    finally:
        response.close()
    if response.status_code != 200 or len(data) > _LIMIT:
        raise AnisetteError(f"machine verification ({step}) returned HTTP {response.status_code}")
    try:
        envelope = plistlib.loads(data)
    except Exception as exc:  # noqa: BLE001 - plistlib raises several types
        raise AnisetteError(f"machine verification ({step}): undecodable answer") from exc
    result = envelope.get("Response") if isinstance(envelope, dict) else None
    if not isinstance(result, dict):
        raise AnisetteError(f"machine verification ({step}): undecodable answer")
    return result


def _provisioning_string(values: Dict[str, object], key: str) -> str:
    value = values.get(key)
    if not _header_value(value, 32768):
        raise AnisetteError(f"machine verification: Apple's answer has no {key}")
    return value  # type: ignore[return-value]


def _provisioning_field(values: Dict[str, object], key: str) -> bytes:
    try:
        decoded = base64.b64decode(_provisioning_string(values, key), validate=True)
    except ValueError as exc:
        raise AnisetteError(f"machine verification: invalid {key}") from exc
    if not decoded or len(decoded) > _LIMIT:
        raise AnisetteError(f"machine verification: invalid {key}")
    return decoded


def anisette_headers(session: requests.Session, verify, bundle, encoded: Optional[bytes]) -> Tuple[Dict[str, str], bytes]:
    """AnisetteHeaders: provision the identity with GSA and return fresh
    X-Apple-I-MD headers plus the updated state to persist."""
    from .sap.errors import SAPError
    from .sap.modern_adi import ModernADI

    state = AnisetteState.decode(encoded)
    # Store provisioning replaces the ADI database; machine provisioning
    # always starts again from the persisted identity.
    state.provisioning = b""
    state.routing_info = 0
    try:
        adi = ModernADI(bundle, state.identifier)
    except SAPError as exc:
        raise AnisetteError(f"open machine verification runtime: {exc}") from exc
    try:
        start = _send_machine_provisioning(session, verify, _START_URL, state.identifier, {})
        spim = _provisioning_field(start, "spim")
        try:
            cpim, provisioning_session = adi.start_provisioning(MACHINE_DSID, spim)
        except SAPError as exc:
            raise AnisetteError(f"start machine provisioning: {exc}") from exc
        finish = _send_machine_provisioning(session, verify, _FINISH_URL, state.identifier,
                                            {"cpim": base64.b64encode(cpim).decode("ascii")})
        ptm = _provisioning_field(finish, "ptm")
        trust_key = _provisioning_field(finish, "tk")
        routing = _provisioning_string(finish, "X-Apple-I-MD-RINFO")
        try:
            state.routing_info = int(routing, 10)
        except ValueError:
            state.routing_info = 0
        if not 0 < state.routing_info < 1 << 64:
            raise AnisetteError("machine verification: invalid routing information")
        try:
            adi.end_provisioning(provisioning_session, ptm, trust_key)
            mid, otp = adi.request_otp(MACHINE_DSID)
            state.provisioning = adi.state()
        except SAPError as exc:
            raise AnisetteError(f"machine verification proof: {exc}") from exc
    finally:
        adi.close()
    return _headers_for(state, otp, mid), state.encode()


def provision_store_anisette(session: requests.Session, verify, bundle, encoded: bytes, challenge: str,
                             endpoint: str, user_agent: str, kbsync: str, hardware_id: bytes,
                             identity: Dict[str, str]) -> bytes:
    """ProvisionStoreAnisette: the Store's own provisioning step, requested
    by the sign-in's ``SP`` machine action. Returns the updated state."""
    from .sap.errors import SAPError
    from .sap.modern_adi import ModernADI

    state = AnisetteState.decode(encoded)
    try:
        spim = base64.b64decode(challenge.strip(), validate=True)
    except ValueError as exc:
        raise AnisetteError("invalid Store provisioning data from Apple") from exc
    if not spim or len(spim) > _LIMIT:
        raise AnisetteError("invalid Store provisioning data from Apple")
    try:
        adi = ModernADI(bundle, state.identifier)
    except SAPError as exc:
        raise AnisetteError(f"open machine verification runtime: {exc}") from exc
    try:
        try:
            cpim, provisioning_session = adi.start_provisioning(STORE_DSID, spim)
        except SAPError as exc:
            raise AnisetteError(f"start Store provisioning: {exc}") from exc
        payload: Dict[str, object] = {"clientData": base64.b64encode(cpim).decode("ascii")}
        if kbsync:
            payload["kbsync"] = kbsync
        setting_value, transport_value, keybag = _finish_store_provisioning(
            session, payload, endpoint, user_agent, identity)
        setting_info = _store_value(setting_value, "settingInfo")
        transport_key = _store_value(transport_value, "transportKey")
        try:
            adi.end_provisioning(provisioning_session, setting_info, transport_key)
        except SAPError as exc:
            raise AnisetteError(f"finish Store provisioning (setting info {len(setting_info)} bytes, "
                                f"transport key {len(transport_key)} bytes): {exc}") from exc
        if keybag:
            try:
                adi.import_keybag(hardware_id, keybag)
            except SAPError as exc:
                raise AnisetteError(f"import the Store's FairPlay keybag: {exc}") from exc
        try:
            state.provisioning = adi.state()
        except SAPError as exc:
            raise AnisetteError(f"keep Store provisioning: {exc}") from exc
    finally:
        adi.close()
    return state.encode()


def _finish_store_provisioning(session: requests.Session, payload: Dict[str, object], endpoint: str,
                               user_agent: str, identity: Dict[str, str]) -> Tuple[str, str, bytes]:
    body = plistlib.dumps(payload, fmt=plistlib.FMT_XML)
    headers = {key: value for key, value in identity.items()
               if key.lower() not in ("x-apple-i-md", "x-apple-i-md-m", "x-apple-i-md-rinfo")}
    headers["Accept"] = "*/*"
    headers["Content-Type"] = "application/x-apple-plist"
    headers["User-Agent"] = user_agent
    try:
        response = session.post(endpoint, data=body, headers=headers, timeout=_TIMEOUT, allow_redirects=False,
                                stream=True)
    except requests.RequestException as exc:
        raise AnisetteError(f"Store provisioning: {exc.__class__.__name__} connecting to Apple") from exc
    try:
        data = response.raw.read(_LIMIT + 1, decode_content=True)
    except Exception as exc:  # noqa: BLE001
        raise AnisetteError("Store provisioning: reading Apple's answer failed") from exc
    finally:
        response.close()
    if len(data) > _LIMIT:
        raise AnisetteError("Store provisioning: Apple's answer is too large")
    if response.status_code != 200:
        raise AnisetteError(f"Store provisioning returned HTTP {response.status_code}")
    try:
        result = plistlib.loads(data)
    except Exception as exc:  # noqa: BLE001
        raise AnisetteError("Store provisioning: undecodable answer") from exc
    if not isinstance(result, dict):
        raise AnisetteError("Store provisioning: undecodable answer")
    setting_info = result.get("settingInfo")
    if not _header_value(setting_info, _LIMIT):
        raise AnisetteError("Store provisioning answer has no settingInfo")
    transport_key = result.get("transportKey")
    if not _header_value(transport_key, _LIMIT):
        raise AnisetteError("Store provisioning answer has no transportKey")
    keybag = result.get("keybag")
    if isinstance(keybag, str):
        try:
            keybag = base64.b64decode(keybag)
        except ValueError:
            keybag = b""
    if not isinstance(keybag, (bytes, bytearray)):
        keybag = b""
    if len(keybag) > _LIMIT:
        raise AnisetteError("Store provisioning answer has an invalid keybag")
    return setting_info, transport_key, bytes(keybag)  # type: ignore[return-value]


def _store_value(value: str, key: str) -> bytes:
    try:
        decoded = base64.b64decode(value, validate=True)
    except ValueError as exc:
        raise AnisetteError(f"invalid Store provisioning {key}") from exc
    if not decoded or len(decoded) > _LIMIT:
        raise AnisetteError(f"invalid Store provisioning {key}")
    return decoded


def _media_segments(bundle):
    """AppleMediaServices as loaded by the Store runtime: its segments at
    their shared-cache addresses, pointer authentication removed."""
    from .sap import macho

    image = macho.PrelinkedImage("AppleMediaServices", bundle.apple_media_services,
                                 pac_stripped=bool(getattr(bundle, "pac_stripped", False)))
    return [(s.address, s.size, bytes(image.data[s.file_offset:s.file_offset + s.file_size]))
            for s in image.segments if s.name != "__LINKEDIT" and s.size]


def store_amd_headers(bundle, encoded: bytes, endpoint: str, hardware_id: bytes) -> Tuple[Dict[str, str], bytes]:
    """StoreAMDHeaders: AppleMediaServices' own proof (X-Apple-AMD,
    X-Apple-AMD-M) for a request to ``endpoint``, computed with the
    Store-provisioned identity; returns the headers and the updated state."""
    from .sap.errors import SAPError
    from .sap.modern_adi import ModernADI
    from .store_emulator import EmulatorError, amd_headers

    state = AnisetteState.decode(encoded)
    if not state.provisioning:
        raise AnisetteError("the Store machine verification isn't provisioned yet; sign in again")
    try:
        adi = ModernADI(bundle, state.identifier, state.provisioning)
    except SAPError as exc:
        raise AnisetteError(f"open machine verification runtime: {exc}") from exc
    try:
        def exchange(service: str, request: bytes) -> bytes:
            if service != "com.apple.adid":
                raise AnisetteError(f"unsupported Store AMD XPC service {service}")
            return adi.exchange_xpc(request)

        try:
            headers = amd_headers(_media_segments(bundle), endpoint, hardware_id, exchange)
        except (EmulatorError, SAPError) as exc:
            raise AnisetteError(f"Store machine verification proof: {exc}") from exc
        try:
            state.provisioning = adi.state()
        except SAPError as exc:
            raise AnisetteError(f"keep Store machine verification state: {exc}") from exc
    finally:
        adi.close()
    return headers, state.encode()
