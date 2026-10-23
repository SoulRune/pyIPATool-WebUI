"""TLS diagnostics for HTTPS with a private CA: ``check_certificates`` checks
Apple's rules at startup, ``make_ssl_context`` logs how far a failed handshake
got (Python drops those silently)."""
from __future__ import annotations

import datetime as _dt
import logging
import ssl
import threading
from pathlib import Path
from typing import List, Optional

logger = logging.getLogger("ipatool.tls")

# Apple's TLS certificate rules (iOS 13+): SAN, serverAuth, <= 825 days, RSA >= 2048, SHA-2.
_MAX_VALIDITY_DAYS = 825


def check_certificates(cert_path: str, ca_path: Optional[str]) -> None:
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric import ec, rsa
        from cryptography.x509.oid import ExtendedKeyUsageOID
    except Exception:  # noqa: BLE001
        logger.info("install 'cryptography' for a startup certificate check")
        return

    try:
        certs = x509.load_pem_x509_certificates(Path(cert_path).read_bytes())
    except Exception as exc:  # noqa: BLE001
        logger.warning("could not read --cert %s: %s", cert_path, exc)
        return
    leaf = certs[0]
    problems: List[str] = []

    try:
        san = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        names = [str(v) for v in san.get_values_for_type(x509.DNSName)] + [
            str(v) for v in san.get_values_for_type(x509.IPAddress)
        ]
    except x509.ExtensionNotFound:
        names = []
        problems.append("no Subject Alternative Name (iOS ignores the Common Name)")

    try:
        eku = leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        if ExtendedKeyUsageOID.SERVER_AUTH not in eku:
            problems.append("ExtendedKeyUsage lacks serverAuth")
    except x509.ExtensionNotFound:
        problems.append("no ExtendedKeyUsage (iOS requires serverAuth)")

    not_before = getattr(leaf, "not_valid_before_utc", None) or leaf.not_valid_before.replace(tzinfo=_dt.timezone.utc)
    not_after = getattr(leaf, "not_valid_after_utc", None) or leaf.not_valid_after.replace(tzinfo=_dt.timezone.utc)
    days = (not_after - not_before).days
    if days > _MAX_VALIDITY_DAYS:
        problems.append(f"valid for {days} days (Apple accepts at most {_MAX_VALIDITY_DAYS})")
    now = _dt.datetime.now(_dt.timezone.utc)
    if now < not_before or now > not_after:
        problems.append(f"not valid right now (valid {not_before:%Y-%m-%d} .. {not_after:%Y-%m-%d})")

    key = leaf.public_key()
    if isinstance(key, rsa.RSAPublicKey) and key.key_size < 2048:
        problems.append(f"RSA key is only {key.key_size} bits (need 2048+)")
    if not isinstance(key, (rsa.RSAPublicKey, ec.EllipticCurvePublicKey)):
        problems.append(f"unusual key type {type(key).__name__}")
    algorithm = leaf.signature_hash_algorithm.name if leaf.signature_hash_algorithm else "?"
    if algorithm in ("sha1", "md5"):
        problems.append(f"signed with {algorithm}")

    issued_by_ca = None
    if ca_path:
        try:
            ca = x509.load_pem_x509_certificates(Path(ca_path).read_bytes())[0]
            try:
                leaf.verify_directly_issued_by(ca)
                issued_by_ca = True
            except Exception:  # noqa: BLE001
                issued_by_ca = False
                problems.append(
                    "NOT issued by the --ca-file root: devices trusting that root will reject this certificate "
                    "(regenerate the cert with the same mkcert CAROOT, or point --ca-file at the right rootCA.pem)"
                )
        except Exception as exc:  # noqa: BLE001
            problems.append(f"could not read --ca-file: {exc}")

    logger.info(
        "TLS certificate: names=%s, valid %s..%s (%d days), %s key, %s signature%s",
        ", ".join(names) or "-",
        f"{not_before:%Y-%m-%d}",
        f"{not_after:%Y-%m-%d}",
        days,
        f"RSA-{key.key_size}" if isinstance(key, rsa.RSAPublicKey) else type(key).__name__,
        algorithm,
        "" if issued_by_ca is None else (", issued by --ca-file root: yes" if issued_by_ca else ", issued by --ca-file root: NO"),
    )
    for problem in problems:
        logger.warning("TLS certificate problem: %s", problem)


# ---------------------------------------------------------------------------
# Handshake tracing
# ---------------------------------------------------------------------------

_trace = threading.local()


def _message_name(content_type, msg_type) -> str:
    try:
        if content_type == ssl._TLSContentType.HANDSHAKE:
            return ssl._TLSMessageType(msg_type).name
        if content_type == ssl._TLSContentType.ALERT:
            return "ALERT"
        return ssl._TLSContentType(content_type).name
    except Exception:  # noqa: BLE001
        return f"{content_type}/{msg_type}"


def _on_message(conn, direction, version, content_type, msg_type, data) -> None:
    events = getattr(_trace, "events", None)
    if events is None or (direction == "read" and msg_type == getattr(ssl._TLSMessageType, "CLIENT_HELLO", 1)
                          and content_type == ssl._TLSContentType.HANDSHAKE):
        events = _trace.events = []
        _trace.version = None
    if content_type == ssl._TLSContentType.HEADER:
        return
    name = _message_name(content_type, msg_type)
    if content_type == ssl._TLSContentType.ALERT and len(data) >= 2:
        try:
            name = f"ALERT {ssl._TLSAlertType(data[1]).name}"
        except Exception:  # noqa: BLE001
            name = f"ALERT {data[1]}"
    events.append(("client:" if direction == "read" else "server:") + name)
    if len(events) > 24:
        del events[:-24]


def handshake_summary() -> str:
    events = getattr(_trace, "events", None) or []
    _trace.events = None
    shown = [e for e in events if not e.endswith(("INNER_CONTENT_TYPE", "CHANGE_CIPHER_SPEC"))]
    got_hello = any(e == "client:CLIENT_HELLO" for e in events)
    sent_certificate = any(e == "server:CERTIFICATE" for e in events)
    client_alert = next((e for e in events if e.startswith("client:ALERT")), None)
    if not got_hello:
        verdict = "client closed before sending a TLS hello (port check / speculative connection - usually harmless)"
    elif client_alert:
        verdict = f"client rejected the handshake ({client_alert.split('ALERT ', 1)[1]})"
    elif sent_certificate:
        verdict = ("client received the certificate and closed without saying why - on Apple devices this "
                   "usually means it doesn't trust the certificate or it violates Apple's certificate rules")
    else:
        verdict = "failed before the certificate was sent (TLS version/cipher negotiation)"
    return f"{verdict} [{' '.join(shown) or '-'}]"


def make_ssl_context(cert: str, key: str) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    try:
        context._msg_callback = _on_message  # CPython 3.8+, private but stable
    except Exception:  # noqa: BLE001
        pass
    return context
