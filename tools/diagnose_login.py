#!/usr/bin/env python3
"""Step-by-step diagnostics for App Store sign-in.

    python tools/diagnose_login.py                  # probe with a made-up account (safe default)
    python tools/diagnose_login.py --email you@x.y  # your account (password asked, hidden)
    python tools/diagnose_login.py --attempts 3     # repeat the sign-in request

It walks the exact path the server takes - same code, same bytes - and shows
every step: environment, DNS/TLS to each Apple host (incl. who issued the
certificate, to catch antivirus/proxy TLS interception), the bag, the SAP
signer, and the sign-in request/response in full. A control request without
a signature is sent too, for comparison.

Nothing sensitive is printed: password, tokens, DSID, cookie values, the
signature, e-mail addresses and the device GUID are masked. The same text is
saved to a report file that is safe to share. Nothing is stored: the session
lives in memory only and your server sessions are untouched.
"""
from __future__ import annotations

import argparse
import datetime as dt
import getpass
import hashlib
import html
import platform
import plistlib
import re
import socket
import ssl
import sys
import time
from email.utils import parsedate_to_datetime
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import getproxies

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import requests  # noqa: E402

from ipatool_api.services import constants, netconfig  # noqa: E402
from ipatool_api.services.appstore import (  # noqa: E402
    AppStoreConfig,
    AppStoreService,
    hardware_id_from_guid,
    normalize_auth_code,
    validate_authentication_endpoint,
)
from ipatool_api.services.errors import AppStoreError  # noqa: E402
from ipatool_api.services.http_client import HTTPRequest, XMLPayload, _normalize_plist_body  # noqa: E402
from ipatool_api.services.machine import Machine  # noqa: E402
from ipatool_api.services.redact import redact, redact_text  # noqa: E402
from ipatool_api.services.state import BrowserState  # noqa: E402

PROBE_EMAIL = "pyipatool-diagnostics-probe@example.com"
PROBE_PASSWORD = "not-a-real-password-0"
HOSTS = ["init.itunes.apple.com", "s.mzstatic.com", "fpinit.itunes.apple.com", "buy.itunes.apple.com"]

# Keys whose *values* are secret in Apple's responses/requests.
SECRET_KEYS = {
    "password", "passwordtoken", "dspersonid", "dsid", "x-dsid", "icloud-dsid", "x-token",
    "x-apple-actionsignature", "cookie", "set-cookie", "authorization", "clearToken".lower(),
    "appleid", "apple-id", "email", "username", "guid", "creditbalance", "accountinfo",
}


# ---------------------------------------------------------------------------
# output
# ---------------------------------------------------------------------------


class Report:
    def __init__(self) -> None:
        self.lines = []
        self.verdicts = []

    def out(self, text: str = "") -> None:
        text = scrub(text)
        self.lines.append(text)
        try:
            print(text)
        except UnicodeEncodeError:  # old Windows console code pages
            print(text.encode("ascii", "replace").decode("ascii"))

    def head(self, title: str) -> None:
        self.out("")
        self.out("=" * 78)
        self.out(title)
        self.out("=" * 78)

    def item(self, label: str, value) -> None:
        self.out(f"  {label:<28} {value}")

    def verdict(self, level: str, text: str) -> None:
        self.verdicts.append((level, text))
        self.out(f"  [{level}] {text}")


_state = {"email": None, "guid": None}


def mask_email(email: str) -> str:
    if not email or "@" not in email:
        return "***"
    user, _, domain = email.partition("@")
    return f"{user[:1]}***@{domain}"


def mask_guid(guid: str) -> str:
    return f"{guid[:2]}********{guid[-2:]}" if guid and len(guid) > 4 else "***"


def scrub(text: str) -> str:
    """Final safety net over everything printed or saved."""
    if _state["email"]:
        text = text.replace(_state["email"], mask_email(_state["email"]))
    if _state["guid"]:
        text = text.replace(_state["guid"], mask_guid(_state["guid"]))
        text = text.replace(_state["guid"].lower(), mask_guid(_state["guid"]))
    return redact_text(text)


def fingerprint(data: bytes) -> str:
    return f"{len(data)} bytes, sha256 {hashlib.sha256(data).hexdigest()[:12]}..."


def safe_headers(headers) -> list:
    out = []
    for key, value in headers.items():
        lower = str(key).lower()
        if lower in ("set-cookie", "cookie"):
            names = re.findall(r"(?:^|[;,]\s*)([A-Za-z0-9_\-]+)=", str(value))
            names = [n for n in names if n.lower() not in ("path", "domain", "expires", "max-age")]
            out.append((key, f"<{len(str(value))} chars; cookie names: {', '.join(sorted(set(names))) or '?'}>"))
        elif lower in SECRET_KEYS:
            out.append((key, f"<hidden, {len(str(value))} chars>"))
        else:
            out.append((key, str(value)))
    return out


def describe_body(body: bytes, content_type: str) -> list:
    """Human summary of a response body without leaking secrets."""
    lines = [f"length: {len(body)} bytes, content-type: {content_type or '-'}"]
    if not body:
        return lines + ["(empty body)"]
    try:
        data = plistlib.loads(_normalize_plist_body(body))
        lines.append("format: plist")
        if isinstance(data, dict):
            lines.append("keys: " + ", ".join(sorted(map(str, data.keys()))))
            for key in ("failureType", "customerMessage", "m-allowed", "jingleDocType", "status"):
                if key in data:
                    lines.append(f"{key}: {redact(data[key])!r}")
            present = [k for k in data if str(k).lower() in SECRET_KEYS]
            if present:
                lines.append("secret fields present (values hidden): " + ", ".join(present))
        return lines
    except Exception:  # noqa: BLE001
        pass
    text = body.decode("utf-8", "replace")
    if "html" in (content_type or "").lower() or text.lstrip().startswith("<"):
        title = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
        plain = re.sub(r"<[^>]+>", " ", text)
        plain = html.unescape(re.sub(r"\s+", " ", plain)).strip()
        lines.append("format: HTML")
        if title:
            lines.append("title: " + title.group(1).strip()[:120])
        lines.append("text: " + plain[:300])
    else:
        lines.append("format: text/other")
        lines.append("text: " + re.sub(r"\s+", " ", text)[:300])
    return lines


# ---------------------------------------------------------------------------
# steps
# ---------------------------------------------------------------------------


def step_environment(r: Report) -> None:
    r.head("1. Environment")
    r.item("OS", f"{platform.system()} {platform.release()} ({platform.machine()})")
    r.item("Python", sys.version.split()[0])
    r.item("OpenSSL", ssl.OPENSSL_VERSION)
    r.item("requests", requests.__version__)
    try:
        import urllib3

        r.item("urllib3", urllib3.__version__)
    except Exception:  # noqa: BLE001
        pass
    try:
        import unicorn

        r.item("unicorn", unicorn.__version__)
    except Exception as exc:  # noqa: BLE001
        r.verdict("FAIL", f"unicorn not importable: {exc}")
    if netconfig.active():
        r.item("proxy (--proxy)", netconfig.active())
    else:
        proxies = {k: netconfig.mask(v) if "://" in str(v) else v for k, v in getproxies().items() if k in ("http", "https", "all")}
        r.item("proxies (env/system)", proxies or "none")
    r.item("local time (UTC)", dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S"))


def mask_ip(ip: str) -> str:
    if ":" in ip:
        return ":".join(ip.split(":")[:2]) + ":****"
    parts = ip.split(".")
    return ".".join(parts[:2] + ["x", "x"]) if len(parts) == 4 else "***"


def step_exit_address(r: Report) -> None:
    r.head("2a. Where your requests reach the internet from")
    via = netconfig.active()
    r.item("route", f"proxy {via}" if via else "direct (no proxy)")
    try:
        start = time.time()
        info = requests.get("https://ipinfo.io/json", timeout=15).json()
        r.item("exit address", f"{mask_ip(str(info.get('ip', '?')))} ({int((time.time() - start) * 1000)} ms)")
        r.item("country / region", f"{info.get('country', '?')} / {info.get('region', '?')}")
        r.item("network (ASN)", info.get("org", "?"))
    except Exception as exc:  # noqa: BLE001
        r.verdict("WARN", f"could not determine the exit address: {netconfig.describe_error(exc)}")


def step_network_via_proxy(r: Report, hosts) -> bool:
    """Returns False if the proxy let nothing through (no point going on)."""
    r.head("2. HTTPS to Apple hosts (through the proxy)")
    reachable = 0
    session = requests.Session()  # no retry adapter: fail fast on a bad proxy
    for host in hosts:
        try:
            start = time.time()
            response = session.head(f"https://{host}/", timeout=20, allow_redirects=False)
            r.item(host, f"reachable, HTTP {response.status_code}, {int((time.time() - start) * 1000)} ms")
            reachable += 1
        except requests.RequestException as exc:
            r.verdict("FAIL", f"{host}: {netconfig.describe_error(exc)}")
    return reachable > 0


def step_network(r: Report, hosts) -> bool:
    if netconfig.active():
        return step_network_via_proxy(r, hosts)
    r.head("2. DNS / TCP / TLS to Apple hosts")
    for host in hosts:
        r.out(f"- {host}")
        try:
            infos = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
            addresses = sorted({i[4][0] for i in infos})
            r.item("  resolves to", ", ".join(addresses))
            if any(a in ("0.0.0.0", "127.0.0.1", "::", "::1") for a in addresses):
                r.verdict("FAIL", f"{host} resolves to a blackhole address - blocked by DNS/hosts/ad-blocker")
                continue
        except OSError as exc:
            r.verdict("FAIL", f"DNS lookup for {host} failed: {exc}")
            continue
        try:
            context = ssl.create_default_context()
            start = time.time()
            with socket.create_connection((host, 443), timeout=10) as raw:
                with context.wrap_socket(raw, server_hostname=host) as tls:
                    cert = tls.getpeercert()
                    issuer = dict(x[0] for x in cert.get("issuer", ()))
                    subject = dict(x[0] for x in cert.get("subject", ()))
                    r.item("  TLS", f"{tls.version()}, {tls.cipher()[0]}, {int((time.time() - start) * 1000)} ms")
                    r.item("  certificate subject", subject.get("commonName", "?"))
                    r.item("  issued by", f"{issuer.get('organizationName', '?')} / {issuer.get('commonName', '?')}")
                    org = (issuer.get("organizationName", "") + issuer.get("commonName", "")).lower()
                    if not any(k in org for k in ("apple", "digicert", "entrust", "sectigo", "globalsign", "let's encrypt")):
                        r.verdict(
                            "WARN",
                            f"{host}: certificate issued by '{issuer.get('organizationName', '?')}' - looks like TLS "
                            "interception (antivirus 'HTTPS scanning', corporate proxy). Apple rejects signed requests "
                            "that pass through such proxies more often.",
                        )
        except ssl.SSLCertVerificationError as exc:
            r.verdict("FAIL", f"{host}: certificate not trusted by this PC: {exc.verify_message}")
        except OSError as exc:
            r.verdict("FAIL", f"{host}: connection failed: {exc}")
    return True


def make_service(user_agent=None, minimal_headers=False):
    state = BrowserState()  # in-memory: nothing written, server sessions untouched
    machine = Machine()
    service = AppStoreService(AppStoreConfig(state=state, machine=machine, verify=True))
    if user_agent:
        # The client adds constants.DEFAULT_USER_AGENT to *every* request
        # (overriding session headers), and the SAP setup has its own copy:
        # replace both so the override really goes out everywhere.
        from ipatool_api.services.sap import protocol as sap_protocol

        constants.DEFAULT_USER_AGENT = user_agent
        sap_protocol._USER_AGENT = user_agent
        for session in (service._http.session, service._http.signed_session):
            session.headers["User-Agent"] = user_agent
    if minimal_headers:
        # Header set of ipatool's Go client: User-Agent, Content-Type,
        # Content-Length and "Accept-Encoding: gzip" - no Accept, no
        # Connection, no deflate/zstd (requests adds those by default).
        for session in (service._http.session, service._http.signed_session):
            session.headers["Accept-Encoding"] = "gzip"
            session.headers["Accept"] = None
            session.headers["Connection"] = None
    captured = []

    def hook(response, *args, **kwargs):
        captured.append(response)

    for session in (service._http.session, service._http.signed_session):
        session.hooks["response"].append(hook)
    return service, state, captured


def show_exchange(r: Report, response: requests.Response, sent_body: bytes) -> None:
    req = response.request
    r.out(f"  -> {req.method} {req.url.split('?')[0]}{'?<query hidden>' if '?' in req.url else ''}")
    for key, value in safe_headers(req.headers):
        r.out(f"       {key}: {value}")
    if sent_body:
        try:
            body = plistlib.loads(sent_body)
            r.out(f"     body: plist ({len(sent_body)} bytes), fields:")
            for key in sorted(body):
                value = body[key]
                if key in ("attempt", "rmp", "why"):
                    shown = repr(value)
                else:
                    shown = f"hidden ({len(str(value))} chars)"
                # "->" rather than "=": the log scrubber treats "password=..." as a secret to mask
                r.out(f"       {key} -> {shown}")
        except Exception:  # noqa: BLE001
            r.out(f"     body: {fingerprint(sent_body)}")
    r.out(f"  <- HTTP {response.status_code} {response.reason} in {int(response.elapsed.total_seconds() * 1000)} ms")
    for key, value in safe_headers(response.headers):
        r.out(f"       {key}: {value}")
    for line in describe_body(response.content, response.headers.get("Content-Type", "")):
        r.out(f"     {line}")


def step_bag(r: Report, service, captured):
    r.head("3. Bag (init.itunes.apple.com)")
    try:
        bag = service.bag()
    except AppStoreError as exc:
        if captured:
            show_exchange(r, captured[-1], b"")
        r.verdict("FAIL", f"bag failed: {exc}")
        return None
    show_exchange(r, captured[-1], b"")
    r.item("authenticateAccount", bag.auth_endpoint)
    r.item("sign-sap-setup", bag.sap.setup_url)
    r.item("sign-sap-setup-cert", bag.sap.certificate_url)
    r.item("sign-sap-version", bag.sap.version)
    date = captured[-1].headers.get("Date")
    if date:
        skew = (dt.datetime.now(dt.timezone.utc) - parsedate_to_datetime(date)).total_seconds()
        r.item("clock skew vs Apple", f"{skew:+.0f} s")
        if abs(skew) > 120:
            r.verdict("WARN", f"this PC's clock is off by {skew:+.0f}s - fix the time (signed requests may be rejected)")
    r.verdict("OK", "bag fetched and valid")
    return bag


def step_signer(r: Report, service, state, bag):
    r.head("4. SAP signer (Apple's FairPlay code in the emulator)")
    from ipatool_api.services.sap import assets as sap_assets
    cache = service._storage_dir / "sap" / sap_assets.CACHE_VERSION
    r.item("asset cache", "present" if (cache / "AppleMediaServices").exists()
           else "missing (will be read from Apple's macOS restore image, ~100-350 MB, once)")
    guid = state.device_guid()
    _state["guid"] = guid
    r.item("device GUID", mask_guid(guid))
    start = time.time()
    try:
        signer = service._create_signer(bag.sap, hardware_id_from_guid(guid))
    except AppStoreError as exc:
        r.verdict("FAIL", f"signer setup failed: {exc}")
        return None
    r.item("setup (cert + exchange)", f"OK in {time.time() - start:.1f} s")
    sample = signer.sign(b"diagnostics")
    r.item("test signature", f"{len(sample)} bytes (value hidden)")
    r.verdict("OK", "Apple accepted the SAP setup handshake")
    return signer


def login_request(bag, guid, email, password, code, attempt, signer, url=None):
    return HTTPRequest(
        method="POST",
        url=url or bag.auth_endpoint,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        payload=XMLPayload(
            {"appleId": email, "attempt": str(attempt), "guid": guid, "password": f"{password}{code}", "rmp": "0", "why": "signIn"}
        ),
        response_format=constants.ResponseFormatXML,
        follow_redirects=False,
        signer=signer.sign if signer else None,
    )


def send_raw(service, request, captured):
    before = len(captured)
    error = None
    try:
        service._send_request(request)
    except AppStoreError as exc:
        error = exc
    response = captured[-1] if len(captured) > before else None
    return response, error


def classify(response) -> str:
    if response is None:
        return "no response"
    status = response.status_code
    if 300 <= status < 400:
        location = response.headers.get("Location")
        if location:
            host = urlparse(location).hostname or "?"
            return f"redirect to Store pod {host} (normal Apple answer - sign-in continues there)"
        return f"HTTP {status} redirect WITHOUT target"
    try:
        data = plistlib.loads(_normalize_plist_body(response.content))
    except Exception:  # noqa: BLE001
        data = None
    if isinstance(data, dict):
        if data.get("passwordToken"):
            return "SIGNED IN (credentials accepted)"
        if data.get("customerMessage") == constants.CUSTOMER_MESSAGE_BAD_LOGIN:
            return "normal Apple answer: 2FA code required / credentials not accepted"
        if data.get("failureType"):
            return f"normal Apple answer: failureType {data.get('failureType')}"
        return "plist answer (unrecognized)"
    if 300 <= status < 400:
        location = response.headers.get("Location")
        if location:
            host = urlparse(location).hostname or "?"
            return f"redirect to Store pod {host} (normal Apple answer - sign-in continues there)"
        return f"HTTP {status} redirect WITHOUT target"
    return f"HTTP {status}, not a plist - Apple did not process the sign-in"


def step_login(r: Report, service, captured, bag, signer, email, password, attempts):
    guid = _state["guid"]
    r.head("5. Sign-in request (signed, exactly as the server sends it)")
    results = []
    code = ""
    url = None  # set once Apple redirects to the account's Store pod
    for attempt in range(1, attempts + 1):
        r.out(f"- attempt {attempt}")
        hops = 0
        while True:
            # As the server does: after a pod redirect the request is resent to
            # the pod with attempt=1 (ipatool semantics).
            request_attempt = 1 if url else attempt
            response, error = send_raw(
                service, login_request(bag, guid, email, password, code, request_attempt, signer, url), captured
            )
            if response is not None:
                show_exchange(r, response, response.request.body or b"")
            verdict = classify(response)
            r.item("  result", verdict)
            if error is not None:
                r.item("  client error", str(error))
            location = response.headers.get("Location") if response is not None else None
            if response is not None and 300 <= response.status_code < 400 and location and hops < 3:
                try:
                    url = validate_authentication_endpoint(location)
                except AppStoreError as exc:
                    r.verdict("FAIL", f"Apple redirected to an unexpected address: {exc}")
                    break
                hops += 1
                r.out(f"  following Apple's redirect to {urlparse(url).hostname} ...")
                continue
            break
        results.append(verdict)
        if verdict.startswith("SIGNED IN"):
            break
        rejected = not verdict.startswith(("normal Apple answer", "redirect to Store pod", "plist answer"))
        if rejected and attempt < attempts and service is not None:
            # Like the server: a rejected attempt is retried with a fresh SAP
            # session and a new connection (same device GUID and cookies).
            try:
                new_signer = service._create_signer(bag.sap, hardware_id_from_guid(guid))
                signer.close()
                signer = new_signer
                service._http.signed_session.close()
                r.out("  (next attempt uses a fresh SAP session and connection)")
            except AppStoreError as exc:
                r.out(f"  (could not start a fresh SAP session: {exc})")
        if "2FA" in verdict and email != PROBE_EMAIL and not code:
            entered = input("  Apple asks for the 6-digit code (Enter to skip): ").strip()
            if entered:
                try:
                    code = normalize_auth_code(entered)
                except AppStoreError as exc:
                    r.out(f"  {exc}")
        if attempt < attempts:
            time.sleep(3)

    r.head("6. Control: same request WITHOUT the SAP signature")
    response, _ = send_raw(service, login_request(bag, guid, email, password, "", 1, None), captured)
    if response is not None:
        show_exchange(r, response, b"")
    control = classify(response)
    r.item("result", control)
    return results, control, signer


def summarize(r: Report, results, control, probe: bool) -> None:
    r.head("7. Verdict")
    signed = results[-1] if results else "not run"
    r.item("signed request", signed)
    r.item("unsigned control", control)
    processed = [x for x in results if x.startswith(("normal Apple answer", "SIGNED IN", "redirect to Store pod"))]
    if processed:
        r.item("processed by Apple", f"{len(processed)} of {len(results)} attempts")
    if signed.startswith("SIGNED IN"):
        r.verdict("OK", "sign-in works from this machine/network")
    elif signed.startswith("normal Apple answer"):
        if probe:
            r.verdict("OK", "the sign-in API works: Apple processed the signed request normally (the probe account "
                            "doesn't exist, so a 'bad login' answer is expected). If your real account still fails, "
                            "run again with --email to test it.")
        else:
            r.verdict("INFO", "Apple processed the request; the answer is about the account/credentials/2FA.")
    elif "not a plist" in signed or "WITHOUT target" in signed:
        control_rejected = "not a plist" in control or "WITHOUT target" in control
        r.verdict(
            "FAIL",
            "Apple's sign-in endpoint did not process the signed request (empty/HTML/redirect-less answer). "
            + ("The unsigned control was rejected the same way. Apple rotates between 204/301/403/404 for "
               "requests it refuses, so different codes here mean nothing: the signature is simply not "
               "accepted any more. This points to an Apple-side change of the sign-in requirements "
               "(compare ipatool issues), not to this machine or account."
               if control_rejected else
               "The unsigned control was processed normally, so the signature itself is being rejected."),
        )
        r.verdict("INFO", "to rule out network-level blocking, run once more from another network (phone hotspot).")
    fails = [t for level, t in r.verdicts if level in ("FAIL", "WARN")]
    if fails:
        r.out("")
        r.out("  Problems found along the way:")
        for text in fails:
            r.out(f"   - {text}")


def main() -> None:
    parser = argparse.ArgumentParser(description="App Store sign-in diagnostics (safe to share output)")
    parser.add_argument("--email", help="test this Apple ID (password is asked, never shown); default: a made-up probe account")
    parser.add_argument("--attempts", type=int, default=1, help="how many signed sign-in requests to send (default 1)")
    parser.add_argument(
        "--user-agent",
        help="experiment: send this User-Agent to Apple instead of the built-in "
        "Apple Configurator 2.20 string (e.g. to compare client versions)",
    )
    parser.add_argument(
        "--minimal-headers",
        action="store_true",
        help="experiment: send only the headers ipatool's Go client sends (User-Agent, Content-Type, "
        "Accept-Encoding: gzip) instead of Python's defaults",
    )
    parser.add_argument("--proxy", metavar="HOST:PORT", help="send everything through this proxy (host:port or full URL)")
    parser.add_argument("--proxy-type", choices=("http", "https", "socks5"), default="http",
                        help="proxy type for host:port (default http; socks5 resolves DNS via the proxy)")
    parser.add_argument("--proxy-user", help="proxy login (optional)")
    parser.add_argument("--proxy-password", help="proxy password (or IPATOOL_PROXY_PASSWORD; asked if missing)")
    parser.add_argument("--report", help="report file (default: login-diagnostics-<time>.txt in the current folder)")
    args = parser.parse_args()

    if args.proxy:
        proxy_password = netconfig.resolve_password(args.proxy_password)
        if args.proxy_user and proxy_password is None:
            proxy_password = getpass.getpass(f"Password for proxy user {args.proxy_user} (hidden): ")
        try:
            netconfig.configure(netconfig.build_proxy_url(args.proxy, args.proxy_type, args.proxy_user, proxy_password))
        except netconfig.ProxyConfigError as exc:
            raise SystemExit(f"proxy: {exc}")

    probe = not args.email
    email = args.email or PROBE_EMAIL
    password = PROBE_PASSWORD if probe else getpass.getpass("Apple ID password (hidden): ")
    _state["email"] = email

    r = Report()
    r.out("pyIPATool sign-in diagnostics - " + dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    r.out(f"mode: {'probe account (no real credentials)' if probe else 'real account ' + mask_email(email)}")
    step_environment(r)
    step_exit_address(r)
    if not step_network(r, HOSTS):
        r.head("7. Verdict")
        r.verdict("FAIL", "the proxy let no request through - check its address/port, type (http/socks5) "
                          "and login/password. Stopped before contacting Apple's sign-in.")
        save_report(r, args.report)
        return

    if args.user_agent:
        r.out(f"User-Agent override: {args.user_agent}")
    if args.minimal_headers:
        r.out("Headers: minimal (like ipatool's Go client)")
    service, state, captured = make_service(args.user_agent, args.minimal_headers)
    bag = step_bag(r, service, captured)
    results, control = [], "not run"
    if bag is not None:
        extra = urlparse(bag.auth_endpoint).hostname
        if extra and extra not in HOSTS:
            step_network(r, [extra])
        signer = step_signer(r, service, state, bag)
        if signer is not None:
            try:
                results, control, signer = step_login(r, service, captured, bag, signer, email, password, max(1, args.attempts))
            finally:
                signer.close()
    summarize(r, results, control, probe)

    save_report(r, args.report)


def save_report(r: Report, report_path=None) -> None:
    path = Path(report_path or f"login-diagnostics-{dt.datetime.now():%Y%m%d-%H%M%S}.txt")
    path.write_text("\n".join(r.lines) + "\n", encoding="utf-8")
    print(f"\nReport saved to {path.resolve()} (secrets masked - safe to share)")


if __name__ == "__main__":
    main()
