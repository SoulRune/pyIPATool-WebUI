"""pyIPATool WebUI.

    python app.py                     # local mode on http://127.0.0.1:5002
    python app.py --host 0.0.0.0      # network mode: per-browser sessions
    python app.py --legacy            # [Recommended for servers] UI with support for old browsers (iOS 6 Safari or other)

Importing has no side effects, so ``from app import build_app`` works in tests.
"""
from __future__ import annotations

import argparse
import ipaddress
import logging
import logging.handlers
import os
import sys
from pathlib import Path
from typing import List, Optional

LOOPBACK_NAMES = {"localhost", "127.0.0.1", "::1"}

logger = logging.getLogger("ipatool")


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="pyIPATool WebUI")
    parser.add_argument(
        "--legacy",
        action="store_true",
        help="Serve the legacy-compatible UI (plain ES5 JS, prefixed/float-based CSS) for old "
        "browsers such as Mobile Safari on iOS 6.",
    )
    parser.add_argument("--port", type=int, default=5002, help="Port to listen on (default: 5002)")
    parser.add_argument("--host", default="127.0.0.1", help="Host/interface to bind to (default: 127.0.0.1)")
    parser.add_argument("--debug", action="store_true", help="Flask debug mode + verbose (redacted) logging")

    sessions = parser.add_argument_group("sessions & security")
    sessions.add_argument(
        "--session-mode",
        choices=("auto", "local", "browser"),
        default="auto",
        help="'local': one shared account stored in ~/.ipatool (only sensible when the server is "
        "reachable from this machine only). 'browser': every browser signs in with its own Apple ID; "
        "the session lives in an encrypted cookie on that device, nothing per-user is stored on the "
        "server. 'auto' (default): local when --host is a loopback address (and not --behind-proxy), "
        "browser otherwise.",
    )
    sessions.add_argument("--session-days", type=int, default=30, help="Browser session lifetime in days (default: 30)")
    sessions.add_argument(
        "--allow-server-save",
        action="store_true",
        help="In browser mode, still offer 'Save on server' (writes into ~/Downloads/IPATool on this machine). "
        "Always on in local mode.",
    )
    sessions.add_argument(
        "--allow-http",
        action="store_true",
        help="With --behind-proxy: also serve requests that reached the proxy over plain HTTP (by default "
        "pages are redirected to https:// and anything else is refused).",
    )
    sessions.add_argument(
        "--access-password-file",
        metavar="FILE",
        help="A private server: every browser must first enter the password in this file (once, then a 30-day "
        "cookie). Without it anyone who finds the address can use the server. Or env IPATOOL_ACCESS_PASSWORD.",
    )
    sessions.add_argument(
        "--repo-url",
        "--source-url",
        dest="repo_url",
        default=os.environ.get("IPATOOL_REPO_URL") or os.environ.get("IPATOOL_SOURCE_URL", ""),
        metavar="URL",
        help="The project's repository (e.g. on GitHub): a second footer link next to \"Source code\", which "
        "always downloads /source, an archive of this running copy (env IPATOOL_REPO_URL).",
    )
    sessions.add_argument(
        "--trusted-host",
        action="append",
        default=[],
        metavar="HOST",
        help="Allowed Host header value (repeatable). Loopback names are added automatically when bound to "
        "loopback. Recommended when exposing the server under a fixed name/IP.",
    )
    sessions.add_argument(
        "--user-agent",
        help="User-Agent sent to Apple (default: the Apple Configurator 2.17 string ipatool uses). "
        "Apple ties the sign-in to it: after changing it, sign out and in again.",
    )
    sessions.add_argument("--cert", help="TLS certificate (PEM) - serve HTTPS directly")
    sessions.add_argument(
        "--ca-file",
        help="Root CA certificate that signed --cert (for mkcert: the rootCA.pem in `mkcert -CAROOT`). "
        "Served at /ca.crt so iPhones/iPads can install and trust it from Safari - required for OTA installs.",
    )
    sessions.add_argument("--key", help="TLS private key (PEM) for --cert")
    sessions.add_argument(
        "--ota-http-port",
        type=int,
        default=None,
        help="Also serve OTA packages (and /ca.crt) over plain HTTP on this port, and point OTA manifests at it. "
        "The manifest itself stays on HTTPS. Only /ota/.../app.ipa and /ca.crt are reachable on this port. "
        "Workaround for devices whose installer rejects the HTTPS certificate for the package download.",
    )
    sessions.add_argument(
        "--behind-proxy",
        action="store_true",
        help="Trust X-Forwarded-Proto/Host/For from one reverse proxy (so HTTPS terminated at the proxy "
        "gets Secure cookies).",
    )

    enc = parser.add_argument_group(
        "master password (optional encryption of stored sign-ins, cookies and the session key in ~/.ipatool)")
    enc.add_argument("--master-password-file", help="file with the master password (instead of typing it at start; "
                     "or the IPATOOL_MASTER_PASSWORD environment variable)")
    enc_actions = enc.add_mutually_exclusive_group()
    enc_actions.add_argument("--encrypt-storage", action="store_true",
                             help="turn encryption on (asks for a new master password), then exit")
    enc_actions.add_argument("--decrypt-storage", action="store_true",
                             help="turn encryption off (asks for the master password), then exit")
    enc_actions.add_argument("--change-master-password", action="store_true",
                             help="change the master password, then exit")
    enc_actions.add_argument("--reset-encrypted-storage", action="store_true",
                             help="forgotten master password: delete the encrypted sign-ins, cookies and session "
                                  "key (sign in again afterwards), then exit")

    net = parser.add_argument_group("outbound proxy (all traffic to Apple)")
    net.add_argument(
        "--proxy",
        metavar="HOST:PORT",
        help="Send all requests to Apple through this proxy. host:port, or a full URL like "
        "socks5://host:1080 or http://user:pass@host:3128",
    )
    net.add_argument(
        "--proxy-type",
        choices=("http", "https", "socks5"),
        default="http",
        help="Proxy type when --proxy is given as host:port (default: http). socks5 resolves DNS via the proxy.",
    )
    net.add_argument("--proxy-user", help="Proxy login (optional)")
    net.add_argument(
        "--proxy-password",
        help="Proxy password. Prefer the IPATOOL_PROXY_PASSWORD environment variable (a command-line "
        "password is visible in the process list); if neither is set and --proxy-user is given, "
        "it is asked for interactively.",
    )

    catalog = parser.add_argument_group("version catalog (GitHub repository or static URL, read-only)")
    catalog.add_argument(
        "--catalog-repo",
        metavar="OWNER/NAME",
        help="GitHub repository with version catalog files (apps/<appId>.json, written by a separate "
        "collector). Public repository: no token needed. Private: read token from IPATOOL_CATALOG_TOKEN "
        "or --catalog-token-file (read-only, this repository only). Default from catalog.json next to app.py.",
    )
    catalog.add_argument("--catalog-url", help="Any HTTPS base URL serving <appId>.json files (instead of --catalog-repo)")
    catalog.add_argument("--no-catalog", action="store_true", help="Ignore catalog.json")
    catalog.add_argument("--catalog-branch", default="main", help="Branch of --catalog-repo (default: main)")
    catalog.add_argument("--catalog-prefix", default="apps", help="Folder in --catalog-repo (default: apps)")
    catalog.add_argument("--catalog-token-file", help="File containing the read token (instead of the environment variable)")

    server = parser.add_argument_group("server")
    server.add_argument(
        "--server",
        choices=("auto", "waitress", "werkzeug"),
        default="auto",
        help="HTTP server. 'auto': waitress if installed (production-grade, pure Python, works everywhere), "
        "otherwise Flask's built-in one. --cert/--key and --debug always use the built-in one.",
    )
    server.add_argument("--threads", type=int, default=8, help="Worker threads for waitress (default: 8)")
    server.add_argument(
        "--min-free-disk",
        type=int,
        default=int(os.environ.get("IPATOOL_MIN_FREE_DISK_MB", "1024") or 1024),
        metavar="MB",
        help="Disk space every download must leave free (default 1024 MB); a download that wouldn't fit is "
        "refused before it starts (env IPATOOL_MIN_FREE_DISK_MB).",
    )
    server.add_argument(
        "--emulators",
        type=int,
        default=int(os.environ.get("IPATOOL_EMULATORS", "2") or 2),
        metavar="N",
        help="Apple-signature emulations at once (sign-ins, download signatures; default 2). Each needs "
        "~400 MB of memory at its peak: use 1 on a server with 1 GB (env IPATOOL_EMULATORS).",
    )
    server.add_argument("--max-downloads", type=int, default=2, help="Concurrent IPA downloads (default: 2)")

    daemon = parser.add_argument_group("background running")
    daemon.add_argument(
        "--daemon",
        action="store_true",
        help="Detach from the terminal (POSIX double-fork, no external binaries needed). "
        "On Windows use serverctl.py instead.",
    )
    daemon.add_argument("--pid-file", default="ipatool-webui.pid", help="PID file for --daemon")
    daemon.add_argument(
        "--log-file",
        default=None,
        help="Write the (rotating, redacted) application log here. Defaults to ./ipatool-webui.log with --daemon. "
        "Raw stdout/stderr (e.g. crash tracebacks) go to <name>.stdout.log next to it.",
    )
    daemon.add_argument("--log-level", default=None, help="DEBUG/INFO/WARNING (default: INFO, DEBUG with --debug)")
    daemon.add_argument(
        "--trace",
        metavar="FILE",
        default=None,
        help="Diagnostics: write every request to Apple to FILE as JSON lines, secrets hidden "
        "(same as the IPATOOL_TRACE environment variable)",
    )
    return parser.parse_args(argv)


def is_loopback(host: str) -> bool:
    host = host.strip("[]").lower()
    if host in LOOPBACK_NAMES:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def local_host_names(bind_host: str) -> list:
    """This machine's names and addresses, for the Host-header allow-list."""
    import socket

    names = {"localhost", "127.0.0.1", "::1", "[::1]"}
    hostname = socket.gethostname()
    if hostname:
        names.update({hostname, hostname.lower(), f"{hostname}.local", f"{hostname.lower()}.local"})
    try:
        for info in socket.getaddrinfo(hostname, None):
            names.add(info[4][0])
    except OSError:
        pass
    try:  # the address used for outbound traffic (no packet is sent)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.connect(("192.0.2.1", 9))
            names.add(probe.getsockname()[0])
    except OSError:
        pass
    if bind_host and bind_host not in ("0.0.0.0", "::"):
        names.add(bind_host)
    return sorted(names)


def stdout_log_path(log_file: str) -> str:
    path = Path(log_file)
    return str(path.with_name(path.stem + ".stdout" + (path.suffix or ".log")))


def _enable_console_colors() -> None:
    """Windows' console shows the colour codes of Werkzeug's request lines
    as text ("[31m...") unless asked to interpret them."""
    if sys.platform != "win32":
        return
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        for std in (-11, -12):  # stdout, stderr
            handle = kernel32.GetStdHandle(std)
            mode = ctypes.c_uint32()
            if handle and kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
                kernel32.SetConsoleMode(handle, mode.value | 0x0004)  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
    except Exception:  # noqa: BLE001 - old Windows: the codes stay visible, nothing else changes
        pass


def setup_logging(log_file: Optional[str], level_name: str) -> None:
    from ipatool_api.services.redact import RedactingFilter

    _enable_console_colors()
    level = getattr(logging, level_name.upper(), logging.INFO)
    handlers: List[logging.Handler] = []
    if log_file:
        # 5 x 2 MB. On Windows rotation needs no other handle open on the
        # file - which is why raw stdout/stderr go to a *separate* file.
        handlers.append(logging.handlers.RotatingFileHandler(log_file, maxBytes=2 * 1024 * 1024, backupCount=5, encoding="utf-8"))
    if not log_file or sys.stderr.isatty():
        handlers.append(logging.StreamHandler())
    formatter = logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s")
    redactor = RedactingFilter()
    root = logging.getLogger()
    root.handlers.clear()
    for handler in handlers:
        handler.setFormatter(formatter)
        handler.addFilter(redactor)
        root.addHandler(handler)
    root.setLevel(level)
    # urllib3 at DEBUG would log full URLs incl. query strings.
    logging.getLogger("urllib3").setLevel(max(level, logging.INFO))


def daemonize(stdout_path: str, pid_path: str) -> None:
    """Unix double-fork: detached from the terminal for good."""
    if not hasattr(os, "fork"):
        raise SystemExit("--daemon is not supported on Windows; use: python serverctl.py")

    if os.fork() > 0:
        os._exit(0)
    os.setsid()
    if os.fork() > 0:
        os._exit(0)

    sys.stdout.flush()
    sys.stderr.flush()
    devnull_fd = os.open(os.devnull, os.O_RDONLY)
    out_fd = os.open(stdout_path, os.O_CREAT | os.O_APPEND | os.O_WRONLY, 0o600)
    os.dup2(devnull_fd, sys.stdin.fileno())
    os.dup2(out_fd, sys.stdout.fileno())
    os.dup2(out_fd, sys.stderr.fileno())

    with open(pid_path, "w") as pid_file:
        pid_file.write(str(os.getpid()))


def load_ca_certificate(path: str) -> bytes:
    """Read a CA certificate for /ca.crt, refusing anything with a key in it."""
    import ssl

    data = Path(path).read_bytes()
    if b"PRIVATE KEY" in data:
        raise SystemExit(f"--ca-file {path} contains a private key; pass the certificate (rootCA.pem), not the key")
    if b"-----BEGIN CERTIFICATE-----" in data:
        text = data.decode("ascii", "replace")
        start = text.index("-----BEGIN CERTIFICATE-----")
        end = text.index("-----END CERTIFICATE-----", start) + len("-----END CERTIFICATE-----")
        return ssl.PEM_cert_to_DER_cert(text[start:end])
    return data  # assume DER


def log_tls_handshake_failures() -> None:
    """Python's socketserver silently drops connections whose TLS handshake
    fails, so a device that doesn't trust the certificate (iOS's installer
    just says "cannot connect") left no trace at all. Log the reason."""
    import ssl

    from werkzeug.serving import BaseWSGIServer

    original = BaseWSGIServer.get_request

    def get_request(self):
        try:
            return original(self)
        except ssl.SSLError as exc:
            reason = getattr(exc, "reason", None) or str(exc)
            hint = ""
            if "UNKNOWN_CA" in str(reason).upper() or "CERTIFICATE_UNKNOWN" in str(reason).upper() or "BAD_CERTIFICATE" in str(reason).upper():
                hint = " - the connecting device doesn't trust this certificate (install and trust the root CA, see /ca.crt)"
            from ipatool_api.tlsdiag import handshake_summary

            summary = handshake_summary()
            if "HTTP_REQUEST" in str(reason).upper():
                # A browser sent plain HTTP to the HTTPS port.
                logger.warning("a client opened the server with http:// - this port speaks HTTPS only, use https://")
                raise
            logger.warning("TLS handshake failed: %s%s | %s", reason, hint, summary)
            raise

    BaseWSGIServer.get_request = get_request


class OtaOnlyPaths:
    """WSGI filter for the plain-HTTP OTA port: only the package download and
    the CA certificate are reachable - sign-in, sessions and the API never
    travel over plain HTTP."""

    def __init__(self, app) -> None:
        self.app = app

    def __call__(self, environ, start_response):
        path = environ.get("PATH_INFO", "")
        if path == "/ca.crt" or (path.startswith("/ota/") and path.endswith("/app.ipa")):
            return self.app(environ, start_response)
        start_response("404 Not Found", [("Content-Type", "text/plain")])
        return [b"Not available on the plain-HTTP port."]


def start_ota_http_server(app, host: str, port: int) -> None:
    import threading

    from werkzeug.serving import make_server

    server = make_server(host, port, OtaOnlyPaths(app), threaded=True)
    threading.Thread(target=server.serve_forever, name="ota-http", daemon=True).start()
    logger.info("OTA packages also served over plain HTTP on port %s (only /ota/*/app.ipa and /ca.crt)", port)


def setup_proxy(args: argparse.Namespace) -> None:
    if not args.proxy:
        return
    import getpass

    from ipatool_api.services import netconfig

    password = netconfig.resolve_password(args.proxy_password)
    if args.proxy_user and password is None:
        if sys.stdin and sys.stdin.isatty():
            password = getpass.getpass(f"Password for proxy user {args.proxy_user}: ")
        else:
            raise SystemExit("--proxy-user needs a password: set IPATOOL_PROXY_PASSWORD or pass --proxy-password")
    try:
        url = netconfig.build_proxy_url(args.proxy, args.proxy_type, args.proxy_user, password)
        netconfig.configure(url)
    except netconfig.ProxyConfigError as exc:
        raise SystemExit(f"proxy: {exc}")
    logger.info("all traffic to Apple goes through proxy %s", netconfig.active())
    ok, message = netconfig.probe()
    if ok:
        logger.info("proxy check: OK, %s", message)
    else:
        logger.warning("proxy check FAILED: %s - requests to Apple will fail until this is fixed", message)


def _access_password(args: argparse.Namespace) -> str:
    if args.access_password_file:
        try:
            with open(args.access_password_file, encoding="utf-8") as handle:
                password = handle.readline().rstrip("\r\n")
        except OSError as exc:
            raise SystemExit(f"--access-password-file: {exc}")
        if not password:
            raise SystemExit("--access-password-file is empty")
        return password
    return os.environ.get("IPATOOL_ACCESS_PASSWORD", "")


def build_app(args: argparse.Namespace):
    from ipatool_api import create_app

    loopback = is_loopback(args.host)
    mode = args.session_mode
    if mode == "auto":
        # Behind a reverse proxy the server listens on loopback, but its users
        # come from the network: each browser gets its own sign-in.
        mode = "local" if loopback and not args.behind_proxy else "browser"

    trusted = list(args.trusted_host)
    if loopback and not args.behind_proxy:
        trusted += ["localhost", "127.0.0.1", "[::1]", "::1"]
    elif mode == "local" and not args.behind_proxy:
        # Shared account on the network: pin Host to this machine's names (DNS rebinding).
        own = local_host_names(args.host)
        trusted += own
        logger.info(
            "shared-account mode on the network: accepting Host names %s (add more with --trusted-host)",
            ", ".join(own),
        )

    if args.user_agent:
        from ipatool_api.services import constants as appstore_constants
        from ipatool_api.services.sap import protocol as sap_protocol

        appstore_constants.DEFAULT_USER_AGENT = args.user_agent
        sap_protocol._USER_AGENT = args.user_agent
        logger.info("User-Agent for Apple: %s", args.user_agent)
    from ipatool_api.services.appstore import set_disk_reserve, set_emulator_slots

    set_emulator_slots(args.emulators)
    set_disk_reserve(args.min_free_disk)
    ca_der = load_ca_certificate(args.ca_file) if args.ca_file else None
    app = create_app(
        ca_certificate=ca_der,
        legacy=args.legacy,
        session_mode=mode,
        allow_server_save=True if (mode == "local" or args.allow_server_save) else False,
        trusted_hosts=trusted or None,
        session_days=args.session_days,
        max_concurrent_downloads=args.max_downloads,
        repo_url=args.repo_url,
        access_password=_access_password(args),
    )

    app.config["OTA_HTTP_PORT"] = args.ota_http_port

    if args.behind_proxy:
        from werkzeug.middleware.proxy_fix import ProxyFix

        # The proxy speaks HTTPS: plain-HTTP requests are redirected / refused
        # (--allow-http turns that off, e.g. for a proxy on a trusted LAN).
        app.config["REQUIRE_HTTPS"] = not args.allow_http

        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

    if (args.behind_proxy or not loopback) and not app.config.get("ACCESS_GATE"):
        logger.warning(
            "no access password is set, so anyone who reaches this server can use it (its CPU, memory, disk and its IP "
            "towards Apple). For a server on the internet set --access-password-file."
        )
    if args.behind_proxy and not args.trusted_host:
        logger.warning(
            "behind a reverse proxy without --trusted-host: any Host name is accepted. "
            "Add --trusted-host your.domain (the name users open)."
        )
    if mode == "local" and (not loopback or args.behind_proxy):
        logger.warning(
            "LOCAL session mode on a non-loopback address (%s): everyone who can reach this server "
            "shares the one signed-in Apple ID. Use --session-mode browser unless that's intended.",
            args.host,
        )
    if mode == "browser" and not (args.cert or args.behind_proxy):
        logger.warning(
            "Browser sessions over plain HTTP: the session cookie is encrypted, but someone sniffing "
            "the network could still replay it. Prefer --cert/--key or an HTTPS reverse proxy (--behind-proxy)."
        )
    logger.info("session mode: %s", mode)
    return app


def serve(app, args: argparse.Namespace) -> None:
    use_tls = bool(args.cert and args.key)
    if args.ota_http_port:
        start_ota_http_server(app, args.host, args.ota_http_port)
    choice = args.server
    if use_tls or args.debug:
        choice = "werkzeug"
    if choice == "auto":
        try:
            import waitress  # noqa: F401

            choice = "waitress"
        except ImportError:
            choice = "werkzeug"

    scheme = "https" if use_tls else "http"
    logger.info("listening on %s://%s:%s (%s)", scheme, args.host, args.port, choice)

    if choice == "waitress":
        from waitress import serve as waitress_serve

        # Behind a proxy ProxyFix reads X-Forwarded-*; waitress would strip them.
        waitress_serve(app, host=args.host, port=args.port, threads=args.threads, ident="pyIPATool",
                       clear_untrusted_proxy_headers=not args.behind_proxy)
    else:
        ssl_context = None
        if use_tls:
            from ipatool_api.tlsdiag import check_certificates, make_ssl_context

            check_certificates(args.cert, args.ca_file)
            ssl_context = make_ssl_context(args.cert, args.key)
            log_tls_handshake_failures()
        # No reloader (breaks --daemon). The debugger runs code from error pages:
        # loopback only, never behind a proxy.
        flask_debug = args.debug and is_loopback(args.host) and not args.behind_proxy
        if args.debug and not flask_debug:
            logger.warning("--debug on a network address: verbose logging only, interactive debugger disabled")
        app.run(debug=flask_debug, host=args.host, port=args.port, ssl_context=ssl_context, use_reloader=False, threaded=True)


def setup_catalog(args: argparse.Namespace) -> None:
    from ipatool_api.services import catalog

    repo, branch, prefix, url = args.catalog_repo, args.catalog_branch, args.catalog_prefix, args.catalog_url
    shipped_token = ""
    defaults = Path(__file__).resolve().parent / "catalog.json"
    if not repo and not url and not args.no_catalog and defaults.exists():
        # Shipped default: {"repo": "owner/name", "branch": "main", "prefix": "apps",
        # "token": "<read-only token for a private repository>"} or {"url": "https://..."}.
        try:
            import json

            config = json.loads(defaults.read_text(encoding="utf-8"))
            repo, url = config.get("repo"), config.get("url")
            branch, prefix = config.get("branch", branch), config.get("prefix", prefix)
            shipped_token = str(config.get("token") or "").strip()
        except (OSError, ValueError) as exc:
            logger.warning("catalog.json ignored: %s", exc)
    if not repo and not url:
        return
    # Precedence: --catalog-token-file > IPATOOL_CATALOG_TOKEN > "token" in catalog.json.
    token = os.environ.get("IPATOOL_CATALOG_TOKEN", "").strip() or shipped_token
    if args.catalog_token_file:
        try:
            token = Path(args.catalog_token_file).read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise SystemExit(f"--catalog-token-file: {exc}")
    try:
        if url:
            catalog.configure_url(url)
        else:
            catalog.configure(repo, token, branch, prefix)
    except catalog.CatalogError as exc:
        raise SystemExit(f"catalog: {exc}")
    ok, message = catalog.check_access()
    if ok:
        logger.info("version catalog: %s (%s)", catalog.describe(), message)
    else:
        logger.warning("version catalog %s: %s - versions from it won't be shown", catalog.describe(), message)


def _ask_new_password(getpass_fn) -> str:
    from ipatool_api.services import vault

    while True:
        first = getpass_fn("New master password: ")
        weak = vault.check_password_strength(first)
        if weak:
            print(f"Too weak ({weak}) - try again.")
            continue
        if getpass_fn("Repeat it: ") != first:
            print("The two don't match - try again.")
            continue
        return first


def setup_vault(args: argparse.Namespace) -> None:
    """Master password: the --encrypt/--decrypt/--change actions (then exit),
    unlocking at start, and - once, at the first interactive start - the
    offer to turn it on."""
    import getpass

    from ipatool_api.services import vault

    interactive = sys.stdin is not None and sys.stdin.isatty()

    def known_password() -> Optional[str]:
        if args.master_password_file:
            return Path(args.master_password_file).read_text(encoding="utf-8").strip("\r\n")
        return vault.password_from_environment()

    def unlock_or_exit() -> None:
        given = known_password()
        if given is None and not interactive:
            raise SystemExit("the stored sign-ins are encrypted and there's no terminal to ask for the master "
                             "password: use --master-password-file or IPATOOL_MASTER_PASSWORD")
        for attempt in range(1 if given else 3):
            password = given or getpass.getpass("Master password: ")
            try:
                vault.unlock(password)
                return
            except vault.VaultError as exc:
                print(f"{exc}")
        raise SystemExit("the stored sign-ins are encrypted: give the master password "
                         "(prompt, --master-password-file or IPATOOL_MASTER_PASSWORD)")

    state = vault.status()
    try:
        if args.encrypt_storage:
            if state == "on":
                raise SystemExit("encryption is already on (--change-master-password changes the password)")
            files = vault.enable(known_password() or _ask_new_password(getpass.getpass))
            raise SystemExit(f"encryption is on; encrypted {len(files)} file(s). Start the server as usual - "
                             "it will ask for the master password.")
        if args.decrypt_storage:
            if state != "on":
                raise SystemExit("encryption is already off")
            if known_password() is None and not interactive:
                raise SystemExit("give the master password (--master-password-file or IPATOOL_MASTER_PASSWORD)")
            files = vault.disable(known_password() or getpass.getpass("Master password: "))
            raise SystemExit(f"encryption is off; decrypted {len(files)} file(s)")
        if args.reset_encrypted_storage:
            if state != "on":
                raise SystemExit("encryption is off - nothing to reset")
            if interactive and input("Delete the encrypted sign-ins, cookies and session key? Type YES: ") != "YES":
                raise SystemExit("cancelled")
            files = vault.reset()
            raise SystemExit(f"deleted {len(files)} encrypted file(s) and the vault; sign in again")
        if args.change_master_password:
            if state != "on":
                raise SystemExit("encryption is off (--encrypt-storage turns it on)")
            old = known_password() or getpass.getpass("Current master password: ")
            vault.change_password(old, _ask_new_password(getpass.getpass))
            raise SystemExit("master password changed")
    except vault.VaultError as exc:
        raise SystemExit(str(exc))

    if state == "on":
        unlock_or_exit()
    elif state == "undecided" and interactive and known_password() is None:
        print("\nThe server stores Apple sign-ins, Apple's cookies and its session key in ~/.ipatool.\n"
              "They can be encrypted with a master password (asked at every start; shared with the\n"
              "collector). Without it nobody - not even with this program's files - can read them.")
        answer = input("Encrypt them with a master password? [y/N] ").strip().lower()
        if answer in ("y", "yes", "д", "да"):
            files = vault.enable(_ask_new_password(getpass.getpass))
            print(f"Encryption is on ({len(files)} file(s) encrypted).")
        else:
            vault.decline()
            print("Not encrypted (turn it on later with --encrypt-storage).")


def main(argv: Optional[List[str]] = None) -> None:
    args = parse_args(argv)
    if bool(args.cert) != bool(args.key):
        raise SystemExit("--cert and --key must be given together")

    if args.daemon and not args.log_file:
        args.log_file = "ipatool-webui.log"
    if args.daemon and args.proxy and args.proxy_user and args.proxy_password is None and not os.environ.get("IPATOOL_PROXY_PASSWORD"):
        import getpass

        # Asked while a terminal is still there; setup_proxy reads it from the environment.
        os.environ["IPATOOL_PROXY_PASSWORD"] = getpass.getpass(f"Password for proxy user {args.proxy_user}: ")
    # Before going to the background: a terminal may be needed for the password.
    setup_vault(args)
    if args.daemon:
        daemonize(stdout_log_path(args.log_file), args.pid_file)

    setup_logging(args.log_file, args.log_level or ("DEBUG" if args.debug else "INFO"))
    from ipatool_api.services import vault

    if vault.is_unlocked():
        logger.info("stored sign-ins are encrypted with the master password (%s)", vault.kdf_name())
    if args.trace:
        os.environ["IPATOOL_TRACE"] = os.path.abspath(args.trace)
    if os.environ.get("IPATOOL_TRACE"):
        logger.info("request trace (diagnostics, secrets hidden): %s", os.environ["IPATOOL_TRACE"])
    setup_proxy(args)
    setup_catalog(args)
    app = build_app(args)
    serve(app, args)


if __name__ == "__main__":
    main()
