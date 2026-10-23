"""Access password and per-IP limits for public servers.

With ``--access-password-file`` every page and API call needs the password
once per browser (signed cookie, 30 days); OTA links and /source stay open.
Sign-ins and password attempts are rate-limited per client IP.
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import threading
import time
from collections import deque
from typing import Deque, Dict, Optional

from flask import Flask, Response, jsonify, redirect, render_template, request, url_for

logger = logging.getLogger(__name__)
COOKIE = "ipatool_access"
COOKIE_DAYS = 30
# Reachable without the access password.
OPEN_PREFIXES = ("/access", "/static/", "/ota/", "/source", "/favicon.ico")


class RateLimiter:
    """At most ``limit`` events per ``window`` seconds per key (client IP)."""

    def __init__(self, limit: int, window: float, max_keys: int = 10000) -> None:
        self.limit, self.window, self.max_keys = limit, window, max_keys
        self._events: Dict[str, Deque[float]] = {}
        self._lock = threading.Lock()

    def hit(self, key: str) -> Optional[int]:
        """Count one event; None if allowed, else seconds to wait."""
        now = time.monotonic()
        with self._lock:
            if len(self._events) > self.max_keys:  # a flood of addresses: forget the idle ones
                for old in [k for k, q in self._events.items() if not q or now - q[-1] > self.window]:
                    del self._events[old]
            events = self._events.setdefault(key, deque())
            while events and now - events[0] > self.window:
                events.popleft()
            if len(events) >= self.limit:
                return int(self.window - (now - events[0])) + 1
            events.append(now)
            return None


def client_ip() -> str:
    """The client's address for the limits (behind --behind-proxy: from the
    proxy's X-Forwarded-For). IPv6: its /64 network - one connection usually
    has a whole /64, so single addresses would be free to rotate."""
    import ipaddress

    address = request.remote_addr or "?"
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return address
    if parsed.version == 6:
        if parsed.ipv4_mapped:
            return str(parsed.ipv4_mapped)
        return str(ipaddress.ip_network(f"{parsed}/64", strict=False))
    return str(parsed)


class AccessGate:
    def __init__(self, password: str) -> None:
        # Same password, same key: restarts keep browsers signed in.
        salt = b"pyIPATool access password v1"
        self._key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000)
        self._check = hmac.new(self._key, b"password-check", hashlib.sha256).digest()
        self._salt = salt
        self.attempts = RateLimiter(limit=8, window=15 * 60)

    def password_ok(self, password: str) -> bool:
        key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), self._salt, 200_000)
        return hmac.compare_digest(hmac.new(key, b"password-check", hashlib.sha256).digest(), self._check)

    def make_cookie(self) -> str:
        expires = str(int(time.time()) + COOKIE_DAYS * 86400)
        return expires + "." + hmac.new(self._key, expires.encode(), hashlib.sha256).hexdigest()

    def cookie_ok(self, value: str) -> bool:
        expires, _, signature = (value or "").partition(".")
        if not expires.isdigit() or int(expires) < time.time():
            return False
        good = hmac.new(self._key, expires.encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(good, signature)


def install(app: Flask, access_password: str = "") -> None:
    """Access password (when given) and per-IP limits on sign-ins."""
    sign_ins = RateLimiter(limit=10, window=10 * 60)

    @app.before_request
    def _limit_sign_ins():
        if request.method == "POST" and request.path in ("/api/auth/login", "/api/accounts/add"):
            wait = sign_ins.hit(client_ip())
            if wait:
                logger.warning("sign-in rate limit for %s", client_ip())
                return jsonify({"error": f"too many sign-in attempts from your address - try again in "
                                         f"{wait // 60 + 1} min"}), 429
        return None

    if not access_password:
        return
    gate = AccessGate(access_password)
    app.config["ACCESS_GATE"] = True

    @app.before_request
    def _require_access():
        if request.path.startswith(OPEN_PREFIXES):
            return None
        if gate.cookie_ok(request.cookies.get(COOKIE, "")):
            return None
        if request.path.startswith("/api/"):
            return jsonify({"error": "access password required - reload the page"}), 401
        here = request.script_root + (request.full_path if request.query_string else request.path)
        return redirect(url_for("access_page", next=here))

    @app.route("/access", methods=["GET", "POST"], endpoint="access_page")
    def access_page():
        target = request.values.get("next") or (request.script_root + "/")
        if not target.startswith("/") or target.startswith("//"):
            target = "/"  # only back into this site
        error = ""
        status = 200
        if request.method == "POST":
            wait = gate.attempts.hit(client_ip())
            if wait:
                error, status = f"Too many attempts - try again in {wait // 60 + 1} min.", 429
            elif gate.password_ok(request.form.get("password", "")):
                response: Response = redirect(target)
                response.set_cookie(COOKIE, gate.make_cookie(), max_age=COOKIE_DAYS * 86400, httponly=True,
                                    secure=request.is_secure, samesite="Lax")
                return response
            else:
                logger.warning("wrong access password from %s", client_ip())
                error, status = "Wrong password.", 403
        return render_template("access.html", error=error, target=target), status
