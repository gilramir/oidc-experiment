"""
Reusable OIDC/OAuth2 client library.

Implements three grant types for CLI/service use:
  - Authorization Code + PKCE (RFC 7636) — interactive, opens a browser
  - Device Authorization Grant (RFC 8628) — headless/SSH, prints a code
  - Client Credentials (RFC 6749 §4.4) — machine-to-machine, no user

Token persistence: on-disk cache at ~/.config/{app}/token.json (mode 0600),
with transparent silent refresh via the refresh token.

Requires: requests (pip install requests)
Python 3.10+
"""

import base64
import hashlib
import json
import os
import secrets
import threading
import time
import urllib.parse
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Callable, Optional

import requests

__all__ = [
    "Token",
    "OIDCConfig",
    "ProviderEndpoints",
    "discover_provider",
    "auth_code_flow",
    "device_flow",
    "client_credentials_flow",
    "refresh_access_token",
    "TokenStore",
    "describe_token",
]


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------


@dataclass
class Token:
    """OAuth2 token set returned by any of the three grant flows."""
    access_token: str
    token_type: str = "Bearer"
    refresh_token: str = ""
    id_token: str = ""
    expiry: Optional[datetime] = None  # timezone-aware UTC

    def is_expired(self, skew_seconds: int = 10) -> bool:
        """True if the access token is expired or within skew_seconds of expiry."""
        if self.expiry is None:
            return False
        return datetime.now(timezone.utc) >= self.expiry - timedelta(seconds=skew_seconds)

    def is_valid(self) -> bool:
        return bool(self.access_token) and not self.is_expired()


@dataclass
class OIDCConfig:
    """How to reach the OIDC provider and which client we are."""
    issuer: str
    client_id: str
    redirect_url: str    # loopback URL for the auth-code flow
    scopes: list[str]    # include "offline_access" to receive a refresh token


@dataclass
class ProviderEndpoints:
    """Endpoints extracted from the OIDC discovery document."""
    authorization_endpoint: str
    token_endpoint: str
    device_authorization_endpoint: str = ""


# ---------------------------------------------------------------------------
# OIDC discovery
# ---------------------------------------------------------------------------


def discover_provider(issuer: str) -> ProviderEndpoints:
    """
    Fetch the OIDC discovery document and return parsed endpoints.

    Raises requests.HTTPError on a non-2xx response.
    """
    url = issuer.rstrip("/") + "/.well-known/openid-configuration"
    resp = requests.get(url, timeout=10)
    resp.raise_for_status()
    doc = resp.json()
    return ProviderEndpoints(
        authorization_endpoint=doc["authorization_endpoint"],
        token_endpoint=doc["token_endpoint"],
        device_authorization_endpoint=doc.get("device_authorization_endpoint", ""),
    )


# ---------------------------------------------------------------------------
# PKCE helpers (RFC 7636)
# ---------------------------------------------------------------------------


def _generate_pkce() -> tuple[str, str]:
    """Return (verifier, S256 challenge) for PKCE."""
    verifier = secrets.token_urlsafe(32)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


def _random_state() -> str:
    return secrets.token_hex(16)


# ---------------------------------------------------------------------------
# Token response parsing
# ---------------------------------------------------------------------------


def _parse_token_response(data: dict) -> Token:
    """Build a Token from a raw token-endpoint JSON response."""
    expiry = None
    if "expires_in" in data:
        expiry = datetime.now(timezone.utc) + timedelta(seconds=int(data["expires_in"]))
    return Token(
        access_token=data.get("access_token", ""),
        token_type=data.get("token_type", "Bearer"),
        refresh_token=data.get("refresh_token", ""),
        id_token=data.get("id_token", ""),
        expiry=expiry,
    )


# ---------------------------------------------------------------------------
# Grant flows
# ---------------------------------------------------------------------------


def auth_code_flow(
    endpoints: ProviderEndpoints,
    config: OIDCConfig,
    present: Callable[[str], None],
) -> Token:
    """
    Authorization Code + PKCE flow (RFC 7636).

    Steps:
      1. Bind a throwaway HTTP server on the loopback redirect URL.
      2. Call present(auth_url) so the caller can open a browser (or drive it
         programmatically in tests).
      3. The provider redirects back with an authorization code.
      4. Exchange the code + PKCE verifier for tokens.

    No client secret needed — PKCE replaces it for public/CLI clients.
    """
    parsed = urllib.parse.urlparse(config.redirect_url)
    host = parsed.hostname or "127.0.0.1"
    callback_path = parsed.path or "/callback"

    state = _random_state()
    verifier, challenge = _generate_pkce()

    result: dict = {"code": None, "error": None}
    done = threading.Event()

    class _Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            pass  # silence per-request logs

        def do_GET(self):
            req = urllib.parse.urlparse(self.path)
            if req.path != callback_path:
                self._reply(404, b"Not found.")
                return

            params = urllib.parse.parse_qs(req.query)
            if "error" in params:
                err = params["error"][0]
                result["error"] = f"provider returned error: {err}"
                self._reply(400, f"Login failed: {err}".encode())
            elif params.get("state", [""])[0] != state:
                result["error"] = "state mismatch (possible CSRF)"
                self._reply(400, b"State mismatch.")
            else:
                result["code"] = params.get("code", [""])[0]
                self._reply(200, b"Login complete. You can close this tab and return to the terminal.")
            done.set()

        def _reply(self, status: int, body: bytes):
            self.send_response(status)
            self.end_headers()
            self.wfile.write(body)

    # Bind on port 0 so the kernel assigns an ephemeral port.
    server = HTTPServer((host, 0), _Handler)
    actual_port = server.server_address[1]
    # Rebuild the redirect URL with the actual port so the provider's redirect
    # lands on the port we're listening on.
    redirect_url = urllib.parse.urlunparse((
        parsed.scheme or "http",
        f"{host}:{actual_port}",
        callback_path,
        "", "", "",
    ))

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        auth_url = endpoints.authorization_endpoint + "?" + urllib.parse.urlencode({
            "response_type": "code",
            "client_id": config.client_id,
            "redirect_uri": redirect_url,
            "scope": " ".join(config.scopes),
            "state": state,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        })
        present(auth_url)
        done.wait()
    finally:
        server.shutdown()

    if result["error"]:
        raise RuntimeError(result["error"])

    resp = requests.post(
        endpoints.token_endpoint,
        data={
            "grant_type": "authorization_code",
            "code": result["code"],
            "redirect_uri": redirect_url,
            "client_id": config.client_id,
            "code_verifier": verifier,
        },
        timeout=10,
    )
    resp.raise_for_status()
    return _parse_token_response(resp.json())


def device_flow(
    endpoints: ProviderEndpoints,
    config: OIDCConfig,
    present: Callable[[dict], None],
) -> Token:
    """
    Device Authorization Grant (RFC 8628).

    Steps:
      1. POST to device_authorization_endpoint to obtain a device code and user code.
      2. Call present(device_auth_response) with the raw response dict so the
         caller can instruct the user where to go (verification_uri, user_code,
         verification_uri_complete).
      3. Poll the token endpoint until approved, expired, or an error.

    No loopback server and no PKCE required.
    """
    if not endpoints.device_authorization_endpoint:
        raise RuntimeError("provider does not advertise a device authorization endpoint")

    resp = requests.post(
        endpoints.device_authorization_endpoint,
        data={
            "client_id": config.client_id,
            "scope": " ".join(config.scopes),
        },
        timeout=10,
    )
    resp.raise_for_status()
    auth_resp = resp.json()

    present(auth_resp)

    device_code = auth_resp["device_code"]
    interval = int(auth_resp.get("interval", 5))
    expires_in = int(auth_resp.get("expires_in", 300))
    deadline = time.monotonic() + expires_in

    while time.monotonic() < deadline:
        time.sleep(interval)
        token_resp = requests.post(
            endpoints.token_endpoint,
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "device_code": device_code,
                "client_id": config.client_id,
            },
            timeout=10,
        )
        data = token_resp.json()
        if token_resp.status_code == 200:
            return _parse_token_response(data)
        error = data.get("error", "")
        if error == "authorization_pending":
            continue
        if error == "slow_down":
            interval += 5
            continue
        desc = data.get("error_description", "")
        raise RuntimeError(f"device token exchange: {error}: {desc}")

    raise RuntimeError("device authorization timed out")


def client_credentials_flow(
    token_url: str,
    client_id: str,
    client_secret: str,
    scopes: list[str],
) -> Token:
    """
    Client Credentials grant (RFC 6749 §4.4).

    The application itself is the principal — no user, no browser, no
    refresh token. The returned token's subject is the client, not a person.
    Re-mint a fresh token each run; there is nothing to cache or refresh.

    Pass the client secret via the OIDC_CLIENT_SECRET environment variable,
    not as a flag, so it does not land in shell history or argv.
    """
    if not client_secret:
        raise ValueError(
            "client credentials grant requires a client secret (set OIDC_CLIENT_SECRET)"
        )
    resp = requests.post(
        token_url,
        data={
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
            "scope": " ".join(scopes),
        },
        timeout=10,
    )
    resp.raise_for_status()
    return _parse_token_response(resp.json())


# ---------------------------------------------------------------------------
# Transparent refresh
# ---------------------------------------------------------------------------


def refresh_access_token(
    token_endpoint: str,
    client_id: str,
    tok: Token,
) -> Token:
    """
    Use the refresh token to silently obtain a new access token.

    Some providers rotate the refresh token on each use; if the new response
    omits a refresh token, the old one is kept.
    """
    if not tok.refresh_token:
        raise RuntimeError("no refresh token available")

    resp = requests.post(
        token_endpoint,
        data={
            "grant_type": "refresh_token",
            "refresh_token": tok.refresh_token,
            "client_id": client_id,
        },
        timeout=10,
    )
    resp.raise_for_status()
    fresh = _parse_token_response(resp.json())
    if not fresh.refresh_token:
        fresh.refresh_token = tok.refresh_token
    return fresh


# ---------------------------------------------------------------------------
# Token introspection / debug display
# ---------------------------------------------------------------------------


def _decode_jwt_payload(raw_jwt: str) -> dict:
    """Decode a JWT payload without verifying the signature."""
    parts = raw_jwt.split(".")
    if len(parts) != 3:
        return {}
    padded = parts[1] + "=" * (-len(parts[1]) % 4)
    try:
        return json.loads(base64.urlsafe_b64decode(padded))
    except Exception:
        return {}


def _rel_time(t: datetime, now: datetime) -> str:
    """Human-readable relative time: 'in 5m30s' or '5m30s ago'."""
    secs = int(abs((t - now).total_seconds()))
    if secs >= 86400:
        d, h = secs // 86400, (secs % 86400) // 3600
        s = f"{d}d{h}h" if h else f"{d}d"
    elif secs >= 3600:
        h, m = secs // 3600, (secs % 3600) // 60
        s = f"{h}h{m}m" if m else f"{h}h"
    elif secs >= 60:
        m, sec = secs // 60, secs % 60
        s = f"{m}m{sec}s" if sec else f"{m}m"
    else:
        s = f"{secs}s"
    return f"in {s}" if t > now else f"{s} ago"


def describe_token(tok: Token, path: Optional[str] = None) -> str:
    """
    Return a human-readable summary of a Token for debugging.

    Decodes JWT payloads (without verifying signatures) to show all claims,
    annotating iat/exp with human-readable relative times and VALID/EXPIRED.
    Pass path to include the token file location in the output.
    """
    lines: list[str] = []
    if path:
        lines.append(f"Token file: {path}")

    now = datetime.now(timezone.utc)

    def _fmt_jwt(label: str, raw_jwt: str) -> None:
        claims = _decode_jwt_payload(raw_jwt)
        if not claims:
            lines.append(f"\n{label}: (unreadable — not a valid JWT)")
            return
        lines.append(f"\n{label}")
        shown: set[str] = set()
        for key in ("iss", "sub", "aud", "email", "name", "email_verified"):
            if key in claims:
                lines.append(f"  {key + ':':<20} {claims[key]}")
                shown.add(key)
        skip = shown | {"iat", "exp", "at_hash", "c_hash", "nonce"}
        for key, val in claims.items():
            if key not in skip:
                lines.append(f"  {key + ':':<20} {val}")
        if "iat" in claims:
            t = datetime.fromtimestamp(claims["iat"], tz=timezone.utc)
            lines.append(f"  {'iat:':<20} {t.strftime('%Y-%m-%d %H:%M:%S UTC')}  ({_rel_time(t, now)})")
        if "exp" in claims:
            t = datetime.fromtimestamp(claims["exp"], tz=timezone.utc)
            status = "EXPIRED" if now > t else "VALID"
            lines.append(f"  {'exp:':<20} {t.strftime('%Y-%m-%d %H:%M:%S UTC')}  ({_rel_time(t, now)})  [{status}]")

    if tok.access_token:
        _fmt_jwt("Access token", tok.access_token)
    if tok.id_token:
        _fmt_jwt("ID token", tok.id_token)

    if tok.refresh_token:
        lines.append("\nRefresh token: present  (expiry is managed server-side)")
    else:
        lines.append("\nRefresh token: absent")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# On-disk token store
# ---------------------------------------------------------------------------


class TokenStore:
    """
    Persists tokens to ~/.config/{app}/token.json (mode 0600) and provides
    transparent refresh via get_valid_token().

    The on-disk format explicitly stores id_token, which the standard OAuth2
    response parser typically throws away into an opaque extras dict.

    The on-disk JSON is intentionally compatible with the Go client's token
    store (internal/token/store.go) so that both clients can share a cache.
    """

    def __init__(self, app: str = "oidc-experiment", path: Optional[str] = None):
        if path:
            self._path = Path(path)
        else:
            xdg = os.environ.get("XDG_CONFIG_HOME", "")
            base = Path(xdg) if xdg else Path.home() / ".config"
            self._path = base / app / "token.json"

    @property
    def path(self) -> Path:
        return self._path

    def load(self) -> Token:
        """Load from disk. Raises FileNotFoundError if no token is cached."""
        data = json.loads(self._path.read_text())
        expiry = None
        if data.get("expiry"):
            expiry = datetime.fromisoformat(data["expiry"])
            if expiry.tzinfo is None:
                expiry = expiry.replace(tzinfo=timezone.utc)
        return Token(
            access_token=data.get("access_token", ""),
            token_type=data.get("token_type", "Bearer"),
            refresh_token=data.get("refresh_token", ""),
            id_token=data.get("id_token", ""),
            expiry=expiry,
        )

    def save(self, tok: Token) -> None:
        """Write token to disk with 0600 permissions, creating parent dirs."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        data: dict = {
            "access_token": tok.access_token,
            "token_type": tok.token_type,
            "refresh_token": tok.refresh_token,
            "expiry": tok.expiry.isoformat() if tok.expiry else None,
        }
        if tok.id_token:
            data["id_token"] = tok.id_token
        self._path.write_text(json.dumps(data, indent=2))
        self._path.chmod(0o600)

    def clear(self) -> None:
        """Delete the cached token. No-op if it does not exist."""
        try:
            self._path.unlink()
        except FileNotFoundError:
            pass

    def get_valid_token(self, token_endpoint: str, client_id: str) -> Optional[Token]:
        """
        Return a valid token from the cache, refreshing silently if expired.

        Returns None when there is no cached token, the refresh token is
        absent or revoked, or any other error prevents refresh — the caller
        should then run an interactive login flow.
        """
        try:
            tok = self.load()
        except FileNotFoundError:
            return None

        if tok.is_valid():
            return tok

        try:
            tok = refresh_access_token(token_endpoint, client_id, tok)
            self.save(tok)
            return tok
        except Exception:
            return None
