"""
Python client for the oidc-experiment JSON-RPC server.

Mirrors cmd/client/main.go but delegates all OIDC and token management to
oidc_auth.py, which can be reused independently in other Python clients.

Usage:
  python client.py [--auth=authcode] <method>           # opens browser
  python client.py --auth=device <method>               # prints code + URL
  python client.py --login <method>                     # force fresh login
  python client.py --logout                             # remove cached token
  OIDC_CLIENT_SECRET=… python client.py --auth=client-credentials \\
      --client-id=oidc-experiment-bot <method>          # machine-to-machine
"""

import argparse
import json
import os
import platform
import socket
import subprocess
import sys

from oidc_auth import (
    OIDCConfig,
    TokenStore,
    auth_code_flow,
    client_credentials_flow,
    describe_token,
    device_flow,
    discover_provider,
)

DEFAULT_ISSUER = "http://127.0.0.1:5556/dex"
DEFAULT_CLIENT_ID = "oidc-experiment-cli"
DEFAULT_AUDIENCE = "oidc-experiment-api"
REDIRECT_URL = "http://127.0.0.1:5555/callback"

# Dex's cross-client scope mechanism: makes the resource server the token's
# audience rather than the CLI's own client id.
CROSS_CLIENT_SCOPE_PREFIX = "audience:server:client_id:"


def main():
    parser = argparse.ArgumentParser(
        description="Authenticated JSON-RPC client using OIDC.",
    )
    parser.add_argument(
        "--auth", default="authcode",
        choices=["authcode", "device", "client-credentials"],
        help="login flow (default: authcode)",
    )
    parser.add_argument("--addr", default="127.0.0.1:8888",
                        help="server host:port (default: 127.0.0.1:8888)")
    parser.add_argument("--issuer", default=DEFAULT_ISSUER,
                        help="OIDC issuer URL")
    parser.add_argument("--client-id", default=DEFAULT_CLIENT_ID,
                        help="OIDC client id")
    parser.add_argument("--audience", default=DEFAULT_AUDIENCE,
                        help="API audience to request the access token for")
    parser.add_argument("--login", action="store_true",
                        help="force a fresh interactive login")
    parser.add_argument("--logout", action="store_true",
                        help="delete the cached token and exit")
    parser.add_argument("--info", action="store_true",
                        help="print info about the cached token and exit")
    parser.add_argument("method", nargs="?",
                        help="RPC method (e.g. time, token)")
    args = parser.parse_args()

    store = TokenStore()

    if args.logout:
        store.clear()
        print("Logged out (cached token removed).")
        return

    if args.info:
        try:
            tok = store.load()
            print(describe_token(tok, str(store.path)))
        except FileNotFoundError:
            print(f"No cached token at {store.path}")
        return

    if not args.method:
        parser.error("method is required  (e.g. time, token)")

    # Interactive flows need identity + refresh scopes; client-credentials has
    # no user identity to assert so those scopes are meaningless there.
    scopes = [
        "openid", "profile", "email",
        "offline_access",
        CROSS_CLIENT_SCOPE_PREFIX + args.audience,
    ]
    if args.auth == "client-credentials":
        scopes = [CROSS_CLIENT_SCOPE_PREFIX + args.audience]

    try:
        endpoints = discover_provider(args.issuer)
    except Exception as e:
        fatal(f"discover issuer {args.issuer!r}: {e}")

    config = OIDCConfig(
        issuer=args.issuer,
        client_id=args.client_id,
        redirect_url=REDIRECT_URL,
        scopes=scopes,
    )

    try:
        access_token = obtain_access_token(store, endpoints, config, args.auth, args.login)
    except Exception as e:
        fatal(f"authentication failed: {e}")

    try:
        resp = call_rpc(args.addr, args.method, access_token)
    except Exception as e:
        fatal(f"rpc call: {e}")

    if resp.get("error"):
        err = resp["error"]
        fatal(f"server rejected request: [{err['code']}] {err['message']}")

    print(json.dumps(resp.get("result"), indent=2))


def obtain_access_token(store, endpoints, config, mode, force):
    """Return a valid access token, refreshing or logging in as needed."""
    if mode == "client-credentials":
        # Stateless machine-to-machine: mint a fresh token each run.
        # The secret comes from the environment to avoid landing in argv.
        secret = os.environ.get("OIDC_CLIENT_SECRET", "")
        try:
            tok = client_credentials_flow(
                endpoints.token_endpoint,
                config.client_id,
                secret,
                config.scopes,
            )
        except Exception as e:
            if "unsupported_grant_type" in str(e):
                raise RuntimeError(
                    f"{e}\n\nhint: Dex does not support the client_credentials grant; "
                    "point --issuer at a provider that does "
                    "(see DESIGN.md 'Service / role accounts')"
                ) from e
            raise
        return tok.access_token

    if not force:
        tok = store.get_valid_token(endpoints.token_endpoint, config.client_id)
        if tok:
            return tok.access_token
        # Cache miss or refresh failed — fall through to interactive login.

    if mode == "device":
        tok = device_flow(endpoints, config, present_device_code)
    elif mode == "authcode":
        tok = auth_code_flow(endpoints, config, present_auth_url)
    else:
        raise ValueError(
            f"unknown --auth mode {mode!r} (use authcode, device, or client-credentials)"
        )

    store.save(tok)
    return tok.access_token


def call_rpc(addr: str, method: str, access_token: str) -> dict:
    """Open a TCP connection, send one JSON-RPC request, read one response."""
    host, port_str = addr.rsplit(":", 1)
    with socket.create_connection((host, int(port_str))) as conn:
        req = json.dumps({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "token": access_token,
        }) + "\n"
        conn.sendall(req.encode())
        # Go's json.Encoder.Encode appends a newline; readline() reads exactly one.
        return json.loads(conn.makefile("r").readline())


def present_auth_url(auth_url: str) -> None:
    print("Opening browser to log in:")
    print(f"  {auth_url}")
    open_browser(auth_url)


def present_device_code(resp: dict) -> None:
    print("To log in, visit:")
    print(f"  {resp['verification_uri']}")
    print(f"and enter the code: {resp['user_code']}")
    if resp.get("verification_uri_complete"):
        print(f"\nOr open this URL directly (code pre-filled):\n  {resp['verification_uri_complete']}")
    print("\nWaiting for you to finish logging in...")


def open_browser(url: str) -> None:
    """Best-effort browser open; if it fails the user can click the printed URL."""
    system = platform.system()
    try:
        if system == "Darwin":
            subprocess.Popen(["open", url])
        elif system == "Windows":
            subprocess.Popen(["rundll32", "url.dll,FileProtocolHandler", url])
        else:
            subprocess.Popen(["xdg-open", url])
    except Exception:
        pass


def fatal(msg: str) -> None:
    print(f"error: {msg}", file=sys.stderr)
    sys.exit(1)


if __name__ == "__main__":
    main()
