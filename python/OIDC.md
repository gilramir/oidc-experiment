# Developer's Guide: `oidc_auth.py`

A library for authenticating CLI tools and services against any OIDC provider
(Dex, Okta, Keycloak, …). It covers three grant types, an on-disk token cache
with silent refresh, and a clean separation between the auth logic and the UI
so tests can drive it without a real browser.

## Installation

```
pip install requests        # only external dependency
```

Python 3.10+ required.

---

## Concepts

### The three grant types

| Flow | When to use | User involved? | Refresh token? |
|---|---|---|---|
| Authorization Code + PKCE | Default for CLI tools that can open a browser | Yes | Yes |
| Device Authorization Grant | Headless, SSH, or no local browser | Yes | Yes |
| Client Credentials | Automation, CI, daemons — no human | No | No |

All three return the same `Token` dataclass. Everything downstream
(storage, refresh, the RPC call) is identical regardless of which flow ran.

### The `present` callback

The interactive flows (auth-code and device) don't decide how the user is
notified — that's the caller's job. Both accept a `present` function that
receives the URL or device response and does whatever is appropriate: print to
stdout, open a browser, drive a headless test browser, etc.

This makes unit-testing flows without a real browser straightforward (see
[Testing](#testing) below).

---

## Data types

### `Token`

```python
@dataclass
class Token:
    access_token: str
    token_type: str           # "Bearer"
    refresh_token: str        # empty for client-credentials
    id_token: str             # OIDC id token, empty if not returned
    expiry: datetime | None   # timezone-aware UTC; None means "unknown"

    def is_valid(self) -> bool: ...    # non-empty access_token and not expired
    def is_expired(self, skew_seconds=10) -> bool: ...
```

### `OIDCConfig`

```python
@dataclass
class OIDCConfig:
    issuer: str        # e.g. "https://your-provider/dex"
    client_id: str     # registered public client id
    redirect_url: str  # loopback URL for auth-code callback
    scopes: list[str]  # see Scopes section below
```

### `ProviderEndpoints`

```python
@dataclass
class ProviderEndpoints:
    authorization_endpoint: str
    token_endpoint: str
    device_authorization_endpoint: str   # empty if provider doesn't support it
```

Obtain this via `discover_provider()` — don't fill it by hand.

---

## API

### `discover_provider(issuer) → ProviderEndpoints`

Fetches `{issuer}/.well-known/openid-configuration` and returns the parsed
endpoints. Call this once at startup.

```python
from oidc_auth import discover_provider

endpoints = discover_provider("http://127.0.0.1:5556/dex")
print(endpoints.token_endpoint)
# → http://127.0.0.1:5556/dex/token
```

Raises `requests.HTTPError` if the discovery request fails.

---

### `auth_code_flow(endpoints, config, present) → Token`

Authorization Code + PKCE (RFC 7636). No client secret needed; PKCE replaces
it for public clients.

1. Binds a throwaway HTTP server on the loopback address in `config.redirect_url`.
2. Calls `present(auth_url)`.
3. Waits for the provider to redirect the browser back with an authorization code.
4. Exchanges the code + PKCE verifier for tokens.

```python
from oidc_auth import OIDCConfig, auth_code_flow, discover_provider
import subprocess, sys

endpoints = discover_provider("http://127.0.0.1:5556/dex")
config = OIDCConfig(
    issuer="http://127.0.0.1:5556/dex",
    client_id="my-cli",
    redirect_url="http://127.0.0.1:5555/callback",
    scopes=["openid", "profile", "email", "offline_access"],
)

def open_browser(url: str) -> None:
    print(f"Opening: {url}")
    subprocess.Popen(["xdg-open", url])

tok = auth_code_flow(endpoints, config, open_browser)
print(tok.access_token)
```

The `redirect_url` host and port determine where the loopback server listens.
The path (e.g. `/callback`) must match what the provider has registered.

---

### `device_flow(endpoints, config, present) → Token`

Device Authorization Grant (RFC 8628). No loopback server, no PKCE.
Good for SSH sessions or environments where you can't open a local browser.

`present` receives the raw device-auth response dict, which contains:

| Key | Description |
|---|---|
| `verification_uri` | URL the user visits |
| `user_code` | Code the user enters |
| `verification_uri_complete` | URL with the code pre-filled (optional) |
| `expires_in` | Seconds until the code expires |

```python
from oidc_auth import device_flow

def show_code(resp: dict) -> None:
    print(f"Visit {resp['verification_uri']}")
    print(f"Enter code: {resp['user_code']}")

tok = device_flow(endpoints, config, show_code)
print(tok.access_token)
```

The library polls at the interval the provider specifies and handles
`authorization_pending` and `slow_down` errors automatically.

---

### `client_credentials_flow(token_url, client_id, secret, scopes) → Token`

Client Credentials grant (RFC 6749 §4.4). The application is the principal —
no user, no browser, no refresh token. Re-mint a fresh token on every run.

```python
import os
from oidc_auth import client_credentials_flow

tok = client_credentials_flow(
    token_url=endpoints.token_endpoint,
    client_id="my-service-account",
    client_secret=os.environ["OIDC_CLIENT_SECRET"],
    scopes=["audience:server:client_id:my-api"],
)
print(tok.access_token)
```

Always read the secret from an environment variable — never from a flag or
config file, so it does not appear in shell history or `argv`.

Note: Dex (the bundled dev provider) does not implement this grant. It works
against Okta, Keycloak, Authentik, Zitadel, and other production providers.

---

### `refresh_access_token(token_endpoint, client_id, tok) → Token`

Explicitly refresh an expired token. You usually don't call this directly —
`TokenStore.get_valid_token()` does it for you.

```python
from oidc_auth import refresh_access_token

fresh = refresh_access_token(endpoints.token_endpoint, config.client_id, stale_tok)
```

If the provider rotates the refresh token on each use and omits it from the
response, the old refresh token is preserved in the returned `Token`.

Raises `RuntimeError` if the cached token has no refresh token (e.g. a token
produced by the client-credentials flow).

---

### `TokenStore`

On-disk token cache at `~/.config/{app}/token.json` (mode 0600).
The format stores `id_token` explicitly, which standard OAuth2 libraries
typically discard.

```python
from oidc_auth import TokenStore

store = TokenStore()            # ~/.config/oidc-experiment/token.json
store = TokenStore(app="myapp") # ~/.config/myapp/token.json
store = TokenStore(path="/tmp/tok.json")  # explicit path, useful in tests
```

#### `store.load() → Token`

Load from disk. Raises `FileNotFoundError` if nothing is cached.

#### `store.save(tok)`

Write to disk with `0600` permissions, creating parent directories as needed.

#### `store.clear()`

Delete the cached token file. No-op if it does not exist.

#### `store.get_valid_token(token_endpoint, client_id) → Token | None`

The main entry point for cached auth. Returns `None` when:
- No token file exists.
- The access token is expired and there is no refresh token.
- The refresh request fails (token revoked, provider unreachable, etc.).

```python
tok = store.get_valid_token(endpoints.token_endpoint, config.client_id)
if tok:
    use(tok.access_token)
else:
    # run an interactive flow, then store.save(tok)
```

---

## Scopes

Always include:

| Scope | Purpose |
|---|---|
| `openid` | Required for OIDC — gives you an `id_token` |
| `profile`, `email` | Standard user identity claims |
| `offline_access` | Requests a refresh token |

**Audience scopes (Dex-specific).** Dex uses a non-standard cross-client scope
to set the access token's audience to a resource server rather than the CLI
itself:

```python
scopes = [
    "openid", "profile", "email", "offline_access",
    "audience:server:client_id:my-api",   # makes my-api the token's audience
]
```

The resource server (`my-api`) must list the CLI as a `trustedPeer` in the
Dex config. Other providers (Okta, Keycloak) have their own audience-mapping
mechanisms; consult `PROVIDERS.md`.

For client-credentials flows, omit `openid` / `offline_access` — there is no
user identity to assert and nothing to refresh.

---

## Complete example

The following mirrors what `client.py` does: try the cache, fall back to
interactive login, save the result.

```python
import os
from oidc_auth import (
    OIDCConfig, TokenStore,
    discover_provider, auth_code_flow, device_flow,
)

ISSUER     = "http://127.0.0.1:5556/dex"
CLIENT_ID  = "my-cli"
REDIRECT   = "http://127.0.0.1:5555/callback"
SCOPES     = ["openid", "profile", "email", "offline_access",
               "audience:server:client_id:my-api"]

endpoints = discover_provider(ISSUER)
config    = OIDCConfig(ISSUER, CLIENT_ID, REDIRECT, SCOPES)
store     = TokenStore(app="my-cli")

def get_token(force_login=False, device=False) -> str:
    if not force_login:
        tok = store.get_valid_token(endpoints.token_endpoint, CLIENT_ID)
        if tok:
            return tok.access_token

    if device:
        tok = device_flow(endpoints, config, lambda r: (
            print(f"Visit {r['verification_uri']}"),
            print(f"Code:  {r['user_code']}"),
        ))
    else:
        tok = auth_code_flow(endpoints, config, lambda url: (
            print(f"Opening: {url}"),
            __import__("subprocess").Popen(["xdg-open", url]),
        ))

    store.save(tok)
    return tok.access_token
```

---

## Testing

Because auth and UI are decoupled via the `present` callback, tests can drive
the flows without a real browser. The end-to-end test suite in `internal/e2e`
(Go) passes a function that submits Dex's login form programmatically; the
same pattern works here.

For `auth_code_flow`, your test `present` function should open the auth URL
in a headless browser (e.g. Playwright or Selenium), submit the credentials,
and let the redirect complete. The library's loopback server handles the rest.

For `device_flow`, point a headless browser at `verification_uri`, enter the
`user_code`, and approve.

Use `TokenStore(path="/tmp/test-token.json")` to isolate test token files from
your real cache.

---

## Provider compatibility notes

| Feature | Dex (dev) | Okta | Keycloak | Authentik |
|---|---|---|---|---|
| Auth-code + PKCE | ✓ | ✓ | ✓ | ✓ |
| Device flow | ✓ | ✓ | ✓ | ✓ |
| Client credentials | ✗ | ✓ | ✓ | ✓ |
| Cross-client audience scope | ✓ | — | — | — |

See `PROVIDERS.md` for provider-specific audience-mapping details.
