# Design

This repo is an experiment in OIDC authentication for a small client/server
pair. The server speaks a minimal JSON-RPC protocol over TCP; the client logs in
through an OIDC provider, obtains an **access token**, and passes it on every
request. The server verifies the token and trusts the identity inside it.

The interesting part is not the RPC — it's **how the client acquires, stores,
refreshes, and presents credentials**, and **how the server validates them
without ever contacting the provider per-request**. That is what this document
focuses on.

## Components

```
        ┌────────────┐     1. log in (browser / device code)
        │   Client   │ ───────────────────────────────────────►┌──────────┐
        │   (CLI)    │ ◄───────────────────────────────────────│   Dex    │
        └─────┬──────┘     2. access + refresh + id tokens     │ (OIDC    │
              │                                                │ provider)│
              │ 3. JSON-RPC request                            └────┬─────┘
              │    { method, token: <access JWT> }                  │
              ▼                                                     │
        ┌────────────┐                                              │
        │   Server   │  4. verify JWT signature against JWKS ──────►│
        │ (resource) │     (fetched once, then cached)              │
        └────────────┘                                              │
```

- **Dex** is the OIDC provider. It stands in for a real-world provider such as
  Okta. The client and server only ever know an **issuer URL** and a **client
  id**, so migrating to Okta is a configuration change, not a code change.
- **Client** (`cmd/client`) is a native/CLI app. It is a *public* OAuth2 client:
  it ships no secret.
- **Server** (`cmd/server`) is a *resource server*. It owns no user database and
  performs no login. It only validates tokens.

## Why the access token (not the ID token)

OIDC produces two JWTs:

| Token        | Audience    | Intended consumer | Purpose                         |
| ------------ | ----------- | ----------------- | ------------------------------- |
| ID token     | the client  | the client        | "who is the logged-in user?"    |
| Access token | the API     | a resource server | "bearer credential for the API" |

Our JSON-RPC server is a resource server, so the textbook-correct credential to
present to it is the **access token**. The client sends `access_token`; the
server validates it. (With Dex both tokens are JWTs signed by the same key, so
the mechanics would be identical either way — but using the access token keeps
the experiment aligned with real Okta/production usage.)

The server reads the user's identity (`email`, falling back to `sub`) from the
verified token's claims and trusts it, because the signature proves the token
came from the provider and was not tampered with.

## Token audience: who the token is *for*

A JWT's `aud` (audience) claim names the party the token is meant for, and a
resource server must reject tokens that aren't addressed to it. Otherwise a token
minted for *some other* service could be replayed against ours.

By default Dex sets a token's `aud` to the **client that requested it** — here,
the CLI (`oidc-experiment-cli`). If the server simply required `aud =
oidc-experiment-cli`, it would accept *any* token Dex ever issued to the CLI for
any purpose. That's too loose: the server should only accept tokens explicitly
minted **for the server**.

So we give the resource server its own identity, `oidc-experiment-api`, and have
the client request that as the audience. The pieces:

- **A second registered client** in `dex/config.yaml`, `oidc-experiment-api`,
  representing the API. It never runs a login flow; it exists only to be named as
  an audience. It lists the CLI as a **trusted peer**.
- **The CLI requests it** by adding the scope
  `audience:server:client_id:oidc-experiment-api`. This is Dex's "cross-client"
  mechanism (`internal/auth` builds the scope from the `--audience` flag).
- **Dex honors it only because of the trust**: `oidc-experiment-api` lists
  `oidc-experiment-cli` in `trustedPeers`, so Dex is willing to mint a token
  addressed to the API on the CLI's behalf. Without that trust the request is
  refused.

The resulting access token carries `aud = ["oidc-experiment-api",
"oidc-experiment-cli"]` (Dex always keeps the requesting client in the list, with
`azp` — authorized party — identifying who actually asked). The server is
configured with `--audience oidc-experiment-api` and requires that value to be
present. A plain token whose audience is only `oidc-experiment-cli` is now
**rejected**, which is the property we wanted.

> **Honest caveat.** Dex stamps this same audience on the **ID token** too, so
> `aud` alone does not let the server distinguish an access token from an ID
> token — both would pass. Fully separating them would require checking a
> token-type marker or introspecting. Requiring a dedicated API audience is
> still the right and standard hardening step: it ensures the token was minted
> *for this API*, not merely for the client.

## The two login flows

The client supports two interactive flows, selected with `--auth`. Both produce
an identical `*oauth2.Token`; **everything downstream — storage, refresh, the RPC
call — is flow-agnostic.** The flow only matters at first login (and when the
refresh token has died).

### `--auth=authcode` — Authorization Code + PKCE (default)

For a machine with a browser. See `internal/auth/authcode.go`.

1. The client starts a throwaway HTTP server on the loopback redirect URL
   (`http://127.0.0.1:5555/callback`).
2. It generates a **PKCE** verifier/challenge and a random **state**, then opens
   the browser at the provider's authorization endpoint.
3. The user logs in at the provider. The browser is redirected back to the
   loopback server with an authorization `code`.
4. The client exchanges the code **plus the PKCE verifier** for tokens.

PKCE (RFC 7636) is what lets a public client skip a client secret safely: the
authorization code is useless to an interceptor who doesn't hold the original
verifier. This is the flow Okta recommends for CLIs/native apps (RFC 8252).

### `--auth=device` — Device Authorization Grant

For headless boxes / SSH sessions with no local browser. See
`internal/auth/device.go`.

1. The client asks the provider for a device code + user code.
2. It prints a URL and a short user code: "go to `<url>` and enter `ABCD-1234`".
   The user does this on *any* device.
3. The client polls the token endpoint until the user finishes, then receives
   the same set of tokens.

No loopback server and no PKCE are involved.

## Token management

This is the core of the experiment.

### Lifetimes

Set in `dex/config.yaml`:

- **ID / access tokens: 10 minutes** (`expiry.idTokens`). Deliberately short so
  the silent-refresh path is exercised during normal use rather than once a day.
- **Refresh token: up to 90 days idle / ~165 days absolute.** Long-lived, opaque
  (not a JWT) — it is just a handle Dex stores server-side.

In production these numbers differ (Okta commonly issues ~1h access tokens), but
the shape is the same.

> A refresh token is only issued if the client requests the **`offline_access`**
> scope. The client always does (`cmd/client/main.go`). Without it there would be
> nothing to refresh with, and every expiry would force a full interactive login.

### Where tokens are stored

A single JSON file under the user's config directory, written with `0600`
permissions:

```
$XDG_CONFIG_HOME/oidc-experiment/token.json   (≈ ~/.config/oidc-experiment/token.json)
```

It holds the whole token set so the client can both *present* the access token
and *refresh* it later:

```json
{
  "access_token":  "eyJ...",
  "id_token":      "eyJ...",
  "refresh_token": "Chl0a2...",
  "token_type":    "Bearer",
  "expiry":        "2026-06-09T14:32:00Z"
}
```

See `internal/token/store.go`. Note we serialize a dedicated struct rather than
`oauth2.Token` directly, because the `id_token` lives in that type's untyped
`Extra` map and would otherwise be silently dropped on save.

> Production hardening (out of scope here): store these in the OS keychain
> (macOS Keychain / libsecret / Windows Credential Manager) instead of a flat
> file. It's a drop-in replacement for the `Store` type.

### How automatic refresh works

The client never logs in if it doesn't have to. On every invocation
(`obtainAccessToken` in `cmd/client/main.go`):

1. Load `token.json`. If it's missing, go to interactive login.
2. Wrap the cached token in a **persisting token source** (see below) and ask it
   for a token:
   - If the access token is still valid → it's returned as-is.
   - If it's expired (or within ~10s of expiry) → the source uses the refresh
     token to fetch a fresh set from the provider, **writes it back to disk**,
     and returns it.
3. If the refresh fails (refresh token expired/revoked/absent) → fall back to a
   full interactive login, then save the new tokens.

The mechanism is a thin wrapper over the standard library:

```
oauth2.Config.TokenSource(ctx, tok)   // a ReuseTokenSource:
                                       //   returns the current token until ~expiry,
                                       //   then auto-refreshes — but does NOT persist
        │
        ▼
persistingSource (internal/token/store.go)
        // calls the base source, and whenever the access token CHANGES
        // (i.e. a refresh happened) writes the new set to token.json
```

So "auto-refresh, persisted to disk" is achieved by composing one small type on
top of `golang.org/x/oauth2`'s built-in refreshing source. The same wrapper
serves both login flows because both just produce an `*oauth2.Token`.

`client --login` forces a fresh interactive login (ignoring the cache);
`client --logout` deletes `token.json`.

## Server-side verification

On startup the server performs OIDC **discovery** against the issuer and builds
a verifier (`internal/server`). The provider's signing keys (**JWKS**) are
fetched lazily and cached by `go-oidc`; the server does **not** call the provider
on every request.

For each request the server, via `verifier.Verify`:

1. Parses the JWT and checks its **signature** against the cached JWKS.
2. Checks the **issuer** matches the configured issuer.
3. Checks the **audience** contains the required API audience (`--audience`,
   default `oidc-experiment-api`) — see "Token audience" above.
4. Checks **expiry** (`exp`).

Only then does it run the method. A missing token, a bad signature, a wrong
issuer/audience, or an expired token all produce a JSON-RPC error with code
`-32001` ("unauthorized"). Anonymous requests are rejected by the same path
(empty token → error). This is what makes the short token lifetime safe: an
expired token is rejected, and the client transparently refreshes it.

Each connection also carries a read deadline (`Server.ReadTimeout`, default 5s),
so a client that connects but never sends a request cannot pin a goroutine and
socket open. The validation paths (valid / expired / wrong-audience /
wrong-issuer / bad-signature / missing) are covered by unit tests in
`internal/server` using a mock issuer.

## Protocol

One JSON object per direction, per TCP connection (`internal/rpc`).

Request:

```json
{ "jsonrpc": "2.0", "id": 1, "method": "time", "token": "<access JWT>" }
```

Success response:

```json
{ "jsonrpc": "2.0", "id": 1, "result": { "time": "2026-06-09T14:22:01Z", "user": "alice@example.com" } }
```

Rejection:

```json
{ "jsonrpc": "2.0", "id": 1, "error": { "code": -32001, "message": "unauthorized: token is expired" } }
```

The only method today is `time`, which returns the current time in RFC 3339
format together with the authenticated user.

## Path to production (Okta)

Nothing structural changes:

- Point `--issuer` at the Okta org and `--client-id` at an Okta app registration.
- Register the same loopback redirect URI for the auth-code app, and enable the
  device grant for the device flow.
- Keep `offline_access` in the requested scopes.
- Keep requesting a dedicated API `audience`. Okta models this with a custom
  Authorization Server whose **audience** is your API; the client requests it via
  the standard `audience` parameter (rather than Dex's `audience:server:client_id:`
  scope), and the server still just requires that value in `aud`. The
  `--audience` flag and the server's expected-audience check are unchanged.
