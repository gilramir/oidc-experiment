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

## Authentication backends (Dex connectors)

Dex is a front end, not an identity store. It speaks OIDC/OAuth2 to our client
and delegates the *actual* authentication to a pluggable backend it calls a
**connector** (LDAP, SAML, GitHub/Google/Microsoft, a generic upstream OIDC
provider, …). Swapping the backend is a Dex-side change only: the issuer URL and
client ids the client/server know never move.

This repo ships two configs and a launcher:

| Backend | Config | Launch |
| --- | --- | --- |
| Static password (default) | `dex/config.yaml` | `./scripts/run-dex.sh` (or `static`) |
| LDAP directory | `dex/config-ldap.yaml` | `./scripts/run-dex.sh ldap` |

The default uses Dex's built-in `staticPasswords` (alice@example.com) so the
experiment runs with no external dependencies. `dex/config-ldap.yaml` is a
ready-to-fill template for a site that has a real LDAP/AD server — it is *not*
enabled by default and has placeholder values.

**How the LDAP connector authenticates.** Dex binds to the directory with a
read-only service account, searches for the user who is logging in, then
re-binds *as that user* with the password they typed — a successful bind is the
proof. Optional group lookup is surfaced as a `groups` claim (only if the client
also requests the `groups` scope, which this CLI does not by default).

Because verification is a bind against a typed password, **LDAP only works with
flows where Dex itself collects the password** — the browser-based auth-code
login form and the device-flow verification page. That is exactly what this CLI
drives. It does *not* add a non-interactive password-grant or passthrough path;
the password is still entered at Dex's page, never handled by our client (see
"CLI login: terminal vs. browser"). Dex's own `storage` stays `memory` either
way — that holds Dex's auth codes and refresh tokens, not user identities, which
live in LDAP.

The placeholder fields (host/TLS, service-account bind, `userSearch`,
`groupSearch`, and the Active-Directory attribute equivalents) are documented
inline in `dex/config-ldap.yaml`.

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
3. The user opens the URL in a **browser on any other device** — a laptop, a phone,
   anything. They type the user code, then **log in normally at the provider's page**:
   username + password, MFA, SSO, whatever that provider requires. This is the same
   login form as the auth-code flow; only the entry point differs.
4. The provider links the approved user code → device code it issued in step 1.
5. The client's next poll succeeds and it receives tokens scoped to that user.

The `device_code` is only a **temporary nonce** — it carries no cryptographic proof of
device identity. The security model rests entirely on the user-code UX: it is
short-lived, and the user must proactively visit the specific URL and type it in. The
assumption is that only the person who initiated the flow would do so.

One implication: **device code phishing** is a real attack. An attacker can start the
flow on their own machine, send a victim a phishing link to `<url>?user_code=…`, and if
the victim logs in they are handing the attacker a valid token. This cannot be fully
prevented at the client level — it is the provider's and user's problem — but short
code expiry limits the window.

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

### Real-world lifetimes and re-authentication

The values above are compressed for the experiment, but they mirror the real
shape: a **short access token** (invisible plumbing — the client refreshes it
silently) and a **long refresh token** (what actually decides how often a human
must log in again through a browser).

Access / ID tokens, typical production values:

| Provider | Access-token lifetime |
| --- | --- |
| Okta | 1 hour default (≈5 min–24 h configurable) |
| Microsoft Entra (Azure AD) | ~60–90 min (randomized) |
| Auth0 | minutes to ~24 h, configurable |
| Google | 1 hour |
| AWS Cognito | 1 hour default (5 min–24 h) |

High-security APIs go as low as 5–15 min: a leaked access token is only useful
until it expires (see "Token introspection and revocation" below for the
revocation trade-off).

Refresh tokens have **two clocks**, and whichever fires first ends the
silent-refresh streak:

1. **Idle / inactivity window (sliding)** — valid as long as it is *used* within
   this period; each use resets it (especially with rotation). Commonly 14–90 days.
2. **Absolute / maximum lifetime (hard cap)** — a wall regardless of activity.
   Commonly 30 days to ~1 year, sometimes "unlimited."

| Provider | Refresh token, typical |
| --- | --- |
| Okta | sliding 30–90 days; absolute cap optional (can be "unlimited" with rotation) |
| Entra (Azure AD) | ~90-day sliding window; bounded/overridden by Conditional Access |
| Auth0 | rotation on; idle ~15 days, absolute ~30 days (configurable) |
| Google (installed/CLI apps) | effectively indefinite; dies on long inactivity, password change, or revoke |

So a regularly used CLI can auto-refresh **silently for weeks to months** — bounded
by the idle window if it goes unused, and by the absolute cap if one is set.

A browser re-authentication is forced — regardless of those timers — by:

- **Refresh token expiry** (idle or absolute) — the normal case.
- **Revocation** — logout, "sign out everywhere," admin revoke, password change.
- **Rotation reuse detection** — replaying an already-rotated refresh token
  invalidates the whole chain as a theft signal. (This is why a second login
  invalidated the first refresh token in the e2e test — Dex rotates refresh
  tokens.)
- **Policy / step-up auth** — Conditional Access or an MFA policy may require
  fresh authentication every N days, or for sensitive actions, even while tokens
  are still valid.
- **Scope / consent changes** — requesting new scopes needs a fresh authorization.

In this experiment the refresh token is **90 days idle / ~165 days absolute**, so
a user who runs the CLI at least every 90 days (and within ~165 days of first
login) never sees a browser again — the production pattern. Raising `idTokens`
from `10m` to `1h` would make the numbers realistic outright.

#### Who actually sets these lifetimes (Okta)

In this experiment **we** set the lifetimes, because we own `dex/config.yaml`. In
a real Okta deployment that file belongs to your IT/IAM team, and the split of
control matters:

- **The authorization server (Okta) sets every lifetime.** Access-token and
  refresh-token lifetimes are configured per **access-policy rule** on the Okta
  authorization server (Security → API → Authorization Servers → Access Policies),
  and changing them requires admin rights. The ID token is fixed at 1 hour and is
  not configurable. None of this is in the gift of the application developer.
- **The resource server (our `cmd/server`) gets no say.** It only *verifies* the
  `exp` Okta already stamped — exactly what `internal/server` does via go-oidc. If
  you need shorter effective sessions than Okta grants, the only server-side lever
  is to be *stricter* than the token (e.g. additionally reject by `iat` age); you
  can never extend a lifetime, only shorten its acceptance.
- **The client (our `cmd/client`) influences only indirectly.** The scopes/audience
  it requests select *which* access-policy rule applies, and different rules can
  carry different lifetimes — so the client can land on a longer- or shorter-lived
  token, but only among options the admins have already defined. The client also
  owns the *refresh cadence* (whether it requests `offline_access` and how often it
  refreshes), not the token's stamped lifetime.

Caveat: this assumes a **custom authorization server** (Okta Developer/Org editions
with API Access Management). The default "org authorization server" exposes fewer
lifetime knobs — confirm with your Okta admins which one you'll be issued against.

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

## Configuring the client

The client needs more than the server, because it actually performs the OAuth
exchange (the server only validates the result). But it still ships **no secret**.
The configuration lives in `cmd/client/main.go` and `auth.Config`:

1. **The issuer URL** (`--issuer`). The same anchor as the server. From discovery
   the client learns the endpoints it *drives*:
   - **`authorization_endpoint`** — where to send the user to log in (auth-code);
   - **`token_endpoint`** — where to exchange the code, and where to **refresh**;
   - **`device_authorization_endpoint`** — where to start the device flow.
2. **A client id** (`--client-id`, `oidc-experiment-cli`) — its registered
   identity, sent on every request so the provider knows which app is asking.
3. **A redirect URI** (`http://127.0.0.1:5555/callback`) — **auth-code flow only**.
   The loopback URL the provider returns the browser to; it must exactly match one
   registered at the provider. The **device flow needs no redirect URI**.
4. **Scopes** (`openid profile email offline_access` + the audience scope):
   - `openid` makes it an OIDC request;
   - **`offline_access`** is what yields a **refresh token** — without it, every
     expiry becomes a fresh browser login;
   - `profile` / `email` populate identity claims;
   - the cross-client audience scope (built from `--audience`) so the token is
     minted for the resource server (see "Token audience" above).

What it does **not** need:

- **No client secret.** The CLI is a **public client** and uses **PKCE** instead;
  PKCE proves it is the same app that started the flow, so no shipped secret is
  required. A *confidential* client (a server-side web app) would need a secret
  here — a CLI should not.
- **No token-validation logic** — the client consumes tokens; only the server
  verifies them.

**Prerequisite — registration.** The client id *and* its redirect URI must be
**pre-registered at the provider** (`dex/config.yaml` `staticClients`; an app
registration in Okta). An unknown client id or an unregistered redirect URI is
rejected — this is the "Unregistered redirect_uri" wall the device flow hits if
its callback isn't registered.

Implicit requirements:

- **A way to complete the login** — a browser on the machine (auth-code), or the
  ability to display a URL + code for the user to enter elsewhere (device).
- **Network reachability to the issuer** — for discovery, the token exchange, and
  every refresh.
- **Somewhere to cache tokens** — client-side state
  (`~/.config/oidc-experiment/token.json`), not provider info, but required for
  refresh to work across runs.

## Configuring the server

Because the server validates tokens **locally**, it needs surprisingly little —
just two pieces of configuration (`server.New(ctx, issuer, audience)`):

1. **The issuer URL** (`--issuer`, e.g. `http://127.0.0.1:5556/dex`). This is the
   anchor for everything else. On startup the server fetches the issuer's
   discovery document (`<issuer>/.well-known/openid-configuration`) and learns:
   - the **`jwks_uri`** — where to fetch the provider's public signing keys
     (JWKS), used to verify token **signatures**;
   - the canonical **`issuer`** string — which must match the token's `iss` claim.
2. **The expected audience** (`--audience`, e.g. `oidc-experiment-api`) — the
   value the server requires in the token's `aud` claim, i.e. its own
   resource-server identity (see "Token audience" above).

What it does **not** need, and why:

- **No client id / secret.** The server is a *resource server*, not an OAuth
  client. It never calls the token or authorization endpoints and never logs
  anyone in. The only provider endpoint it touches is the **JWKS** — public keys,
  no authentication required.
- **No redirect URI, scopes, or PKCE** — those belong to the client.
- **No JWKS URL by hand** — it is discovered from the issuer. (You could supply it
  directly if a provider lacked discovery, but standard OIDC providers have it.)
- **No per-request call to the provider** — JWKS is fetched once and cached.

Implicit requirements worth noting:

- **Network reachability to the issuer** at startup (discovery + JWKS), and
  occasionally afterward for key rotation. If the provider is unreachable on boot,
  `server.New` fails.
- **A correct clock** (NTP) — the `exp` / `iat` / `nbf` checks assume the server's
  time is roughly right.
- **Matching signing algorithm** — `go-oidc` defaults to RS256 (what Dex uses). A
  provider signing with ES256 etc. would require configuring the allowed algs,
  which discovery advertises in `id_token_signing_alg_values_supported`.

> **The introspection exception.** If the server instead used **opaque** access
> tokens, or chose introspection for immediate revocation (see "Token
> introspection and revocation" below), it *would* need its own **client
> credentials** to authenticate to the provider's `/introspect` endpoint. Local
> validation needs only public information (issuer + audience); introspection
> needs the server to be a credentialed client.

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

Two methods, both requiring a valid token:

- **`time`** — returns the current time in RFC 3339 format together with the
  authenticated user (email, else subject).
- **`token`** — echoes back the **verified token claims** as the result object:
  whatever the provider put in the token, e.g. `sub`, `email`, `name`, `groups`,
  plus the standard `iss`/`aud`/`exp`/`iat`. It is a diagnostic: it confirms auth
  is working *and* shows exactly what the server sees, which is the natural place
  to read a `groups` claim for authorization (see "Authentication backends").

```json
{ "jsonrpc": "2.0", "id": 1, "result": {
  "sub": "08a8684b-…", "email": "alice@example.com", "name": "Alice",
  "groups": ["engineering"], "iss": "http://127.0.0.1:5556/dex",
  "aud": "oidc-experiment-api", "exp": 1749481321 } }
```

The server only returns claims for a token that already passed verification, so
`token` is also a quick way to confirm a login succeeded. (Which claims appear
depends on the scopes the client requested and what the backend supplies —
`groups` only shows up with a group-aware backend and the `groups` scope.)

## Transport security (TLS)

This experiment sends the JSON-RPC request — **including the access token** — over
**plain TCP**. In production that should be TLS. Here is the reasoning, and the
cases where plaintext is acceptable.

### Why TLS is recommended

The access token is a **bearer token**: whoever presents it is treated as the
user, no questions asked. Our signature/issuer/audience/expiry checks prove the
token is *authentic*, but they cannot tell whether the *legitimate client* or an
attacker is presenting it. So a token observed on the wire can simply be
**replayed** until it expires (≤10 min here) and the server will accept it.

Plain TCP exposes the token to anyone who can see the traffic — a host on the same
LAN, a compromised router, anything in the path. TLS closes two holes at once:

- **Confidentiality** — the channel is encrypted, so the token (and the request)
  can't be sniffed and replayed.
- **Server authentication** — the client verifies the server's certificate, so it
  isn't handing its token to an impostor (a man-in-the-middle).

This is not optional in the spec: RFC 6750 (OAuth 2.0 Bearer Token Usage)
**requires** TLS whenever a bearer token is transmitted. The same applies to the
OIDC traffic itself — the authorization code, the token exchange, and refreshes
all carry secrets, which is why real issuer URLs are **`https://`** (OIDC requires
it; Dex and `go-oidc` permit `http://` only for localhost, which is exactly why
this experiment can use a plain `http://127.0.0.1` issuer).

### When plaintext is OK

The token only needs transport protection when it crosses a network another party
could observe. Plaintext is acceptable when that isn't the case:

- **Loopback only.** If the client, server, and provider all run on `127.0.0.1`
  and the traffic never leaves the host, no other network host can see it. That is
  exactly this experiment's situation, and why it skips TLS. (On a shared
  multi-user machine, even loopback can be observable by other local users/root,
  so this assumes a single-trust host.)
- **TLS terminated by the infrastructure.** In a service mesh with mutual TLS, or
  behind a localhost sidecar/proxy that adds TLS, the application speaks plaintext
  but the wire is already protected. The app offloads transport security rather
  than omitting it.
- **Throwaway experiments and tests**, like this repo.

The rule of thumb: **the moment the token travels over a LAN, the internet, or any
link a third party could tap, TLS is mandatory.** This experiment uses plain TCP
solely because everything is on loopback; promoting it to a real deployment means
putting the server behind TLS (and pointing the client at an `https://` address).

## CLI login: terminal vs. browser

A common question for a CLI like this one: **can the user just type their username
and password at the command line, or must they use a browser?**

Short answer: there *is* a no-browser path where the user types credentials right
at the terminal — but it's a different OAuth grant, and it only works for plain
password accounts. Once real-world authentication is involved (MFA, SSO,
federated/social login, passkeys), a browser becomes effectively mandatory,
because the identity provider — not the CLI — owns the login ceremony.

The experiment ships two browser-delegating flows (`--auth=authcode` and
`--auth=device`, covered above). This section records the terminal-only
alternatives and why they are not the default.

### Option A — Resource Owner Password Credentials (ROPC), the "password" grant

The direct answer. The CLI prompts for username + password and POSTs them
straight to the token endpoint — no browser, no redirect, no loopback server:

```
POST /token
grant_type=password
&client_id=oidc-experiment-cli
&scope=openid profile email offline_access
&username=alice@example.com
&password=...
```

You get back the same tokens (including a refresh token if `offline_access` is
requested).

**Dex supports it** with one config line — point it at the connector that handles
passwords:

```yaml
oauth2:
  responseTypes: ["code"]
  passwordConnector: local   # "local" is the enablePasswordDB connector
```

The client then performs the token request above. In this repo it would slot in
cleanly as a third mode, `--auth=password`.

**Okta supports it too**, but you must enable "Resource Owner Password" in the
app's allowed grant types.

**Why it's discouraged:**

- **Deprecated.** Removed entirely in OAuth 2.1; both Okta and the IETF actively
  advise against it.
- **The CLI handles the raw password** — exactly what OAuth was designed to
  avoid. Only acceptable for a fully trusted first-party client.
- **Breaks with MFA and federation.** If the user logs in via Google/SAML/social,
  or has any second factor, plain ROPC fails — there's no way to render that
  challenge inside a `grant_type=password` call. An MFA-enrolled Okta user gets
  an error instead of a token.

### Option B — Okta Authentication API (interactive CLI, no browser, incl. MFA)

Okta has a proprietary path that real CLIs use for terminal-only login *including*
MFA:

1. CLI prompts for username/password and calls Okta's **Authentication API**
   (`POST /api/v1/authn`).
2. If MFA is required, the API returns a challenge; the CLI **prompts for the OTP
   at the terminal** and answers it.
3. On success Okta returns a one-time **`sessionToken`**.
4. The CLI runs a normal **Authorization Code flow but passes `sessionToken=...`
   to `/authorize`** — Okta skips the login page and returns the code, which the
   CLI exchanges for tokens.

This is how tools like `okta-aws-cli` allow full terminal login, OTP and all,
with no browser. It is **Okta-specific** (Dex has no equivalent) and still cannot
handle factors that require a browser (WebAuthn/passkeys, IdP redirects).

### The fundamental constraint

Browser flows exist because **the IdP, not the CLI, owns the authentication
ceremony.** A browser can render whatever the IdP presents: a Google login, a
SAML redirect, a push notification, a passkey prompt. A CLI that collects
`username`/`password` can only handle username and password.

- **Local password accounts** → terminal-typed login is feasible (Option A, or
  Option B on Okta).
- **Anything federated / SSO / MFA-with-passkey** → fall back to a browser. This
  is why the **Device Authorization Grant** exists: it keeps the CLI itself
  browser-free, but still delegates the actual login to a browser somewhere
  (even on your phone).

### Decision for this experiment

We use the browser-delegating flows (`--auth=authcode`, `--auth=device`) because
they reflect how a real CLI authenticates against Okta and survive MFA/SSO.

Since our Dex setup uses a local `passwordDB`, **Option A (ROPC) would also work**
and is a legitimate thing to demo — it cleanly contrasts "trusted first-party CLI
takes the password" against "delegate to the browser." If added, it should be
exposed as `--auth=password` and clearly labelled deprecated / first-party-only,
so the experiment documents *why* it's normally avoided. It is intentionally not
implemented today.

## Service / role accounts (machine-to-machine)

Everything above assumes a **human**: the auth-code and device flows both end at a
login page somebody fills in. But automation — CI jobs, cron tasks, daemons, one
service calling another — has no human and no browser. How does a "role" account
authenticate?

The answer is a different OAuth2 grant whose whole point is that **there is no
user**: the **Client Credentials grant** (RFC 6749 §4.4). The automation itself is
the principal. There is no login ceremony to delegate, so there is no browser, no
redirect, and no device code — the client authenticates directly to the token
endpoint with its own credentials:

```
POST /token
grant_type=client_credentials
&client_id=oidc-experiment-bot
&client_secret=...                                 # or a signed JWT assertion (below)
&scope=audience:server:client_id:oidc-experiment-api
```

What comes back differs from the human flows in two ways that ripple through the
rest of this design:

- **No `id_token`.** An ID token answers "who is the logged-in *user*?" — and there
  isn't one. The access token's `sub` is the **client itself** (`oidc-experiment-bot`),
  not a person. (So the server's "identity" for a role account is the client id, not
  an `email` — see "Authorization" below.)
- **No refresh token.** Refresh tokens exist to avoid re-prompting a human. A
  machine can just ask for a new access token whenever it needs one — re-minting is
  a cheap, stateless POST. Requesting `offline_access` here would be pointless.

### How it maps onto this experiment

The key property is that **the server does not change at all.** `internal/server`
only checks signature / issuer / audience / expiry; it never cares *which grant*
minted the token. A client-credentials access token from the same issuer carrying
`aud = oidc-experiment-api` validates by the identical code path as a human's
token. Only the *client*'s token-acquisition step is new.

Concretely, the repo gains a third login mode alongside `authcode` and `device`:

- **`internal/auth/clientcreds.go`** — `ClientCredentials(...)`, a thin wrapper over
  `golang.org/x/oauth2/clientcredentials`. Like `Device` and `AuthCode` it returns
  an `*oauth2.Token`; unlike them it needs a **client secret**.
- **`cmd/client`** — `--auth=client-credentials`. It reads the secret from
  `OIDC_CLIENT_SECRET` (never a flag — secrets do not belong in argv or shell
  history), requests only the audience scope (no `openid`/`offline_access`), and
  **skips `internal/token` entirely**: there is no refresh token to persist and no
  per-user state worth caching, so it mints a fresh token each run rather than
  writing one to `~/.config`.

```sh
OIDC_CLIENT_SECRET=… go run ./cmd/client \
    --auth=client-credentials --client-id=oidc-experiment-bot token
```

The **audience subtlety is unchanged**: the bot must still get `aud =
oidc-experiment-api` onto its token, so `dex/config.yaml` lists `oidc-experiment-bot`
as a `trustedPeer` of `oidc-experiment-api`, exactly as it does for the CLI (see
"Token audience" above).

### The Dex caveat (this grant does not run against Dex)

There is one blunt limitation, and it is worth stating plainly because it bites
immediately: **mainline Dex does not implement the client_credentials grant.** Its
discovery document advertises only `authorization_code`, `refresh_token`,
`device_code`, and `token-exchange` (plus `implicit`/`password` conditionally), and
no config can add to that set — it is hard-coded in Dex's server. Running the
command above against the bundled Dex returns `unsupported_grant_type` (the client
catches this and prints a hint pointing here).

So this flow is in the same category as Okta's Authentication API (Option B under
"CLI login"): the code and the `oidc-experiment-bot` registration are **correct for
a provider that supports the grant** — Okta, Keycloak, Zitadel, Auth0, Entra — and
switching to one is the usual config swap (issuer + client id + secret). Dex simply
cannot demo it. The one machine-to-machine grant Dex *does* support is **token
exchange** (next), which is the foundation of the modern, secretless approach.

### The hard part is the secret, not the grant

Client Credentials is trivial mechanically. The real problem of role accounts is
**where the credential lives and how the workload proves it is allowed to hold it.**
Roughly in increasing order of safety:

| Approach | How it works | Good for |
| --- | --- | --- |
| **Static client secret** | Shared secret in a vault / env var / k8s Secret (what `--auth=client-credentials` uses) | Simple CI bots, on-prem |
| **`private_key_jwt`** | The client signs a short-lived JWT assertion with a private key instead of sending a shared secret; only the *public* key is registered at the provider. No secret ever crosses the wire; the key can sit in an HSM. | Avoiding a shared secret; higher-assurance M2M |
| **Workload identity federation** | *No stored secret at all.* The platform (GitHub Actions, GCP, AWS, Kubernetes, SPIFFE/SPIRE) issues the workload a short-lived OIDC token proving its identity; the provider trusts that issuer and exchanges it for an access token via **token exchange (RFC 8693)**. | CI/CD and cloud workloads — the current best practice |

That last row is why token exchange matters: it lets automation hold **no
long-lived credential**. The runner proves its identity to *its own* platform, gets
a short-lived JWT, and trades it for a token from the OIDC provider. GitHub Actions
OIDC and SPIFFE are the common implementations. Dex supports the token-exchange
grant, but a working demo needs an **upstream connector** to validate the incoming
subject token, which the bundled static-password setup doesn't have — so it is
documented here rather than wired up.

#### Workload identity in practice

The pattern is always: **platform attestation → short-lived OIDC token → Token
Exchange → access token**. The receiving service does not change — it still validates
the same way against the same IdP. Only the *calling* service's token-acquisition
step differs.

**Kubernetes projected service account tokens.** Each pod can be given a
volume-projected service account JWT bound to a specific audience (not the default
`kubernetes.svc` token — that one is long-lived and too broad). Configure the IdP
to trust the k8s API server as an upstream OIDC issuer; then the pod exchanges its
SA token at the IdP's token endpoint via RFC 8693 and gets back an access token it
can present to other services. AWS EKS IRSA and GCP Workload Identity Federation
both work this way: the cloud IAM system is the IdP, the k8s OIDC issuer is the
trusted upstream, and the pod's SA token is the subject token being exchanged.

**SPIFFE/SPIRE.** For environments that span k8s, VMs, and bare-metal, SPIRE
attests each workload (by node/process/pod/container identity) and issues
short-lived **JWT-SVIDs** with a `spiffe://` URI as the subject. These can be
used as subject tokens in a Token Exchange request to any IdP that trusts the
SPIRE issuer. SPIRE is the standard approach for multi-platform service meshes
where you can't assume k8s everywhere.

**GitHub Actions / CI.** Each job gets a short-lived OIDC token from GitHub's own
issuer, scoped to the repository and workflow. Configure the IdP to trust
`token.actions.githubusercontent.com` as an upstream, and the workflow can exchange
its job token for an access token — no secrets stored in the repo at all.

The net result in all these cases: a service calling another service presents an
access token just like a human would. The resource server (`internal/server`) is
identical. Only how that token was *minted* differs.

#### Secret storage options (for the static-secret approach)

When workload identity isn't available (on-prem, legacy infra, simple setups), the
client secret or private key has to live somewhere. Options roughly in order of
increasing security:

| Storage | Key property | Weakness |
| --- | --- | --- |
| **k8s Secret** | Simple; available to pods as env vars or volume mounts | Base64-only encoding, not encryption; visible to anyone with `get secret` permission in the namespace |
| **Env var from CI/CD** (GitHub Actions secret, GitLab CI variable) | Easy for CI pipelines; scoped to repo/environment | Lives in CI system's secret store; hard to rotate across many jobs |
| **HashiCorp Vault** | Open-source; k8s/AWS/GCP/OIDC auth methods; **dynamic secrets** (Vault generates a short-lived client secret on demand — the stored thing is an API policy, not a password); runs on-prem or as HCP Vault | Operational overhead to run |
| **AWS Secrets Manager** | Managed; native IAM access control; built-in rotation hooks | AWS-only; cost per secret |
| **GCP Secret Manager** | Managed; IAM via Workload Identity; versioned | GCP-only |
| **Azure Key Vault** | Managed; HSM-backed for keys; Managed Identity access | Azure-only |
| **Infisical / Doppler** | Developer-friendly SaaS vaults; k8s operator injection | Third-party dependency; SaaS trust model |

The standout is **Vault's dynamic secrets**: rather than storing a static client
secret, Vault's IdP secrets engine generates a fresh, short-lived credential each
time a service asks for one. The service holds nothing between calls; the long-lived
thing is the Vault policy, and the secret itself expires in minutes. This is the
closest you get to workload identity's "no stored secret" property while still using
Client Credentials.

#### How Vault trusts the service requesting secrets

Vault has pluggable **auth methods** — each answers "how does this caller prove who
it is?" Vault doesn't trust the service directly; it trusts an **external authority**
that vouches for the service's identity, then maps that identity to a policy. The
mechanism is the same check as `internal/server`'s `verifier.Verify` — just done by
Vault instead of your API.

**Kubernetes auth** (most common for k8s workloads). The pod presents its projected
service account JWT to Vault. Vault calls the Kubernetes **TokenReview API** to
validate it — the k8s API server is the authority, so there is no bootstrapping
secret. Vault checks the pod's service account and namespace against a configured
role and, on a match, issues a short-lived Vault token with the policies for that
role.

**JWT/OIDC auth** (for SPIFFE, GitHub Actions, etc.). If the workload already has
an OIDC token — a SPIFFE JWT-SVID, a GitHub Actions job token, a GCP service account
JWT — it presents that directly to Vault. Vault fetches the issuer's JWKS and
validates signature, issuer, audience, and expiry. It then maps claims (`sub`,
`namespace`, etc.) to a Vault role. This is identical to what `internal/server` does;
the only difference is the output is a Vault token instead of an authorized RPC call.

**AWS/GCP auth**. The instance calls a cloud-native "who am I?" API
(`sts:GetCallerIdentity` on AWS, the GCP metadata server for a signed identity
token) and forwards the signed proof to Vault. Vault verifies with the cloud
provider's API. The cloud platform's hardware root of trust is the authority —
nothing to bootstrap.

**AppRole** (fallback for simpler setups without a platform to vouch). Two pieces: a
`role_id` (not secret — can be baked into the image) and a `secret_id` (short-lived,
injected at deploy time by a Vault agent sidecar or CI step). Neither half is useful
alone. There is still a "secret zero" bootstrapping problem for the `secret_id`, but
the sidecar or CI system solves it in practice.

The k8s and JWT/OIDC methods are the clean ones: there is genuinely no secret to
bootstrap because the authority is cryptographic and held by the platform, not the
workload.

### On Okta specifically

In the real-world target, role accounts are **"service apps"**: applications with
the Client Credentials grant enabled, authenticating with either a client secret or
`private_key_jwt`. Two Okta-specific wrinkles, consistent with the lifetime/audience
notes elsewhere in this doc:

- Client Credentials generally requires a **custom authorization server** (API
  Access Management), not the org authorization server — the same prerequisite the
  audience and lifetime sections call out.
- The audience comes from the custom authorization server's configuration, not
  Dex's `audience:server:client_id:` cross-client scope; the `--audience`/`scope`
  the client requests selects it, and the server's expected-audience check is
  unchanged (see "Path to production").

### Authorization

Authentication is only half the story for a role account. Because the token's
identity is a **client id**, not a user `email`, any access decision keys off the
client (or its granted scopes), not a person. This experiment does no authorization
at all — any valid token is accepted (see "Authentication only, no authorization"
under Security considerations) — but a role account is the textbook case where you
*would* add one: e.g. require a specific scope, or allow only certain `sub`/`azp`
values. That is the natural next layer on top of this flow.

## Acting on behalf of another principal (admin-granted credentials)

A recurring question, adjacent to role accounts: can an admin **grant a token to another
principal** — especially a service/role account — and **install it into a file**? Yes,
but OAuth2 splits this into several mechanisms, and most of them deliberately avoid
putting a bare access token on disk. Access tokens are short-lived by design (10 minutes
here — see "Token management"), so the real question is *what long-lived artifact you
install, and what mints the short-lived tokens from it.*

| You want… | Mechanism | Artifact on disk |
| --- | --- | --- |
| Machine/role account, no human, no browser | **Client Credentials** (RFC 6749 §4.4) or `private_key_jwt` (RFC 7523) | client **secret** / private key |
| Admin acquires a token to **act as** a user | **Token Exchange** (RFC 8693) | none — minted at runtime by a trusted service |
| Durable on-disk credential that self-refreshes | **Refresh token** via `offline_access` | refresh token (inside `token.json`) |
| Ephemeral, single use (CI step) | bare access token | access token (expires fast) |

The reframings that matter:

- **Service account → install a *secret*, not a token.** The admin provisions a client in
  the IdP and hands over a `client_id` + `client_secret` (or registers a public key for
  `private_key_jwt`). The service mints its own short-lived access tokens on demand via
  the client-credentials grant; the file on disk holds the *secret*, and tokens stay
  ephemeral. This is exactly the flow in "Service / role accounts" above.

- **"Install a *token* into a file" is only correct for a *refresh* token.** If you truly
  want a durable on-disk credential that survives restarts and silently produces access
  tokens, that is a refresh token obtained with `offline_access` after one interactive
  consent — precisely what `internal/token` already persists (`0600`, silent refresh; see
  "Where tokens are stored"). A bare *access* token in a file is an anti-pattern: it
  expires in minutes and has no rotation story. Only an ephemeral CI step should do it.

- **Admin acting *as* another user → Token Exchange, done at runtime, not written to a
  file.** A privileged client presents its own token (and optionally the target's) to the
  token endpoint and receives a token scoped to the other principal. Two variants:
  - **Impersonation** — the issued token's `sub` *is* the target user. Our
    `internal/server` cannot tell it apart from that user logging in directly, so there is
    no record of who actually acted.
  - **Delegation** — the issued token keeps the target user as `sub` but adds an **`act`**
    (actor) claim naming the real caller, so a resource server can see "service S acting
    for user U." `internal/server` would accept such a token today (the extra claim
    doesn't affect signature/issuer/aud/expiry), but it would *record* the actor only if
    it additionally read the `act` claim — which it does not currently do.

### How Token Exchange works (RFC 8693)

User A calls the token endpoint with both tokens:

```
POST /token
grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&subject_token=<user B's access token>          # the resource being acted upon
&subject_token_type=urn:ietf:params:oauth:token-type:access_token
&actor_token=<user A's access token>            # who is doing the acting
&actor_token_type=urn:ietf:params:oauth:token-type:access_token
&audience=oidc-experiment-api
```

The IdP verifies both tokens, checks its policy, and returns a new token. Whether the
result carries `sub=B` alone (**impersonation** — A is invisible) or `sub=B` plus
`act={"sub":"A"}` (**delegation** — both identities visible) is a provider configuration
choice. Impersonation requires no changes to `internal/server`; delegation would
require it to additionally read the `act` claim for auditing or authorization.

**Pre-authorizing delegation with `may_act`.** User B's token can carry a `may_act`
claim — a JSON object identifying who is pre-authorized to act on their behalf:

```json
{ "may_act": { "sub": "user-A-id" } }
```

When user A presents the exchange, the IdP checks `may_act` to decide whether to grant
it. Without this claim (or an equivalent admin policy at the IdP), user A cannot
unilaterally claim permission to act for user B — the request is rejected. Consent
can also come from an interactive flow where user B explicitly approves the delegation.

**Provider support.** RFC 8693 is relatively recent (2020) and implementation quality
varies significantly:

| Provider | Token Exchange support |
| --- | --- |
| Keycloak | Strong: impersonation and delegation with `act`, configurable per-client policy |
| Zitadel | Partial (impersonation; `act` support varies by version) |
| Okta | Impersonation via token exchange; `act` claim requires additional configuration |
| Auth0 | Not supported natively |
| Dex | Advertises `token-exchange` in discovery but does not implement it; any exchange request returns `unsupported_grant_type` |

The wire-level Token Exchange request/response, and which providers can actually perform
it (Dex can run neither `client_credentials` nor an end-to-end exchange against the
bundled setup), are in **PROVIDERS.md** under "Token Exchange and machine-to-machine
grants."

## Token introspection and revocation

A question this experiment raises: once the server has validated a token, can it
know the token was **revoked** before it expired — for example because the user
logged out, was deactivated, or the token was stolen?

With our design the answer is *no*, and that's a deliberate trade-off. This
section explains why, and what the alternative (introspection) buys you.

### Local JWT validation vs. introspection

Our server does **local validation**: it holds the provider's public keys (JWKS)
and checks the JWT's signature, issuer, audience, and `exp` without ever calling
the provider per request. That's fast, scalable, and works offline — but it means
the token is valid until it expires, full stop. If the user logs out or is
deactivated, nothing the IdP does can stop that token until `exp`. The only lever
is keeping `exp` short (this experiment uses 10 minutes).

This is forced by the token *shape*:

- **JWT (self-contained) access tokens** — what Dex issues. All the claims live
  inside the signed token, so the resource server can validate locally. There is
  nothing to phone home about, so there is no revocation awareness.
- **Opaque (reference) access tokens** — just a random string, a handle. There
  are **no claims inside**, so the resource server cannot validate it locally; it
  has literally nothing to verify. It has no choice but to ask the IdP.

That "ask the IdP" call is **token introspection** (RFC 7662):

```
POST /introspect              (the resource server authenticates itself to the IdP)
token=<the token>
→  { "active": true, "sub": "...", "scope": "...", "exp": ..., "client_id": "...", "aud": ... }
```

The crucial part: the IdP checks **its own store**. If the token was revoked or
the session was logged out, it returns `{"active": false}` — so **revocation is
immediate**. That is the property local JWT validation cannot have.

### The trade-off

| | Local JWT validation (this experiment) | Opaque + introspection |
| --- | --- | --- |
| Per-request IdP call | No | Yes (unless cached) |
| Scales / works offline | Yes | Couples you to IdP availability |
| Revocation | Only via `exp` | Immediate |
| Token contents visible to resource server | Yes (decode the JWT) | Only what `/introspect` returns |

"Opaque-token systems *must* introspect" because there is no other option — there
are no claims to validate locally. As a side effect they get instant revocation
for free, paying with a network round-trip per request (usually softened by
caching the `active` result for a few seconds).

### Three things worth knowing

- **You can introspect JWTs too.** Dex and Okta both expose an introspection
  endpoint (you can see `introspection_endpoint` in Dex's discovery document). It
  is just usually pointless for JWTs — you would give up the speed that was the
  whole reason to use them.
- **The refresh token is the real revocation lever in our design.** Even with
  un-revocable JWT access tokens, revoking the *refresh token* at the IdP means
  the client can no longer mint a new access token — so access dies within one
  access-token lifetime (≤10 min here). Short access-token TTL + a revocable
  refresh token is the standard compromise, and it is exactly what this
  experiment implements (see "Token management" above).
- **Okta does both, depending on the authorization server.** Okta's *org*
  authorization server issues **opaque** access tokens (you must introspect or
  call `/userinfo` to learn anything about them); a *custom* authorization server
  issues **JWTs** you can validate locally, like we do with Dex.

### Other revocation strategies (for completeness)

If you need tighter revocation than "wait for `exp`" but don't want an IdP call on
every request, the common middle grounds are:

- **Short-lived JWTs** (our approach): accept a small revocation window in
  exchange for no per-request IdP calls. Most common for APIs.
- **Introspection with caching**: introspect, but cache the `active` result for a
  few seconds/minutes to amortize the cost — trading revocation latency for
  performance.
- **Revocation / "kill" lists**: push revoked token IDs (`jti`) to resource
  servers (often via a fast shared cache) so they can reject specific JWTs
  locally. Adds infrastructure.
- **Backchannel logout**: OIDC has a logout spec where the IdP notifies relying
  parties when a session ends.

### Why this experiment chose local validation

The experiment's goal is to demonstrate OIDC authentication end to end with a
fast, self-contained resource server. Local JWT validation against the provider's
JWKS gives exactly that, and pairing it with **short access-token lifetimes plus a
revocable refresh token** keeps the revocation window small without adding a
per-request dependency on the provider. Introspection would be the natural change
if the requirement shifted to *immediate* revocation, or if the provider were
configured to issue opaque tokens.

## Security considerations

A roundup of the security-relevant decisions made throughout this document, in
one place. The first table is what the design actively defends against; the
second is what is deliberately simplified and what production would add.

### What the design protects against

| Threat | How it's handled | See |
| --- | --- | --- |
| Forged or tampered tokens | Signature verified against the provider's JWKS | Server-side verification |
| Token from another issuer | `iss` must match the configured issuer | Server-side verification |
| Token minted for another party | `aud` must contain this server's API audience | Token audience |
| Expired / stale tokens | `exp` checked; short (10 min) lifetimes bound exposure | Token management |
| Anonymous access | Missing or unparseable token is rejected (`-32001`) | Server-side verification |
| Client-secret leakage | Public client + **PKCE** — no secret is shipped | The two login flows / Configuring the client |
| Auth-code interception / CSRF | PKCE verifier + random `state` on the auth-code flow | The two login flows |
| Token theft from disk | Token cache written `0600`, user-only | Token management |
| Idle-connection resource exhaustion | Per-connection read deadline (`ReadTimeout`, 5 s) | Server-side verification |
| Tokens sniffed/replayed on the wire | TLS recommended off-loopback (here: loopback only) | Transport security (TLS) |

### Deliberate simplifications (and production hardening)

- **Plain TCP, no TLS.** Acceptable only because everything is on loopback. A real
  deployment puts the server behind TLS and points the client at `https://` — see
  Transport security (TLS).
- **No revocation before expiry.** Local JWT validation can't detect a token
  revoked mid-lifetime. Mitigated by short access tokens plus a revocable refresh
  token; use introspection if *immediate* revocation is required — see Token
  introspection and revocation.
- **Audience doesn't separate access from ID tokens.** Dex stamps the same `aud`
  on both, so audience alone won't reject an ID token presented as an access
  token. A fuller solution checks a token-type marker or introspects — see Token
  audience.
- **Token cache is a plaintext file.** Fine for a single-user host; the production
  upgrade is the OS keychain (a drop-in replacement for the `Store` type) — see
  Token management.
- **Authentication only, no authorization.** Any valid user is allowed; there is
  no scope/role/permission check. Adding one (e.g. requiring a scope claim) is the
  natural next layer.
- **ROPC (password grant) intentionally unused.** Deprecated and first-party-only
  — see CLI login: terminal vs. browser.
- **Role-account secret is a static, in-repo client secret.** Fine for the
  experiment; production uses a vault, `private_key_jwt`, or secretless workload
  identity federation — see Service / role accounts.
- **No rate limiting** beyond the read deadline, and **one request per
  connection**; a real service would add connection/request limits and graceful
  shutdown.

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
