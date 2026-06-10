# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A minimal experiment in OIDC authentication: a Go JSON-RPC client/server pair where
the client logs in via an OIDC provider, obtains an OAuth2 access token, and sends it
with each RPC. The server verifies the token and serves only authenticated users.
Dex stands in for a real provider (Okta in the real world) — the client and server
only know the issuer URL and client/audience ids, so switching providers is a config
swap, not a code change.

**[DESIGN.md](DESIGN.md)** is the canonical design doc (token storage/refresh,
lifetimes, terminal-vs-browser login, introspection/revocation). Keep it in sync when
changing behavior it describes.

**[PROVIDERS.md](PROVIDERS.md)** surveys production OIDC providers with LDAP backends
(Keycloak, Authentik, Authelia, Zitadel, Ory Hydra, …), compares them to Dex, and
sketches the provider-specific audience-mapping mechanism for getting
`aud=oidc-experiment-api` onto the access token.

## Commands

```sh
go run ./cmd/server                       # listen on :8888, issuer = local Dex
go run ./cmd/client time                  # auth-code + PKCE login (opens browser)
go run ./cmd/client --auth=device time    # device grant (prints URL + code)
go run ./cmd/client --login time          # force a fresh interactive login
go run ./cmd/client --logout              # delete cached token

go test ./...                             # unit tests + Dex e2e test
go test ./... -short                      # unit tests only (skips Dex e2e)
go test ./internal/server -run TestName   # a single test
go vet ./... && go fmt ./...
```

Running anything end-to-end requires **Dex** (the OIDC provider) on `PATH` or in
`~/go/bin`. `go install ...dex@latest` does NOT work (Dex uses `+incompatible` v2 tags);
build a tagged checkout instead — see README.md "Prerequisites". Start it with
`./scripts/run-dex.sh` (static passwords; add `ldap` to use the
`dex/config-ldap.yaml` LDAP-backend template). Test login:
**alice@example.com** / **password**.

The e2e test (`internal/e2e`) launches a real Dex on random ports, runs the server
in-process, and drives both login flows with a headless "robot browser" that submits
Dex's login form. It auto-skips when the `dex` binary is absent or under `-short`.

## Architecture

The token is the spine of the whole system; trace it through these packages:

- **`internal/auth`** — OIDC discovery (`auth.go`) plus the two interactive login
  flows, each returning an `*oauth2.Token`: `authcode.go` (Authorization Code + PKCE,
  via a throwaway loopback HTTP server) and `device.go` (Device Authorization Grant,
  polling). Everything downstream is identical regardless of which flow ran.
- **`internal/token`** — on-disk token store (`~/.config/oidc-experiment/token.json`,
  mode 0600) and a `TokenSource` that wraps oauth2's auto-refreshing source so any
  refreshed token is written back to disk. The on-disk struct is custom (not a marshalled
  `oauth2.Token`) specifically so the `id_token` — which lives in the token's untyped
  `Extra` map — survives a save.
- **`internal/server`** — JSON-RPC-over-TCP service. Builds an `oidc.IDTokenVerifier`
  once and reuses it; each request's token is checked for signature (against the JWKS),
  issuer, audience, and expiry before any method runs. Empty/invalid token → `unauthorized`.
- **`internal/rpc`** — shared `Request`/`Response` types. The `Token` field is this
  experiment's non-standard extension to JSON-RPC; it carries the access token.
- **`cmd/client`**, **`cmd/server`** — thin mains (flag parsing + wiring).

### The audience subtlety (most likely thing to trip you up)

The access token must carry `aud = oidc-experiment-api` (the resource server), NOT the
CLI's own client id. The CLI requests this via the Dex-specific cross-client scope
`audience:server:client_id:oidc-experiment-api` (see `crossClientScopePrefix` in
`cmd/client/main.go`). Dex only honors it because `dex/config.yaml` registers the
`oidc-experiment-api` client with the CLI listed as a `trustedPeer`. The server's
`oidc.Config.ClientID` field is reused by go-oidc to mean "the audience I require" —
it is the API's id, not the CLI's. Changing the audience requires edits in all three
places: client scope, Dex config, server's expected audience.

`dex/config.yaml`: in-memory storage (nothing persists across restarts), short
`idTokens: 10m` expiry deliberately set so the silent-refresh path gets exercised, and
a single public (no-secret) PKCE client used by both flows.
