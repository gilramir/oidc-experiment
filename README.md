# oidc-experiment

A tiny JSON-RPC client/server pair in Go that uses OIDC for authentication. The
client logs in via an OIDC provider (Dex locally; Okta in the real world),
obtains an access token, and sends it with each request. The server verifies the
token and serves only authenticated users.

See **[DESIGN.md](DESIGN.md)** for the full design — token storage and refresh,
real-world lifetimes, configuring the client and server,
[terminal vs. browser login](DESIGN.md#cli-login-terminal-vs-browser), and
[token introspection & revocation](DESIGN.md#token-introspection-and-revocation).
See **[PROVIDERS.md](PROVIDERS.md)** for production-grade OIDC providers with LDAP
backends (Keycloak, Authentik, Authelia, …), how they compare to Dex, and how to
stamp the resource server's audience onto tokens in each.

## Layout

```
cmd/server      thin main: flags + listen loop
cmd/client      CLI: logs in, caches tokens, calls a method
internal/server JSON-RPC-over-TCP service; verifies access tokens
internal/rpc    shared request/response types
internal/token  on-disk token store + auto-refreshing token source
internal/auth   OIDC provider setup + the two login flows
internal/e2e    end-to-end test (launches Dex, drives both flows)
dex/config.yaml Dex provider configuration (static passwords, default)
dex/config-ldap.yaml  Dex configuration template for an LDAP backend
scripts/run-dex.sh    launch Dex with either config
```

## Prerequisites

- Go 1.25+
- Dex (the OIDC provider), built from source.

  Note: `go install github.com/dexidp/dex/cmd/dex@latest` does **not** work — Dex
  uses legacy `v2.x` `+incompatible` tags, so `@latest` resolves to an ancient
  release. Build a recent tag from a checkout instead:

  ```sh
  git clone --depth 1 --branch v2.45.1 https://github.com/dexidp/dex.git
  cd dex
  go build -o "$(go env GOPATH)/bin/dex" ./cmd/dex   # installs to ~/go/bin/dex
  cd -
  ```

  (Docker also works if you prefer:
  `docker run -p 5556:5556 -v "$PWD/dex:/etc/dex" ghcr.io/dexidp/dex:latest dex serve /etc/dex/config.yaml`)

## Run it

Use three terminals.

**1. Start Dex** (the OIDC provider):

```sh
./scripts/run-dex.sh          # static passwords (default); same as: dex serve dex/config.yaml
# or the docker command above
```

To authenticate against a real LDAP/AD directory instead, fill in
`dex/config-ldap.yaml` (placeholders are documented inline) and start Dex with
`./scripts/run-dex.sh ldap`. The client and server are unchanged — only the Dex
backend differs. See [DESIGN.md](DESIGN.md#authentication-backends-dex-connectors).

**2. Start the server:**

```sh
go run ./cmd/server
# listening on :8888 (issuer http://127.0.0.1:5556/dex)
```

**3. Run the client.** Log in with **alice@example.com** / **password**.

Authorization Code + PKCE (opens a browser):

```sh
go run ./cmd/client time
```

Device Authorization Grant (prints a URL + code):

```sh
go run ./cmd/client --auth=device time
```

Expected output:

```json
{
  "time": "2026-06-09T14:22:01Z",
  "user": "alice@example.com"
}
```

The first run logs you in and caches tokens at
`~/.config/oidc-experiment/token.json`. Subsequent runs reuse the cached token
and refresh it silently when it expires (10 min in this config).

Two methods are available: `time` (above) and `token`, which echoes back the
verified claims the server read from your token — handy for confirming auth works
and seeing exactly what's inside (`sub`, `email`, `name`, `groups`, …):

```sh
go run ./cmd/client token
```

## Useful flags

```sh
go run ./cmd/client --login  time     # force a fresh interactive login
go run ./cmd/client --logout          # delete the cached token
go run ./cmd/client --auth=device time
go run ./cmd/client token             # dump the verified token claims
go run ./cmd/server  --port 9000 --issuer http://127.0.0.1:5556/dex
```

## Tests

```sh
go test ./...          # server unit tests + the Dex end-to-end test
go test ./... -short   # unit tests only (skips anything that launches Dex)
```

Two layers:

- **`internal/server`** unit tests validate the token-checking logic against a
  mock OIDC issuer, so they can mint tokens a real provider never would —
  expired, wrong-audience, wrong-issuer, bad-signature — and assert each is
  rejected (plus the happy path and the read-deadline on idle connections).
  Fast, no external dependencies, run under `-short`.
- **`internal/e2e`** launches a real Dex on random ports, runs the server
  in-process, and drives **both** login flows headlessly (a small "robot
  browser" submits Dex's login form), then checks token caching, silent refresh,
  and the anonymous/invalid-token rejection paths. Skipped automatically if the
  `dex` binary isn't found on `PATH` or in `~/go/bin`, or under `-short`.

## Things to try

- Run `time` twice within 10 min: the second run reuses the cached token (no
  browser). Wait past 10 min and run again: the token refreshes silently.
- Edit `token.json` to corrupt the access token, then run `time`: the server
  rejects it with `unauthorized`.
- `--logout`, then run `time`: a full login is required again.
