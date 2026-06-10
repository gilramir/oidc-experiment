# Token introspection and revocation

A question this experiment raises: once the server has validated a token, can it
know the token was **revoked** before it expired — for example because the user
logged out, was deactivated, or the token was stolen?

With our design the answer is *no*, and that's a deliberate trade-off. This
document explains why, and what the alternative (introspection) buys you.

## Local JWT validation vs. introspection

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

## The trade-off

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

## Three things worth knowing

- **You can introspect JWTs too.** Dex and Okta both expose an introspection
  endpoint (you can see `introspection_endpoint` in Dex's discovery document). It
  is just usually pointless for JWTs — you would give up the speed that was the
  whole reason to use them.
- **The refresh token is the real revocation lever in our design.** Even with
  un-revocable JWT access tokens, revoking the *refresh token* at the IdP means
  the client can no longer mint a new access token — so access dies within one
  access-token lifetime (≤10 min here). Short access-token TTL + a revocable
  refresh token is the standard compromise, and it is exactly what this
  experiment implements (see [DESIGN.md](DESIGN.md) on token management).
- **Okta does both, depending on the authorization server.** Okta's *org*
  authorization server issues **opaque** access tokens (you must introspect or
  call `/userinfo` to learn anything about them); a *custom* authorization server
  issues **JWTs** you can validate locally, like we do with Dex.

## Other revocation strategies (for completeness)

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

## Why this experiment chose local validation

The experiment's goal is to demonstrate OIDC authentication end to end with a
fast, self-contained resource server. Local JWT validation against the provider's
JWKS gives exactly that, and pairing it with **short access-token lifetimes plus a
revocable refresh token** keeps the revocation window small without adding a
per-request dependency on the provider. Introspection would be the natural change
if the requirement shifted to *immediate* revocation, or if the provider were
configured to issue opaque tokens.
