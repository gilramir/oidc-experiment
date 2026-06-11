# OIDC Providers

Dex stands in for a real provider in this experiment, but it is only one of many
open-source OIDC providers. Because the client and server only know the **issuer URL**
and the **client/audience IDs**, any spec-compliant OIDC provider is a drop-in
replacement — the LDAP backend (and everything else about how the provider authenticates
humans) is entirely the provider's internal concern, invisible to our code.

The one thing that is *not* portable is the mechanism for stamping
`aud = oidc-experiment-api` onto the access token. Dex does it with the cross-client
scope `audience:server:client_id:oidc-experiment-api` (see `crossClientScopePrefix` in
`cmd/client/main.go`); every other provider has its own way. Sketches for three of them
are at the bottom.

## Where Dex sits

Dex is a deliberately **lightweight, stateless OIDC front-end**: a small Go binary that
federates to an upstream identity source (LDAP, SAML, GitHub, static passwords, …) and
speaks OIDC to downstream apps. It is *not* a full identity-management product — it has
no real user database of its own, no self-service UI, no MFA/policy engine. That
minimalism is exactly why it suits this experiment, and it frames the comparison below:
most alternatives are heavier because they do more.

| Provider   | Lang        | Weight     | LDAP support                          | Notes vs. Dex |
|------------|-------------|------------|---------------------------------------|---------------|
| **Dex**    | Go          | Tiny       | Federation connector                  | Baseline: stateless front-end, no user store, no UI/MFA. |
| **Keycloak** | Java (JVM) | Heavy     | User Federation (sync + write-back)   | Do-everything: admin UI, MFA, fine-grained authz, token mappers. Bigger ops footprint. |
| **Authentik** | Python+Go | Medium    | LDAP *source* (inbound) + LDAP outpost (outbound) | Modern UI, flexible flow/policy engine. More product than Dex, lighter than Keycloak. |
| **Zitadel** | Go         | Medium     | LDAP as external IdP                   | Closest "Dex but fuller" in Go: multi-tenant, orgs, audit, OIDC-certified. |
| **Authelia** | Go        | Light      | First-class LDAP/AD backend            | Nearest to Dex's small-Go-binary model. OIDC provider support is newer/less complete; historically a forward-auth portal. |
| **Casdoor** | Go         | Light-Med  | LDAP sync                              | UI-centric, growing community. |
| **WSO2 IS / Apereo CAS / Gluu** | Java | Heavy | Mature LDAP                          | Enterprise-integration oriented; heaviest of the set. |
| **Ory Hydra** | Go       | Light core | **None out of the box**                | Headless OAuth2/OIDC, no user store or login UI. Bring your own IdP (e.g. Ory Kratos) and wire LDAP there. Max scalability, most assembly. |

### Quick steer

| If you want…                              | Pick            |
|-------------------------------------------|-----------------|
| Closest to "Dex but more featureful," Go  | **Zitadel** or **Authelia** |
| Industry-standard, do-everything          | **Keycloak**    |
| Modern UI + flexible flows                | **Authentik**   |
| Max scalability, willing to assemble      | **Ory Hydra** + Kratos |

## Audience mapping per provider

In this experiment the resource server (`internal/server`) requires
`aud = oidc-experiment-api`. The CLI must convince the provider to mint an access token
carrying that audience even though the CLI's own client id is `oidc-experiment-cli`.
Here is how that piece looks in three of the alternatives.

### Keycloak

Keycloak attaches audiences with an **Audience protocol mapper** on a **client scope**.

1. Create a client scope, e.g. `oidc-experiment-api`, and add a mapper of type
   **Audience**:
   - *Included Client Audience*: `oidc-experiment-api` (or *Included Custom Audience*
     if you don't model the API as a client).
   - *Add to access token*: ON.
2. Register the API as a client (`oidc-experiment-api`) — typically **bearer-only**,
   since it never runs a login flow.
3. Attach the client scope to the CLI client (`oidc-experiment-cli`) as either a
   *default* scope (always added) or an *optional* scope (added when the CLI requests
   `scope=oidc-experiment-api`).

```
CLI requests:   scope=openid oidc-experiment-api
Token claim:    "aud": "oidc-experiment-api"
```

The CLI change is just adding the scope name `oidc-experiment-api` to the scope list —
no Dex-style `audience:server:client_id:` prefix.

### Authentik

Authentik shapes tokens with **property mappings** (Scope Mappings) bound to the
provider.

1. Create a **Scope Mapping** that injects the audience. Authentik exposes claims via a
   small Python expression:

   ```python
   return {"aud": "oidc-experiment-api"}
   ```

   (Or return a list if the token should carry multiple audiences.)
2. Add that scope mapping to the OAuth2/OIDC **provider** backing the CLI application,
   under its *Selected Scopes*.
3. The CLI requests the corresponding scope name; Authentik evaluates the mapping and
   stamps `aud` onto the issued token.

Authentik can also set the audience implicitly when you model the API as a separate
application/provider and use its audience settings, but the explicit property-mapping
route above is the most direct analogue to what Dex does.

### Authelia

Authelia configures OIDC clients statically in `configuration.yml`. The audience is
controlled by the **`audience`** list on the client, combined with how it grants
requested audiences.

```yaml
identity_providers:
  oidc:
    clients:
      - client_id: oidc-experiment-cli
        public: true                      # PKCE, no secret — matches our CLI
        redirect_uris:
          - http://127.0.0.1:5555/callback
        scopes:
          - openid
          - offline_access
        audience:
          - oidc-experiment-api           # allowed/!default audience for this client
        # Authelia issues the audience when the client requests it via the
        # `resource` / `audience` parameter (RFC 8707), or includes configured
        # audiences per its audience-granting policy.
        grant_types:
          - authorization_code
          - refresh_token
```

The CLI asks for the audience using the standard **RFC 8707 `resource`** parameter
(`resource=oidc-experiment-api`) rather than Dex's cross-client scope. The server side
is unchanged: it still just checks `aud == oidc-experiment-api`.

> Note: Authelia's OIDC provider support is newer than its forward-auth core; confirm
> the exact `audience` / RFC 8707 semantics against the version you deploy.

## Token Exchange and machine-to-machine grants

DESIGN.md ("Acting on behalf of another principal" and "Service / role accounts") covers
*what credential an admin installs* for service and delegated access — the conceptual
split between a secret, a refresh token, and a bare access token. Which of those grants a
given provider can actually perform is the provider-specific part, recorded here.

Two grants matter beyond the interactive human flows:

- **Client Credentials** (RFC 6749 §4.4) — the machine/role-account grant; the client
  authenticates as itself, no user. (Used by `internal/auth/clientcreds.go`.)
- **Token Exchange** (RFC 8693) — the "act on behalf of another principal" grant; a
  trusted service trades one token for another scoped to a different subject/audience. It
  is also the foundation of secretless workload-identity federation.

| Provider | `client_credentials` | Token Exchange (RFC 8693) |
|----------|----------------------|---------------------------|
| **Dex** | No (grant set is hard-coded) | Grant implemented, but a working demo needs an upstream connector to validate the subject token — the bundled static-password setup has none |
| **Keycloak** | Yes | Yes (standard + legacy variants; per-client *token-exchange* permission) |
| **Okta** | Yes (service apps, custom auth server) | Yes (via a custom authorization-server policy) |
| **Zitadel** | Yes | Yes |
| **Authentik** | Yes | Partial / evolving |
| **Auth0** | Yes (M2M apps) | Yes (custom token exchange) |
| **Ory Hydra** | Yes | Yes |

So against the bundled Dex neither grant runs end to end: `client_credentials` returns
`unsupported_grant_type`, and token exchange has no upstream subject token to exchange
*from*. Both are correct against a provider in the table above; switching is the usual
config swap (issuer + client id + secret).

### Token Exchange (RFC 8693) flow sketch

The scenario: a privileged service (an admin tool, an API gateway, a job runner) holds
its own token and wants a token that lets it act **as** — or **on behalf of** — another
principal. RFC 8693 defines this as a grant on the token endpoint.

```
POST /token
grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&subject_token=<token identifying the principal to act as>          (required)
&subject_token_type=urn:ietf:params:oauth:token-type:access_token   (or id_token, jwt, …)
&actor_token=<the admin/service's own token>                        (optional; required for delegation)
&actor_token_type=urn:ietf:params:oauth:token-type:access_token
&audience=oidc-experiment-api          (who the new token is for — our resource server)
&scope=openid                          (requested scopes, may be narrowed)
&requested_token_type=urn:ietf:params:oauth:token-type:access_token
```

Two semantically different results, distinguished by whether `actor_token` is sent (the
impersonation-vs-delegation distinction — see DESIGN.md):

- **Impersonation** — no `actor_token`. The returned token's `sub` *is* the target user.
- **Delegation** — `actor_token` present. The token keeps the target user as `sub` but
  adds an **`act`** (actor) claim naming the real caller:

  ```json
  { "aud": "oidc-experiment-api", "sub": "alice@example.com",
    "act": { "sub": "admin-tool@example.com" } }
  ```

The endpoint responds with a normal token payload (note `issued_token_type`):

```json
{
  "access_token": "eyJ…",
  "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
  "token_type": "Bearer",
  "expires_in": 600
}
```

How this would land in *this* codebase (against a provider that supports it):

- A new flow next to the others — `internal/auth/exchange.go` returning the same
  `*oauth2.Token` the other flows do — so everything downstream (the token store, the
  server's verifier) is unchanged. The grant isn't in `golang.org/x/oauth2`, so it'd be a
  manual POST to the token endpoint (like `clientcreds.go` builds its own config), setting
  the form fields above.
- The privileged client must be authorized in the IdP to perform exchange (Keycloak:
  *token-exchange* permission on the target client; Okta: a custom auth-server policy).
- The resulting token carries `aud = oidc-experiment-api` via the same audience-mapping
  mechanism described above — token exchange sets it through the `audience` request
  parameter rather than a scope.
- For an **`act`**-aware server, `internal/server` would additionally read the `act` claim
  to log/authorize the actor; today it checks only signature/issuer/aud/expiry, so a
  delegation token still verifies but the actor goes unrecorded.

## Bottom line

Switching providers in this experiment is a **config swap, not a code change**, with one
caveat: the audience-injection mechanism is provider-specific. Everything downstream of
the issued token (verification of signature, issuer, audience, expiry in
`internal/server`) is identical regardless of which provider minted it.
