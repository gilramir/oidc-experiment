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

## Bottom line

Switching providers in this experiment is a **config swap, not a code change**, with one
caveat: the audience-injection mechanism is provider-specific. Everything downstream of
the issued token (verification of signature, issuer, audience, expiry in
`internal/server`) is identical regardless of which provider minted it.
