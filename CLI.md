# CLI login: terminal vs. browser

A common question for a CLI like this one: **can the user just type their username
and password at the command line, or must they use a browser?**

Short answer: there *is* a no-browser path where the user types credentials right
at the terminal — but it's a different OAuth grant, and it only works for plain
password accounts. Once real-world authentication is involved (MFA, SSO,
federated/social login, passkeys), a browser becomes effectively mandatory,
because the identity provider — not the CLI — owns the login ceremony.

This experiment ships two browser-delegating flows (`--auth=authcode` and
`--auth=device`, see [DESIGN.md](DESIGN.md)). This document records the
terminal-only alternatives and why we don't use them by default.

## Option A — Resource Owner Password Credentials (ROPC), the "password" grant

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

## Option B — Okta Authentication API (interactive CLI, no browser, incl. MFA)

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

## The fundamental constraint

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

## Decision for this experiment

We use the browser-delegating flows (`--auth=authcode`, `--auth=device`) because
they reflect how a real CLI authenticates against Okta and survive MFA/SSO.

Since our Dex setup uses a local `passwordDB`, **Option A (ROPC) would also work**
and is a legitimate thing to demo — it cleanly contrasts "trusted first-party CLI
takes the password" against "delegate to the browser." If added, it should be
exposed as `--auth=password` and clearly labelled deprecated / first-party-only,
so the experiment documents *why* it's normally avoided. It is intentionally not
implemented today.
