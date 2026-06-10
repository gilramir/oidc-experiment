package auth

import (
	"context"
	"fmt"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

// ClientCredentials runs the OAuth2 Client Credentials grant (RFC 6749 §4.4):
// the *application itself* is the principal, so there is no user, no browser,
// and no refresh token. This is the flow for "role"/service accounts used by
// automation (CI jobs, cron, daemons) — see DESIGN.md "Service / role accounts".
//
// It differs from the two interactive flows in two ways that matter downstream:
//
//   - The client authenticates with its own secret (a *confidential* client),
//     where the CLI's human flows are public + PKCE and ship no secret.
//   - The returned token carries no id_token and no refresh token. There is no
//     human identity to assert (the token's sub is the client itself), and a
//     refresh token is pointless when re-minting is a cheap, stateless POST.
//
// Because there is nothing to refresh and nothing user-specific to cache, the
// caller does not persist this token (contrast the interactive flows, which save
// to token.json for silent refresh across runs): it just asks for a new one.
func ClientCredentials(ctx context.Context, tokenURL, clientID, clientSecret string, scopes []string) (*oauth2.Token, error) {
	if clientSecret == "" {
		return nil, fmt.Errorf("client credentials grant requires a client secret (set OIDC_CLIENT_SECRET)")
	}
	cfg := clientcredentials.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		TokenURL:     tokenURL,
		Scopes:       scopes,
	}
	tok, err := cfg.Token(ctx)
	if err != nil {
		return nil, fmt.Errorf("client credentials token request: %w", err)
	}
	return tok, nil
}
