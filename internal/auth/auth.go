// Package auth holds the OIDC provider configuration and the two interactive
// login flows: Authorization Code + PKCE, and the Device Authorization Grant.
// Both return an *oauth2.Token; everything downstream (storage, refresh, the
// RPC call) is identical regardless of which flow produced the token.
package auth

import (
	"context"
	"fmt"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// Config describes how to reach the OIDC provider (Dex in this experiment, Okta
// in the real world) and which client we are.
type Config struct {
	Issuer      string   // e.g. http://127.0.0.1:5556/dex
	ClientID    string   // registered (public) client id
	RedirectURL string   // loopback redirect for the auth-code flow
	Scopes      []string // must include "offline_access" to get a refresh token
}

// Provider discovers the OIDC endpoints and builds the oauth2 config. The
// returned *oidc.Provider is also used by the server to verify tokens, but here
// the client only needs its endpoints.
func (c Config) Provider(ctx context.Context) (*oidc.Provider, *oauth2.Config, error) {
	provider, err := oidc.NewProvider(ctx, c.Issuer)
	if err != nil {
		return nil, nil, fmt.Errorf("discover issuer %q: %w", c.Issuer, err)
	}

	endpoint := provider.Endpoint()
	// go-oidc only fills AuthURL and TokenURL. The device endpoint lives in the
	// discovery document under a non-standard-to-go field, so pull it manually.
	var extra struct {
		DeviceAuthURL string `json:"device_authorization_endpoint"`
	}
	if err := provider.Claims(&extra); err == nil {
		endpoint.DeviceAuthURL = extra.DeviceAuthURL
	}

	oauthCfg := &oauth2.Config{
		ClientID:    c.ClientID,
		Endpoint:    endpoint,
		RedirectURL: c.RedirectURL,
		Scopes:      c.Scopes,
	}
	return provider, oauthCfg, nil
}
