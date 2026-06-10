package auth

import (
	"context"
	"fmt"

	"golang.org/x/oauth2"
)

// Device runs the Device Authorization Grant (RFC 8628). It is meant for clients
// that cannot pop a browser on the same machine (headless boxes, SSH sessions):
//
//  1. Ask the provider for a device code and user code.
//  2. Hand the response to present so the user can be told which URL to visit
//     and which code to enter (the CLI prints it; a test can drive it).
//  3. Poll the token endpoint until the user finishes logging in.
//
// No loopback server and no PKCE are involved.
func Device(ctx context.Context, cfg *oauth2.Config, present func(*oauth2.DeviceAuthResponse)) (*oauth2.Token, error) {
	if cfg.Endpoint.DeviceAuthURL == "" {
		return nil, fmt.Errorf("provider does not advertise a device authorization endpoint")
	}

	resp, err := cfg.DeviceAuth(ctx)
	if err != nil {
		return nil, fmt.Errorf("start device authorization: %w", err)
	}

	present(resp)

	// DeviceAccessToken blocks, polling at the interval the provider specified,
	// until the user approves, the code expires, or ctx is cancelled.
	tok, err := cfg.DeviceAccessToken(ctx, resp)
	if err != nil {
		return nil, fmt.Errorf("device token exchange: %w", err)
	}
	return tok, nil
}
