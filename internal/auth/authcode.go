package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/url"

	"golang.org/x/oauth2"
)

// AuthCode runs the Authorization Code flow with PKCE for a native/CLI client:
//
//  1. Start a throwaway HTTP server on the loopback redirect URL.
//  2. Hand the provider's authorization URL to present (the CLI opens a browser;
//     a test can drive it programmatically), carrying a PKCE challenge and a
//     random state value.
//  3. The user logs in at the provider; the browser is redirected back to our
//     loopback server with an authorization code.
//  4. Exchange the code (plus the PKCE verifier) for tokens.
//
// PKCE means no client secret is needed, which is exactly right for a binary
// distributed to users.
func AuthCode(ctx context.Context, cfg *oauth2.Config, present func(authURL string)) (*oauth2.Token, error) {
	u, err := url.Parse(cfg.RedirectURL)
	if err != nil {
		return nil, fmt.Errorf("parse redirect url: %w", err)
	}

	ln, err := net.Listen("tcp", u.Host)
	if err != nil {
		return nil, fmt.Errorf("listen on %s for redirect: %w", u.Host, err)
	}
	defer ln.Close()

	state := randomString()
	verifier := oauth2.GenerateVerifier()

	type result struct {
		code string
		err  error
	}
	resultCh := make(chan result, 1)

	mux := http.NewServeMux()
	mux.HandleFunc(u.Path, func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if e := q.Get("error"); e != "" {
			http.Error(w, "login failed: "+e, http.StatusBadRequest)
			resultCh <- result{err: fmt.Errorf("provider returned error: %s", e)}
			return
		}
		if q.Get("state") != state {
			http.Error(w, "state mismatch", http.StatusBadRequest)
			resultCh <- result{err: fmt.Errorf("state mismatch (possible CSRF)")}
			return
		}
		fmt.Fprintln(w, "Login complete. You can close this tab and return to the terminal.")
		resultCh <- result{code: q.Get("code")}
	})

	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	defer srv.Close()

	authURL := cfg.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier))
	present(authURL)

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case res := <-resultCh:
		if res.err != nil {
			return nil, res.err
		}
		return cfg.Exchange(ctx, res.code, oauth2.VerifierOption(verifier))
	}
}

func randomString() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
