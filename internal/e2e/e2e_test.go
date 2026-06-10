// Package e2e contains an end-to-end test that launches a real Dex provider,
// runs the JSON-RPC server in-process, and drives both login flows the way the
// CLI does — then exercises token caching/refresh and the rejection paths.
//
// The Dex login pages normally need a human in a browser. A small "robot
// browser" (an http.Client with a cookie jar) submits the login form instead,
// and the provider's redirect drives the rest of the flow exactly as a real
// browser would.
//
// The test is skipped when the `dex` binary is not available or when running
// with `-short`.
package e2e

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gilramir/oidc-experiment/internal/auth"
	"github.com/gilramir/oidc-experiment/internal/rpc"
	"github.com/gilramir/oidc-experiment/internal/server"
	"github.com/gilramir/oidc-experiment/internal/token"
	"golang.org/x/oauth2"
)

const (
	clientID    = "oidc-experiment-cli"
	apiAudience = "oidc-experiment-api"
	testUser    = "alice@example.com"
	testPass    = "password"
	// bcrypt hash of testPass; matches dex/config.yaml.
	testHash = `$2a$10$351Qx.P/23Bb5lXu2MwhB.7YhfDzf2OPIW3kZurT34OZODmmArYk.`
)

func TestEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test (launches Dex); skipped under -short")
	}
	dexBin := findDex()
	if dexBin == "" {
		t.Skip("dex binary not found in PATH or ~/go/bin; skipping integration test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	dexPort := freePort(t)
	redirectPort := freePort(t)
	issuer := fmt.Sprintf("http://127.0.0.1:%d/dex", dexPort)
	redirectURL := fmt.Sprintf("http://127.0.0.1:%d/callback", redirectPort)

	startDex(ctx, t, dexBin, dexPort, redirectPort)

	// Build the OIDC client config (issuer + endpoints), as the CLI does.
	cfg := auth.Config{
		Issuer:      issuer,
		ClientID:    clientID,
		RedirectURL: redirectURL,
		Scopes: []string{
			oidc.ScopeOpenID, "profile", "email", oidc.ScopeOfflineAccess,
			"audience:server:client_id:" + apiAudience, // mint the token for the API
		},
	}
	_, oauthCfg, err := cfg.Provider(ctx)
	if err != nil {
		t.Fatalf("build provider: %v", err)
	}

	// Run the JSON-RPC server in-process on a random port. It requires the API
	// audience, so it only accepts tokens explicitly minted for it.
	srv, err := server.New(ctx, issuer, apiAudience)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go srv.Serve(ln)
	serverAddr := ln.Addr().String()

	// latestToken holds the token from the most recent successful login. The
	// refresh subtest uses it because Dex keeps a single offline session per
	// (user, client): a later login rotates and invalidates earlier refresh
	// tokens, so only the newest one is still refreshable.
	var latestToken *oauth2.Token

	t.Run("AuthorizationCodePKCE", func(t *testing.T) {
		robotErr := make(chan error, 1)
		tok, err := auth.AuthCode(ctx, oauthCfg, func(authURL string) {
			go func() { robotErr <- robotLogin(authURL) }()
		})
		if err != nil {
			t.Fatalf("AuthCode: %v", err)
		}
		if err := <-robotErr; err != nil {
			t.Fatalf("robot login: %v", err)
		}
		latestToken = tok

		// The access token must be minted for the resource server, not the CLI.
		assertAudienceContains(t, tok.AccessToken, apiAudience)

		resp := callRPC(t, serverAddr, "time", tok.AccessToken)
		assertUser(t, resp, testUser)
	})

	t.Run("DeviceFlow", func(t *testing.T) {
		robotErr := make(chan error, 1)
		tok, err := auth.Device(ctx, oauthCfg, func(r *oauth2.DeviceAuthResponse) {
			go func() { robotErr <- robotDevice(r.VerificationURIComplete) }()
		})
		if err != nil {
			t.Fatalf("Device: %v", err)
		}
		if err := <-robotErr; err != nil {
			t.Fatalf("robot device approval: %v", err)
		}
		latestToken = tok

		resp := callRPC(t, serverAddr, "time", tok.AccessToken)
		assertUser(t, resp, testUser)
	})

	t.Run("AnonymousRejected", func(t *testing.T) {
		resp := callRPC(t, serverAddr, "time", "")
		assertUnauthorized(t, resp)
	})

	t.Run("InvalidTokenRejected", func(t *testing.T) {
		resp := callRPC(t, serverAddr, "time", "not.a.valid.jwt")
		assertUnauthorized(t, resp)
	})

	t.Run("SilentRefreshPersisted", func(t *testing.T) {
		if latestToken == nil || latestToken.RefreshToken == "" {
			t.Skip("no refresh token from the login subtests")
		}
		store := token.NewStoreAt(filepath.Join(t.TempDir(), "token.json"))
		if err := store.Save(latestToken); err != nil {
			t.Fatalf("save: %v", err)
		}

		// Pretend the cached access token has expired; the refresh token is
		// still good. The persisting source should refresh and re-save.
		stale := *latestToken
		stale.Expiry = time.Now().Add(-time.Hour)
		fresh, err := store.TokenSource(ctx, oauthCfg, &stale).Token()
		if err != nil {
			t.Fatalf("refresh: %v", err)
		}
		if fresh.AccessToken == latestToken.AccessToken {
			t.Fatal("expected a new access token after refresh, got the same one")
		}

		reloaded, err := store.Load()
		if err != nil {
			t.Fatalf("reload: %v", err)
		}
		if reloaded.AccessToken != fresh.AccessToken {
			t.Fatal("refreshed access token was not persisted to disk")
		}

		// The refreshed token still authenticates against the server.
		resp := callRPC(t, serverAddr, "time", fresh.AccessToken)
		assertUser(t, resp, testUser)
	})
}

// --- Dex lifecycle ---------------------------------------------------------

func findDex() string {
	if p, err := exec.LookPath("dex"); err == nil {
		return p
	}
	home, err := os.UserHomeDir()
	if err == nil {
		p := filepath.Join(home, "go", "bin", "dex")
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

func startDex(ctx context.Context, t *testing.T, dexBin string, dexPort, redirectPort int) {
	t.Helper()
	cfgPath := filepath.Join(t.TempDir(), "dex.yaml")
	cfg := fmt.Sprintf(`issuer: http://127.0.0.1:%d/dex
storage:
  type: memory
web:
  http: 127.0.0.1:%d
expiry:
  idTokens: "10m"
  refreshTokens:
    reuseInterval: "30s"
    validIfNotUsedFor: "2160h"
    absoluteLifetime: "3960h"
oauth2:
  responseTypes: ["code"]
  skipApprovalScreen: true
staticClients:
  - id: %s
    name: 'OIDC Experiment CLI'
    public: true
    redirectURIs:
      - 'http://127.0.0.1:%d/callback'
      - '/device/callback'
  - id: %s
    name: 'OIDC Experiment API'
    secret: test-api-secret
    redirectURIs: []
    trustedPeers:
      - %s
enablePasswordDB: true
staticPasswords:
  - email: "%s"
    hash: '%s'
    username: "alice"
    userID: "08a8684b-db88-4b73-90a9-3cd1661f5466"
`, dexPort, dexPort, clientID, redirectPort, apiAudience, clientID, testUser, testHash)

	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatalf("write dex config: %v", err)
	}

	cmd := exec.Command(dexBin, "serve", cfgPath)
	var logs strings.Builder
	cmd.Stdout, cmd.Stderr = &logs, &logs
	if err := cmd.Start(); err != nil {
		t.Fatalf("start dex: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})

	// Wait for discovery to come up.
	wk := fmt.Sprintf("http://127.0.0.1:%d/dex/.well-known/openid-configuration", dexPort)
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(wk)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		select {
		case <-ctx.Done():
			t.Fatalf("context cancelled waiting for dex")
		case <-time.After(200 * time.Millisecond):
		}
	}
	t.Fatalf("dex did not become ready; logs:\n%s", logs.String())
}

// --- robot browser ---------------------------------------------------------

var (
	formRe       = regexp.MustCompile(`(?s)<form[^>]*action="([^"]*)"[^>]*>(.*?)</form>`)
	inputRe      = regexp.MustCompile(`(?s)<input[^>]*>`)
	inputNameRe  = regexp.MustCompile(`name="([^"]*)"`)
	inputValueRe = regexp.MustCompile(`value="([^"]*)"`)
)

// robotLogin drives the Authorization Code flow's Dex login page: GET the
// authorize URL, submit the password form, and let the redirect land on the
// CLI's loopback callback (which completes the exchange).
func robotLogin(authURL string) error {
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar}

	resp, err := c.Get(authURL)
	if err != nil {
		return fmt.Errorf("GET authorize: %w", err)
	}
	body := readBody(resp)

	m := formRe.FindStringSubmatch(body)
	if m == nil {
		return fmt.Errorf("no login form (status %d):\n%s", resp.StatusCode, body)
	}
	postURL := resolveRef(resp.Request.URL, html.UnescapeString(m[1]))

	resp2, err := c.PostForm(postURL, url.Values{"login": {testUser}, "password": {testPass}})
	if err != nil {
		return fmt.Errorf("POST login: %w", err)
	}
	body2 := readBody(resp2)
	if strings.Contains(body2, "Login complete") || strings.Contains(resp2.Request.URL.Path, "/callback") {
		return nil
	}
	return fmt.Errorf("login did not reach callback; ended at %s:\n%s", resp2.Request.URL, body2)
}

// robotDevice drives the Device Authorization Grant pages by submitting whatever
// single form each page presents (filling login/password when present) until a
// terminal page with no form is reached.
func robotDevice(verificationURIComplete string) error {
	if verificationURIComplete == "" {
		return fmt.Errorf("provider returned no verification_uri_complete")
	}
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar}

	resp, err := c.Get(verificationURIComplete)
	if err != nil {
		return fmt.Errorf("GET verification uri: %w", err)
	}
	for step := 0; step < 8; step++ {
		body := readBody(resp)
		fm := formRe.FindStringSubmatch(body)
		if fm == nil {
			return nil // terminal page (device approved)
		}
		action := resolveRef(resp.Request.URL, html.UnescapeString(fm[1]))

		form := url.Values{}
		for _, inp := range inputRe.FindAllString(fm[2], -1) {
			name := inputNameRe.FindStringSubmatch(inp)
			if name == nil {
				continue
			}
			val := ""
			if v := inputValueRe.FindStringSubmatch(inp); v != nil {
				val = html.UnescapeString(v[1])
			}
			form.Set(name[1], val)
		}
		if form.Has("login") {
			form.Set("login", testUser)
		}
		if form.Has("password") {
			form.Set("password", testPass)
		}

		resp, err = c.PostForm(action, form)
		if err != nil {
			return fmt.Errorf("POST device form (step %d): %w", step, err)
		}
	}
	return fmt.Errorf("device flow did not terminate after 8 steps")
}

func resolveRef(base *url.URL, ref string) string {
	u, err := url.Parse(ref)
	if err != nil {
		return ref
	}
	return base.ResolveReference(u).String()
}

func readBody(resp *http.Response) string {
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

// --- RPC helpers -----------------------------------------------------------

func callRPC(t *testing.T, addr, method, token string) rpc.Response {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial server: %v", err)
	}
	defer conn.Close()

	req := rpc.Request{JSONRPC: "2.0", ID: 1, Method: method, Token: token}
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		t.Fatalf("encode request: %v", err)
	}
	var resp rpc.Response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return resp
}

func assertUser(t *testing.T, resp rpc.Response, want string) {
	t.Helper()
	if resp.Error != nil {
		t.Fatalf("unexpected error response: [%d] %s", resp.Error.Code, resp.Error.Message)
	}
	result, ok := resp.Result.(map[string]interface{})
	if !ok {
		t.Fatalf("result is not an object: %#v", resp.Result)
	}
	if got := result["user"]; got != want {
		t.Fatalf("authenticated user = %v, want %v", got, want)
	}
	if result["time"] == "" || result["time"] == nil {
		t.Fatalf("missing time in result: %#v", result)
	}
}

// jwtAudience unmarshals a JWT "aud" claim, which may be a single string or an
// array of strings.
type jwtAudience []string

func (a *jwtAudience) UnmarshalJSON(b []byte) error {
	var single string
	if err := json.Unmarshal(b, &single); err == nil {
		*a = []string{single}
		return nil
	}
	var multi []string
	if err := json.Unmarshal(b, &multi); err != nil {
		return err
	}
	*a = multi
	return nil
}

func assertAudienceContains(t *testing.T, accessToken, want string) {
	t.Helper()
	parts := strings.Split(accessToken, ".")
	if len(parts) != 3 {
		t.Fatalf("access token is not a JWT (%d segments)", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode token payload: %v", err)
	}
	var claims struct {
		Aud jwtAudience `json:"aud"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("unmarshal claims: %v", err)
	}
	for _, a := range claims.Aud {
		if a == want {
			return
		}
	}
	t.Fatalf("access token aud = %v, want it to contain %q", claims.Aud, want)
}

func assertUnauthorized(t *testing.T, resp rpc.Response) {
	t.Helper()
	if resp.Error == nil {
		t.Fatalf("expected an error response, got result: %#v", resp.Result)
	}
	if resp.Error.Code != rpc.CodeUnauthorized {
		t.Fatalf("error code = %d, want %d (%q)", resp.Error.Code, rpc.CodeUnauthorized, resp.Error.Message)
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find free port: %v", err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}
