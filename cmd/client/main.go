// Command client logs in via OIDC, caches the resulting tokens, and calls a
// method on the JSON-RPC server, passing the access token along.
//
// On each run it tries the cached token first (refreshing it silently if it has
// expired). Only when there is no usable token does it start an interactive
// login, using either the Authorization Code + PKCE flow (default) or the
// Device Authorization Grant (--auth=device).
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gilramir/oidc-experiment/internal/auth"
	"github.com/gilramir/oidc-experiment/internal/rpc"
	"github.com/gilramir/oidc-experiment/internal/token"
	"golang.org/x/oauth2"
)

// These would be configuration in a real tool. Pointed at the local Dex by
// default; swapping to Okta is a matter of changing issuer + clientID.
const (
	defaultIssuer   = "http://127.0.0.1:5556/dex"
	defaultClientID = "oidc-experiment-cli"
	defaultAudience = "oidc-experiment-api"
	redirectURL     = "http://127.0.0.1:5555/callback"

	// crossClientScopePrefix is Dex's way to request that the issued token's
	// audience be a *different* registered client (our resource server) rather
	// than the CLI itself. The target client must list the CLI as a trusted peer.
	crossClientScopePrefix = "audience:server:client_id:"
)

func main() {
	authMode := flag.String("auth", "authcode", "login flow: authcode | device")
	addr := flag.String("addr", "127.0.0.1:8888", "server address")
	issuer := flag.String("issuer", defaultIssuer, "OIDC issuer URL")
	clientID := flag.String("client-id", defaultClientID, "OIDC client id")
	audience := flag.String("audience", defaultAudience, "API audience to request the access token for")
	forceLogin := flag.Bool("login", false, "force a fresh interactive login")
	logout := flag.Bool("logout", false, "delete the cached token and exit")
	flag.Parse()

	store, err := token.NewStore()
	if err != nil {
		fatal("init token store: %v", err)
	}

	if *logout {
		if err := store.Clear(); err != nil {
			fatal("logout: %v", err)
		}
		fmt.Println("Logged out (cached token removed).")
		return
	}

	method := flag.Arg(0)
	if method == "" {
		fmt.Fprintln(os.Stderr, "usage: client [flags] <method>   (e.g. client time)")
		os.Exit(2)
	}

	ctx := context.Background()
	cfg := auth.Config{
		Issuer:      *issuer,
		ClientID:    *clientID,
		RedirectURL: redirectURL,
		Scopes: []string{
			oidc.ScopeOpenID, "profile", "email",
			oidc.ScopeOfflineAccess,            // required to receive a refresh token
			crossClientScopePrefix + *audience, // make the resource server the token's audience
		},
	}

	_, oauthCfg, err := cfg.Provider(ctx)
	if err != nil {
		fatal("%v", err)
	}

	accessToken, err := obtainAccessToken(ctx, store, oauthCfg, *authMode, *forceLogin)
	if err != nil {
		fatal("authentication failed: %v", err)
	}

	resp, err := call(*addr, method, accessToken)
	if err != nil {
		fatal("rpc call: %v", err)
	}

	if resp.Error != nil {
		fatal("server rejected request: [%d] %s", resp.Error.Code, resp.Error.Message)
	}
	out, _ := json.MarshalIndent(resp.Result, "", "  ")
	fmt.Println(string(out))
}

// obtainAccessToken returns a valid access token, refreshing or logging in as
// needed.
func obtainAccessToken(ctx context.Context, store *token.Store, oauthCfg *oauth2.Config, mode string, force bool) (string, error) {
	if !force {
		if cached, err := store.Load(); err == nil {
			// The persisting source returns the cached token, or silently
			// refreshes (and re-saves) it if expired.
			src := store.TokenSource(ctx, oauthCfg, cached)
			if fresh, err := src.Token(); err == nil {
				return fresh.AccessToken, nil
			}
			// Refresh token missing/expired/revoked: fall through to re-login.
		}
	}

	var tok *oauth2.Token
	var err error
	switch mode {
	case "device":
		tok, err = auth.Device(ctx, oauthCfg, presentDeviceCode)
	case "authcode":
		tok, err = auth.AuthCode(ctx, oauthCfg, presentAuthURL)
	default:
		return "", fmt.Errorf("unknown --auth mode %q (use authcode or device)", mode)
	}
	if err != nil {
		return "", err
	}
	if err := store.Save(tok); err != nil {
		return "", fmt.Errorf("save token: %w", err)
	}
	return tok.AccessToken, nil
}

// call opens a TCP connection, sends one JSON-RPC request, and reads one
// response.
func call(addr, method, accessToken string) (*rpc.Response, error) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	req := rpc.Request{JSONRPC: "2.0", ID: 1, Method: method, Token: accessToken}
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return nil, err
	}
	var resp rpc.Response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// presentAuthURL is the auth-code presenter: print the URL and open a browser.
func presentAuthURL(authURL string) {
	fmt.Println("Opening browser to log in:")
	fmt.Println("  " + authURL)
	openBrowser(authURL)
}

// presentDeviceCode is the device-flow presenter: tell the user where to go and
// what code to enter.
func presentDeviceCode(resp *oauth2.DeviceAuthResponse) {
	fmt.Println("To log in, visit:")
	fmt.Printf("  %s\n", resp.VerificationURI)
	fmt.Printf("and enter the code: %s\n", resp.UserCode)
	if resp.VerificationURIComplete != "" {
		fmt.Printf("\nOr open this URL directly (code pre-filled):\n  %s\n", resp.VerificationURIComplete)
	}
	fmt.Println("\nWaiting for you to finish logging in...")
}

// openBrowser is best-effort; if it fails the user can click the printed URL.
func openBrowser(u string) {
	var cmd string
	var args []string
	switch runtime.GOOS {
	case "darwin":
		cmd = "open"
	case "windows":
		cmd, args = "rundll32", []string{"url.dll,FileProtocolHandler"}
	default:
		cmd = "xdg-open"
	}
	_ = exec.Command(cmd, append(args, u)...).Start()
}

func fatal(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", args...)
	os.Exit(1)
}
