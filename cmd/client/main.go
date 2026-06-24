// Command client logs in via OIDC, caches the resulting tokens, and calls a
// method on the JSON-RPC server, passing the access token along.
//
// On each run it tries the cached token first (refreshing it silently if it has
// expired). Only when there is no usable token does it start an interactive
// login, using either the Authorization Code + PKCE flow (default) or the
// Device Authorization Grant (--auth=device).
//
// For automation ("role" accounts with no human at a browser) it also supports
// the Client Credentials grant (--auth=client-credentials): the client
// authenticates with its own secret (OIDC_CLIENT_SECRET) and gets a token whose
// subject is the client itself. That path is stateless — no browser, no token
// cache, no refresh — see DESIGN.md "Service / role accounts".
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

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
	redirectURL     = "http://127.0.0.1/callback"

	// crossClientScopePrefix is Dex's way to request that the issued token's
	// audience be a *different* registered client (our resource server) rather
	// than the CLI itself. The target client must list the CLI as a trusted peer.
	crossClientScopePrefix = "audience:server:client_id:"
)

func main() {
	authMode := flag.String("auth", "authcode", "login flow: authcode | device | client-credentials")
	addr := flag.String("addr", "127.0.0.1:8888", "server address")
	issuer := flag.String("issuer", defaultIssuer, "OIDC issuer URL")
	clientID := flag.String("client-id", defaultClientID, "OIDC client id")
	audience := flag.String("audience", defaultAudience, "API audience to request the access token for")
	forceLogin := flag.Bool("login", false, "force a fresh interactive login")
	logout := flag.Bool("logout", false, "delete the cached token and exit")
	info := flag.Bool("info", false, "print info about the cached token and exit")
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

	if *info {
		printTokenInfo(store)
		return
	}

	method := flag.Arg(0)
	if method == "" {
		fmt.Fprintln(os.Stderr, "usage: client [flags] <method>   (methods: time, token)")
		os.Exit(2)
	}

	ctx := context.Background()

	// The interactive (human) flows request OIDC identity scopes plus a refresh
	// token. The client-credentials (service-account) flow has no user identity
	// to assert and nothing to refresh, so it asks only for the resource-server
	// audience — requesting openid/offline_access there would be meaningless.
	scopes := []string{
		oidc.ScopeOpenID, "profile", "email",
		oidc.ScopeOfflineAccess,            // required to receive a refresh token
		crossClientScopePrefix + *audience, // make the resource server the token's audience
	}
	if *authMode == "client-credentials" {
		scopes = []string{crossClientScopePrefix + *audience}
	}

	cfg := auth.Config{
		Issuer:      *issuer,
		ClientID:    *clientID,
		RedirectURL: redirectURL,
		Scopes:      scopes,
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
	// Client credentials is a stateless machine-to-machine flow: no user, no
	// browser, no refresh token, and so no on-disk cache. Mint a fresh token
	// straight from the token endpoint each run. The secret is read from the
	// environment, never a flag, so it does not land in shell history or argv.
	if mode == "client-credentials" {
		secret := os.Getenv("OIDC_CLIENT_SECRET")
		tok, err := auth.ClientCredentials(ctx, oauthCfg.Endpoint.TokenURL, oauthCfg.ClientID, secret, oauthCfg.Scopes)
		if err != nil {
			// Mainline Dex does not implement this grant; a real provider (Okta,
			// Keycloak, …) does. Make that failure mode legible instead of cryptic.
			if strings.Contains(err.Error(), "unsupported_grant_type") {
				return "", fmt.Errorf("%w\n\nhint: Dex does not support the client_credentials grant; "+
					"point --issuer at a provider that does (see DESIGN.md \"Service / role accounts\")", err)
			}
			return "", err
		}
		return tok.AccessToken, nil
	}

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
		return "", fmt.Errorf("unknown --auth mode %q (use authcode, device, or client-credentials)", mode)
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

// printTokenInfo loads the on-disk token and prints human-readable debugging
// information: JWT claims for the access and ID tokens (with expiry annotations)
// and whether a refresh token is present.
func printTokenInfo(store *token.Store) {
	fmt.Printf("Token file: %s\n", store.Path())
	tok, err := store.Load()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			fmt.Println("No cached token.")
		} else {
			fmt.Printf("Error reading token: %v\n", err)
		}
		return
	}
	now := time.Now()
	printJWT("Access token", tok.AccessToken, now)
	if id, ok := tok.Extra("id_token").(string); ok && id != "" {
		printJWT("ID token", id, now)
	}
	if tok.RefreshToken != "" {
		fmt.Println("\nRefresh token: present  (expiry is managed server-side)")
	} else {
		fmt.Println("\nRefresh token: absent")
	}
}

func printJWT(label, rawJWT string, now time.Time) {
	claims, err := decodeJWTClaims(rawJWT)
	if err != nil {
		fmt.Printf("\n%s: (unreadable: %v)\n", label, err)
		return
	}
	fmt.Printf("\n%s\n", label)

	shown := map[string]bool{}
	for _, key := range []string{"iss", "sub", "aud", "email", "name", "email_verified"} {
		if v, ok := claims[key]; ok {
			fmt.Printf("  %-20s %s\n", key+":", claimStr(v))
			shown[key] = true
		}
	}
	skip := map[string]bool{"iat": true, "exp": true, "at_hash": true, "c_hash": true, "nonce": true}
	for key, v := range claims {
		if !shown[key] && !skip[key] {
			fmt.Printf("  %-20s %s\n", key+":", claimStr(v))
		}
	}
	if v, ok := claims["iat"]; ok {
		if t, ok := unixTime(v); ok {
			fmt.Printf("  %-20s %s  (%s)\n", "iat:", t.UTC().Format("2006-01-02 15:04:05 UTC"), relTime(t, now))
		}
	}
	if v, ok := claims["exp"]; ok {
		if t, ok := unixTime(v); ok {
			status := "VALID"
			if now.After(t) {
				status = "EXPIRED"
			}
			fmt.Printf("  %-20s %s  (%s)  [%s]\n", "exp:", t.UTC().Format("2006-01-02 15:04:05 UTC"), relTime(t, now), status)
		}
	}
}

func decodeJWTClaims(rawJWT string) (map[string]interface{}, error) {
	parts := strings.Split(rawJWT, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("not a JWT (%d segments)", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode payload: %w", err)
	}
	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("unmarshal claims: %w", err)
	}
	return claims, nil
}

// claimStr formats a JWT claim value for display. Arrays (e.g. aud) are
// joined with commas rather than printed as Go slice literals.
func claimStr(v interface{}) string {
	if arr, ok := v.([]interface{}); ok {
		parts := make([]string, len(arr))
		for i, item := range arr {
			parts[i] = fmt.Sprintf("%v", item)
		}
		return strings.Join(parts, ", ")
	}
	return fmt.Sprintf("%v", v)
}

func unixTime(v interface{}) (time.Time, bool) {
	if n, ok := v.(float64); ok {
		return time.Unix(int64(n), 0), true
	}
	return time.Time{}, false
}

func relTime(t, now time.Time) string {
	d := t.Sub(now)
	if d < 0 {
		return fmtDuration(-d) + " ago"
	}
	return "in " + fmtDuration(d)
}

func fmtDuration(d time.Duration) string {
	d = d.Round(time.Second)
	switch {
	case d >= 24*time.Hour:
		days := d / (24 * time.Hour)
		hours := (d % (24 * time.Hour)) / time.Hour
		if hours == 0 {
			return fmt.Sprintf("%dd", days)
		}
		return fmt.Sprintf("%dd%dh", days, hours)
	case d >= time.Hour:
		hours := d / time.Hour
		mins := (d % time.Hour) / time.Minute
		if mins == 0 {
			return fmt.Sprintf("%dh", hours)
		}
		return fmt.Sprintf("%dh%dm", hours, mins)
	case d >= time.Minute:
		mins := d / time.Minute
		secs := (d % time.Minute) / time.Second
		if secs == 0 {
			return fmt.Sprintf("%dm", mins)
		}
		return fmt.Sprintf("%dm%ds", mins, secs)
	default:
		return fmt.Sprintf("%ds", d/time.Second)
	}
}

func fatal(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", args...)
	os.Exit(1)
}
