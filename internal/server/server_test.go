package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

const testAudience = "oidc-experiment-api"

// mockIDP is a minimal OIDC issuer for unit tests: it serves a discovery
// document and a JWKS, and can mint signed JWTs with arbitrary claims (expired,
// wrong audience, etc.) — tokens a real provider would never hand out.
type mockIDP struct {
	srv    *httptest.Server
	priv   *rsa.PrivateKey
	kid    string
	issuer string
}

func newMockIDP(t *testing.T) *mockIDP {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	m := &mockIDP{priv: priv, kid: "test-key-1"}

	jwks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Key:       priv.Public(),
		KeyID:     m.kid,
		Algorithm: "RS256",
		Use:       "sig",
	}}}

	mux := http.NewServeMux()
	m.srv = httptest.NewServer(mux)
	t.Cleanup(m.srv.Close)
	m.issuer = m.srv.URL

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                m.issuer,
			"authorization_endpoint":                m.issuer + "/auth",
			"token_endpoint":                        m.issuer + "/token",
			"jwks_uri":                              m.issuer + "/keys",
			"id_token_signing_alg_values_supported": []string{"RS256"},
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
		})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(jwks)
	})
	return m
}

// token mints a JWT signed by the IDP's key (the one published in the JWKS).
func (m *mockIDP) token(t *testing.T, claims jwt.Claims, extra map[string]any) string {
	return m.signWith(t, m.priv, m.kid, claims, extra)
}

func (m *mockIDP) signWith(t *testing.T, key *rsa.PrivateKey, kid string, claims jwt.Claims, extra map[string]any) string {
	t.Helper()
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: key, KeyID: kid}},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	raw, err := jwt.Signed(signer).Claims(claims).Claims(extra).Serialize()
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return raw
}

func validClaims(issuer string) (jwt.Claims, map[string]any) {
	now := time.Now()
	return jwt.Claims{
			Issuer:   issuer,
			Subject:  "alice-id",
			Audience: jwt.Audience{testAudience},
			IssuedAt: jwt.NewNumericDate(now),
			Expiry:   jwt.NewNumericDate(now.Add(10 * time.Minute)),
		}, map[string]any{
			"email": "alice@example.com",
		}
}

func newTestServer(t *testing.T, m *mockIDP) *Server {
	t.Helper()
	srv, err := New(context.Background(), m.issuer, testAudience)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return srv
}

// TestAuthenticate exercises the token-validation paths directly: a valid token
// is accepted, and every way a token can be invalid is rejected.
func TestAuthenticate(t *testing.T) {
	m := newMockIDP(t)
	srv := newTestServer(t, m)

	t.Run("ValidTokenAccepted", func(t *testing.T) {
		cl, extra := validClaims(m.issuer)
		user, err := srv.authenticate(m.token(t, cl, extra))
		if err != nil {
			t.Fatalf("expected valid token to be accepted, got: %v", err)
		}
		if user != "alice@example.com" {
			t.Fatalf("identity = %q, want alice@example.com", user)
		}
	})

	t.Run("FallsBackToSubjectWhenNoEmail", func(t *testing.T) {
		cl, _ := validClaims(m.issuer)
		user, err := srv.authenticate(m.token(t, cl, nil))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if user != "alice-id" {
			t.Fatalf("identity = %q, want subject alice-id", user)
		}
	})

	t.Run("EmptyTokenRejected", func(t *testing.T) {
		if _, err := srv.authenticate(""); err == nil {
			t.Fatal("expected empty token to be rejected")
		}
	})

	t.Run("MalformedTokenRejected", func(t *testing.T) {
		if _, err := srv.authenticate("not.a.jwt"); err == nil {
			t.Fatal("expected malformed token to be rejected")
		}
	})

	t.Run("ExpiredTokenRejected", func(t *testing.T) {
		cl, extra := validClaims(m.issuer)
		cl.Expiry = jwt.NewNumericDate(time.Now().Add(-time.Minute))
		if _, err := srv.authenticate(m.token(t, cl, extra)); err == nil {
			t.Fatal("expected expired token to be rejected")
		}
	})

	t.Run("WrongAudienceRejected", func(t *testing.T) {
		cl, extra := validClaims(m.issuer)
		cl.Audience = jwt.Audience{"some-other-api"}
		if _, err := srv.authenticate(m.token(t, cl, extra)); err == nil {
			t.Fatal("expected token for a different audience to be rejected")
		}
	})

	t.Run("WrongIssuerRejected", func(t *testing.T) {
		cl, extra := validClaims("https://evil.example.com")
		if _, err := srv.authenticate(m.token(t, cl, extra)); err == nil {
			t.Fatal("expected token from a different issuer to be rejected")
		}
	})

	t.Run("BadSignatureRejected", func(t *testing.T) {
		// Sign with a key that is NOT published in the IDP's JWKS, but reuse the
		// known key id so the verifier still tries to validate it.
		other, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		cl, extra := validClaims(m.issuer)
		tok := m.signWith(t, other, m.kid, cl, extra)
		if _, err := srv.authenticate(tok); err == nil {
			t.Fatal("expected token with an unknown signing key to be rejected")
		}
	})
}

// TestReadDeadlineClosesIdleConnection covers the read deadline: a client that
// connects but never sends a request must have its connection closed, rather
// than pinning a server goroutine forever.
func TestReadDeadlineClosesIdleConnection(t *testing.T) {
	m := newMockIDP(t)
	srv := newTestServer(t, m)
	srv.ReadTimeout = 150 * time.Millisecond

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go srv.Serve(ln)

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Never send anything. The server should hit its read deadline and close.
	// Our own deadline is just a safety net so the test can't hang.
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	start := time.Now()
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("expected the server to close the idle connection")
	}
	if elapsed := time.Since(start); elapsed > 1500*time.Millisecond {
		t.Fatalf("server took too long to close idle connection: %v", elapsed)
	}
}
