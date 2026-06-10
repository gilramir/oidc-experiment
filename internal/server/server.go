// Package server implements the JSON-RPC-over-TCP service. Every request must
// carry a valid OIDC access token (a JWT). The server verifies the token's
// signature against the provider's JWKS, checks issuer, audience and expiry, and
// only then runs the requested method. Anonymous or invalid requests are
// rejected.
package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gilramir/oidc-experiment/internal/rpc"
)

// defaultReadTimeout bounds how long a connection may take to deliver its
// request, so a client that connects and never sends can't pin a goroutine
// (and a socket) open indefinitely.
const defaultReadTimeout = 5 * time.Second

// Server verifies access tokens and serves JSON-RPC methods.
type Server struct {
	verifier *oidc.IDTokenVerifier
	// ReadTimeout bounds the time allowed to read a request from a connection.
	// Zero disables the deadline. Defaults to defaultReadTimeout.
	ReadTimeout time.Duration
}

// New performs OIDC discovery against the issuer and builds a verifier that
// checks signature, issuer, audience, and expiry. The provider's signing keys
// are fetched lazily and cached by go-oidc, so the provider is not contacted on
// every request.
//
// audience is the value that must appear in the token's "aud" claim — this
// resource server's own identifier, not the CLI's. go-oidc spells the expected
// audience as oidc.Config.ClientID, but here it means "the audience I require".
func New(ctx context.Context, issuer, audience string) (*Server, error) {
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("discover OIDC issuer %q: %w", issuer, err)
	}
	return &Server{
		verifier:    provider.Verifier(&oidc.Config{ClientID: audience}),
		ReadTimeout: defaultReadTimeout,
	}, nil
}

// Serve accepts connections until the listener is closed.
func (s *Server) Serve(ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go s.Handle(conn)
	}
}

// Handle processes a single connection: one JSON-RPC request in, one response
// out.
func (s *Server) Handle(conn net.Conn) {
	defer conn.Close()

	if s.ReadTimeout > 0 {
		_ = conn.SetReadDeadline(time.Now().Add(s.ReadTimeout))
	}

	var req rpc.Request
	if err := json.NewDecoder(conn).Decode(&req); err != nil {
		return
	}
	resp := rpc.Response{JSONRPC: "2.0", ID: req.ID}

	claims, err := s.authenticate(req.Token)
	if err != nil {
		resp.Error = &rpc.Error{Code: rpc.CodeUnauthorized, Message: "unauthorized: " + err.Error()}
		writeResponse(conn, resp)
		return
	}

	switch req.Method {
	case "time":
		resp.Result = map[string]interface{}{
			"time": time.Now().Format(time.RFC3339),
			"user": identity(claims),
		}
	case "token":
		// Echo back the verified token claims (sub, email, name, groups, …) so a
		// user can confirm auth works and inspect exactly what the provider put
		// in the token.
		resp.Result = claims
	default:
		resp.Error = &rpc.Error{Code: rpc.CodeMethodNotFound, Message: "method not found: " + req.Method}
	}
	writeResponse(conn, resp)
}

// authenticate verifies the access token and returns all of its claims. An empty
// or invalid token is an error.
func (s *Server) authenticate(token string) (map[string]interface{}, error) {
	if token == "" {
		return nil, fmt.Errorf("no token supplied")
	}
	verified, err := s.verifier.Verify(context.Background(), token)
	if err != nil {
		return nil, err
	}
	var claims map[string]interface{}
	if err := verified.Claims(&claims); err != nil {
		return nil, fmt.Errorf("parse claims: %w", err)
	}
	return claims, nil
}

// identity reduces a token's claims to a human-readable identity: the email if
// present, else the subject.
func identity(claims map[string]interface{}) string {
	if email, ok := claims["email"].(string); ok && email != "" {
		return email
	}
	if sub, ok := claims["sub"].(string); ok {
		return sub
	}
	return ""
}

func writeResponse(conn net.Conn, resp rpc.Response) {
	if err := json.NewEncoder(conn).Encode(resp); err != nil {
		log.Printf("encode response: %v", err)
	}
}
