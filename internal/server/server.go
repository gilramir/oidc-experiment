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
	"github.com/gilbertr/oidc-experiment/internal/rpc"
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
// checks signature, issuer, audience == clientID, and expiry. The provider's
// signing keys are fetched lazily and cached by go-oidc, so the provider is not
// contacted on every request.
func New(ctx context.Context, issuer, clientID string) (*Server, error) {
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("discover OIDC issuer %q: %w", issuer, err)
	}
	return &Server{
		verifier:    provider.Verifier(&oidc.Config{ClientID: clientID}),
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

	user, err := s.authenticate(req.Token)
	if err != nil {
		resp.Error = &rpc.Error{Code: rpc.CodeUnauthorized, Message: "unauthorized: " + err.Error()}
		writeResponse(conn, resp)
		return
	}

	switch req.Method {
	case "time":
		resp.Result = map[string]interface{}{
			"time": time.Now().Format(time.RFC3339),
			"user": user,
		}
	default:
		resp.Error = &rpc.Error{Code: rpc.CodeMethodNotFound, Message: "method not found: " + req.Method}
	}
	writeResponse(conn, resp)
}

// authenticate verifies the access token and returns a human-readable identity
// (email if present, else subject). An empty or invalid token is an error.
func (s *Server) authenticate(token string) (string, error) {
	if token == "" {
		return "", fmt.Errorf("no token supplied")
	}
	verified, err := s.verifier.Verify(context.Background(), token)
	if err != nil {
		return "", err
	}
	var claims struct {
		Email   string `json:"email"`
		Subject string `json:"sub"`
	}
	if err := verified.Claims(&claims); err != nil {
		return "", fmt.Errorf("parse claims: %w", err)
	}
	if claims.Email != "" {
		return claims.Email, nil
	}
	return verified.Subject, nil
}

func writeResponse(conn net.Conn, resp rpc.Response) {
	if err := json.NewEncoder(conn).Encode(resp); err != nil {
		log.Printf("encode response: %v", err)
	}
}
