// Package token persists OAuth2 tokens to disk and provides a TokenSource that
// transparently refreshes expired access tokens and writes the refreshed set
// back to disk.
package token

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/oauth2"
)

const (
	appDir   = "oidc-experiment"
	fileName = "token.json"
)

// persisted is the on-disk JSON shape. We use our own struct (rather than
// marshalling oauth2.Token directly) because the id_token lives in the token's
// untyped Extra map and would otherwise be lost on save.
type persisted struct {
	AccessToken  string    `json:"access_token"`
	TokenType    string    `json:"token_type"`
	RefreshToken string    `json:"refresh_token"`
	IDToken      string    `json:"id_token,omitempty"`
	Expiry       time.Time `json:"expiry"`
}

// Store reads and writes the token file under the user's config directory,
// e.g. ~/.config/oidc-experiment/token.json (mode 0600).
type Store struct {
	path string
}

// NewStore locates the token file under os.UserConfigDir().
func NewStore() (*Store, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return nil, err
	}
	return &Store{path: filepath.Join(dir, appDir, fileName)}, nil
}

// NewStoreAt returns a Store backed by an explicit file path. Useful for tests.
func NewStoreAt(path string) *Store { return &Store{path: path} }

// Path returns the absolute path of the token file.
func (s *Store) Path() string { return s.path }

// Load reads the stored token, or returns an error if none exists.
func (s *Store) Load() (*oauth2.Token, error) {
	data, err := os.ReadFile(s.path)
	if err != nil {
		return nil, err
	}
	var p persisted
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, err
	}
	tok := &oauth2.Token{
		AccessToken:  p.AccessToken,
		TokenType:    p.TokenType,
		RefreshToken: p.RefreshToken,
		Expiry:       p.Expiry,
	}
	if p.IDToken != "" {
		tok = tok.WithExtra(map[string]interface{}{"id_token": p.IDToken})
	}
	return tok, nil
}

// Save writes the token to disk with 0600 permissions, creating the directory
// if needed.
func (s *Store) Save(tok *oauth2.Token) error {
	p := persisted{
		AccessToken:  tok.AccessToken,
		TokenType:    tok.TokenType,
		RefreshToken: tok.RefreshToken,
		Expiry:       tok.Expiry,
	}
	if id, ok := tok.Extra("id_token").(string); ok {
		p.IDToken = id
	}
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(s.path, data, 0o600)
}

// Clear deletes the token file. Removing a non-existent file is not an error.
func (s *Store) Clear() error {
	err := os.Remove(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// TokenSource wraps the standard oauth2 auto-refreshing token source so that any
// token it mints (the original, or a refreshed one) is written back to disk.
//
// oauth2.Config.TokenSource returns a ReuseTokenSource: it hands back the
// current token until it is within ~10s of expiry, then uses the refresh token
// to fetch a new one. It does NOT persist that new token, so we layer Save on
// top, keyed on the access token changing.
func (s *Store) TokenSource(ctx context.Context, cfg *oauth2.Config, tok *oauth2.Token) oauth2.TokenSource {
	return &persistingSource{
		base:  cfg.TokenSource(ctx, tok),
		store: s,
		last:  tok.AccessToken,
	}
}

type persistingSource struct {
	base  oauth2.TokenSource
	store *Store
	last  string
}

func (p *persistingSource) Token() (*oauth2.Token, error) {
	tok, err := p.base.Token()
	if err != nil {
		return nil, err
	}
	if tok.AccessToken != p.last {
		if err := p.store.Save(tok); err != nil {
			return nil, err
		}
		p.last = tok.AccessToken
	}
	return tok, nil
}
