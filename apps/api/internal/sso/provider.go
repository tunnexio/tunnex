package sso

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// Provider is a configured OIDC identity provider. Google is the first
// registration; Microsoft (S2.4) is the same generic OIDC provider with a
// different issuer, so it needs config + an adapter, not a new implementation.
type Provider interface {
	Name() string
	// AuthCodeURL builds the IdP redirect URL carrying state (callback CSRF),
	// nonce (ID-token replay), and the PKCE S256 challenge (code interception).
	AuthCodeURL(state, nonce, pkceChallenge string) string
	// Exchange trades the callback code (with the PKCE verifier) and verifies the
	// ID token — issuer, audience, expiry, signature (via the provider's JWKS),
	// and nonce — returning a normalized Identity.
	Exchange(ctx context.Context, code, pkceVerifier, expectedNonce string) (Identity, error)
}

// RawClaims are the ID-token claims we read; providers differ in which are
// present/trustworthy, so each supplies a Normalizer.
type RawClaims struct {
	Sub               string `json:"sub"`
	Email             string `json:"email"`
	EmailVerified     bool   `json:"email_verified"`
	Name              string `json:"name"`
	PreferredUsername string `json:"preferred_username"`
	Tid               string `json:"tid"`
}

// Normalizer maps a provider's raw claims into the internal Identity. This is
// THE seam that keeps provider differences out of the shared flow (S2.3(a)).
type Normalizer func(RawClaims) (Identity, error)

// oidcProvider is the generic OIDC implementation used by every provider.
type oidcProvider struct {
	name      string
	oauth2    *oauth2.Config
	verifier  *oidc.IDTokenVerifier
	normalize Normalizer
}

// NewOIDCProvider discovers the issuer (fetching JWKS) and builds a provider
// with the given claims normalizer.
func NewOIDCProvider(ctx context.Context, name, issuer, clientID, clientSecret, redirectURL string, scopes []string, normalize Normalizer) (Provider, error) {
	p, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery for %s: %w", name, err)
	}
	return &oidcProvider{
		name: name,
		oauth2: &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Endpoint:     p.Endpoint(),
			RedirectURL:  redirectURL,
			Scopes:       scopes,
		},
		verifier:  p.Verifier(&oidc.Config{ClientID: clientID}),
		normalize: normalize,
	}, nil
}

func (p *oidcProvider) Name() string { return p.name }

func (p *oidcProvider) AuthCodeURL(state, nonce, challenge string) string {
	return p.oauth2.AuthCodeURL(state,
		oauth2.SetAuthURLParam("nonce", nonce),
		oauth2.SetAuthURLParam("code_challenge", challenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)
}

func (p *oidcProvider) Exchange(ctx context.Context, code, verifier, expectedNonce string) (Identity, error) {
	tok, err := p.oauth2.Exchange(ctx, code, oauth2.SetAuthURLParam("code_verifier", verifier))
	if err != nil {
		return Identity{}, fmt.Errorf("code exchange: %w", err)
	}
	rawID, ok := tok.Extra("id_token").(string)
	if !ok {
		return Identity{}, errors.New("no id_token in token response")
	}
	idt, err := p.verifier.Verify(ctx, rawID) // issuer (exact), audience, expiry, signature
	if err != nil {
		return Identity{}, fmt.Errorf("verify id_token: %w", err)
	}
	if idt.Nonce != expectedNonce {
		return Identity{}, errors.New("id_token nonce mismatch")
	}
	var raw RawClaims
	if err := idt.Claims(&raw); err != nil {
		return Identity{}, fmt.Errorf("parse claims: %w", err)
	}
	id, err := p.normalize(raw)
	if err != nil {
		return Identity{}, err
	}
	id.Provider = p.name
	return id, nil
}

// googleNormalizer trusts Google's standard email + email_verified claims.
func googleNormalizer(r RawClaims) (Identity, error) {
	if r.Email == "" {
		return Identity{}, errors.New("google id_token has no email")
	}
	return Identity{Subject: r.Sub, Email: r.Email, EmailVerified: r.EmailVerified, Name: r.Name}, nil
}

// NewGoogle registers Google as an OIDC provider.
func NewGoogle(ctx context.Context, clientID, clientSecret, redirectURL string) (Provider, error) {
	return NewOIDCProvider(ctx, "google", "https://accounts.google.com",
		clientID, clientSecret, redirectURL, []string{oidc.ScopeOpenID, "email", "profile"}, googleNormalizer)
}

// PKCE returns a fresh (verifier, S256 challenge) pair.
func PKCE() (verifier, challenge string, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	verifier = base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(sum[:])
	return verifier, challenge, nil
}

// RandomToken returns a URL-safe random string for state/nonce.
func RandomToken() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
