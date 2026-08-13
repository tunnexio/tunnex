package sso

import (
	"context"
	"errors"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"

	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
)

// NewMicrosoft registers Microsoft Entra ID, with the organization's tenant
// PINNED. Entra's issuer is tenant-specific
// (https://login.microsoftonline.com/{tid}/v2.0), so pinning the tenant makes
// go-oidc's exact-issuer check reject tokens minted for any other tenant — the
// correct posture for a B2B product (multi-tenant `common`/`organizations`
// endpoints are intentionally refused: they'd defeat issuer validation).
func NewMicrosoft(ctx context.Context, tenantID, clientID, clientSecret, redirectURL string) (Provider, error) {
	tenantID = strings.TrimSpace(tenantID)
	switch strings.ToLower(tenantID) {
	case "", "common", "organizations", "consumers":
		return nil, apierr.BadRequest("sso_tenant_required",
			"Microsoft SSO requires your organization's Entra tenant ID; shared endpoints are not supported")
	}
	issuer := "https://login.microsoftonline.com/" + tenantID + "/v2.0"
	return NewOIDCProvider(ctx, "microsoft", issuer, clientID, clientSecret, redirectURL,
		[]string{oidc.ScopeOpenID, "email", "profile"}, microsoftNormalizer)
}

// microsoftNormalizer handles Entra's claim quirks (see S2.4): `email` may be
// absent; `preferred_username` is a UPN (usually an email). Entra does not
// assert `email_verified` in the ID token, but a pinned-tenant login is vouched
// for by the organization's own directory, so it counts as verified for linking.
func microsoftNormalizer(r RawClaims) (Identity, error) {
	email := r.Email
	if email == "" {
		email = r.PreferredUsername
	}
	if !strings.Contains(email, "@") {
		return Identity{}, errors.New("microsoft id_token has no usable email or preferred_username")
	}
	return Identity{
		Subject:       r.Sub,
		Email:         strings.ToLower(email),
		EmailVerified: true, // tenant-vouched (pinned tenant)
		Name:          r.Name,
	}, nil
}
