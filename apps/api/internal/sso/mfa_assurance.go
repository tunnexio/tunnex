package sso

import (
	"encoding/json"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

// verifiedIDTokenMFATime is called only after signature, issuer, audience,
// expiration and nonce validation. Unknown assurance is not a login failure:
// protected applications must require a supported step-up instead.
func verifiedIDTokenMFATime(token *oidc.IDToken, now time.Time) time.Time {
	var claims struct {
		AMR      json.RawMessage `json:"amr"`
		AuthTime json.RawMessage `json:"auth_time"`
	}
	if token == nil || token.Claims(&claims) != nil {
		return time.Time{}
	}
	var methods []string
	var seconds int64
	if json.Unmarshal(claims.AMR, &methods) != nil || json.Unmarshal(claims.AuthTime, &seconds) != nil ||
		seconds <= 0 || seconds > now.Unix() || len(methods) > 32 {
		return time.Time{}
	}
	// RFC 8176's explicit "mfa" is the supported assurance contract. Neither
	// "otp" alone nor a provider-specific acr value proves multiple factors.
	for _, method := range methods {
		if method == "mfa" {
			return time.Unix(seconds, 0).UTC()
		}
	}
	return time.Time{}
}
