package sso

import (
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"net/url"
	"strings"
	"time"
	"unicode"
)

// SafeInternalReturn permits a console-relative return, including the escaped
// App Access target, but never a protocol-relative or external destination.
func SafeInternalReturn(raw string) (string, error) {
	if raw == "" {
		return "", nil
	}
	if len(raw) > 32768 || !strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "//") || strings.ContainsAny(raw, "\\#") {
		return "", apierr.BadRequest("invalid_return", "invalid sign-in return")
	}
	for _, r := range raw {
		if unicode.IsControl(r) {
			return "", apierr.BadRequest("invalid_return", "invalid sign-in return")
		}
	}
	u, e := url.ParseRequestURI(raw)
	if e != nil || u.IsAbs() || u.Host != "" || u.User != nil || u.Fragment != "" || strings.HasPrefix(u.Path, "//") || strings.Contains(u.Path, "\\") {
		return "", apierr.BadRequest("invalid_return", "invalid sign-in return")
	}
	for _, r := range u.Path {
		if unicode.IsControl(r) {
			return "", apierr.BadRequest("invalid_return", "invalid sign-in return")
		}
	}
	return raw, nil
}

type LoginResult struct {
	UserID        uuid.UUID
	AppAuthEpoch  int64
	MFAVerifiedAt time.Time
	Next          string
	// PortalURL is trusted server-side flow state, captured before the IdP redirect.
	PortalURL string
}
