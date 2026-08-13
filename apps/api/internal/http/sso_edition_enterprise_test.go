//go:build enterprise

package http

import (
	"log/slog"
	"testing"
)

// Enterprise build: SSO IS wired (NewSSOPort returns a real port), so the
// endpoints serve the flow instead of edition_required.
func TestSSOWiredInEnterpriseBuild(t *testing.T) {
	if NewSSOPort(nil, nil, nil, "", nil, slog.Default()) == nil {
		t.Fatal("enterprise build must wire the SSO port")
	}
}
