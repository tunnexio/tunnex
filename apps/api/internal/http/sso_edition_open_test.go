package http

import (
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/licence"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

// TestGetSsoConfigEditionGatedInOpenBuild proves the SSO-config READ endpoint is
// edition-enforced SERVER-side in the open build (not merely hidden in the UI):
// an authenticated, authorized owner still gets 403 edition_required because the
// SSO port is nil. authorize() runs first (so a sessionless request 401s — the
// spec walk stays honest); the edition gate fires for authenticated callers.
func TestGetSsoConfigEditionGatedInOpenBuild(t *testing.T) {
	s := apiServer{} // open build: sso port is nil
	org := uuid.New()
	ctx := principalWithRole(org, rbac.RoleOwner) // authed + verified owner
	_, err := s.GetSsoConfig(ctx, api.GetSsoConfigRequestObject{OrgId: org, Provider: "google"})
	if !hasCode(err, 403, "edition_required") {
		t.Fatalf("open-build GetSsoConfig: want 403 edition_required, got %v", err)
	}
}

// ⭐ THE GAP THIS TEST NAMED IS CLOSED (S12.1 slice 8), AND THE ASSERTION MOVED WITH IT.
//
// It used to assert the port was wired AND that nothing gated it — an honest description of an
// intermediate state. Both halves now hold at once: the port is wired for every deployment, because there
// is one binary, and the licence decides what it will do.
//
// ⚠ The refusal is 403 edition_required either way, which is why the OLD open-build test above still
// passes unchanged. That is not the code being untouched — the CAUSE moved from "the port is nil" to "the
// licence does not grant SSO", and only the census can tell those apart.
func TestSSOPortIsWiredAndGatedByLicence(t *testing.T) {
	if NewSSOPort(nil, nil, nil, "", nil, slog.Default()) == nil {
		t.Fatal("the SSO port must be wired in the single binary")
	}
	// ⛔ Community configures nothing.
	if (apiServer{licence: &licence.Manager{}}).requireSSOAdmin() == nil {
		t.Error("⛔ SSO IS FREE — an unlicensed deployment can configure an IdP")
	}
	if (apiServer{licence: licence.NewTestManager("starter", time.Now().Add(time.Hour))}).requireSSOAdmin() != nil {
		t.Error("a valid Starter licence was refused SSO configuration")
	}
	// ⭐ AND THE HALF THAT MUST NEVER BE GATED, asserted as an ABSENCE: no licence check exists on the
	// login path, so an org whose only identity source is its IdP can always reach its own console.
	src, err := os.ReadFile("sso_handlers.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(src)
	start := strings.Index(body, "func (s apiServer) StartSsoLogin")
	end := strings.Index(body, "func (s apiServer) SetSsoConfig")
	if start < 0 || end < 0 || end < start {
		t.Fatal("⛔ could not locate the login handlers — this guard is scanning nothing")
	}
	if strings.Contains(body[start:end], "requireSSOAdmin") {
		t.Error("⛔ THE SSO LOGIN PATH IS NOW LICENCE-GATED. An org that signs in only through Google or " +
			"Entra is locked out of its own console — including the screen where a licence is renewed. " +
			"A licence state must never delete the remedy along with the capability.")
	}
}

func contains(h []byte, s string) bool {
	for i := 0; i+len(s) <= len(h); i++ {
		if string(h[i:i+len(s)]) == s {
			return true
		}
	}
	return false
}
