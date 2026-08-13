package auth

import (
	"os"
	"strings"
	"testing"
)

// ⛔ THE TWO ADMISSION PATHS MUST SURVIVE SIGNUP CLOSING, AND NEITHER GOES THROUGH IT.
//
// This is a SOURCE assertion, deliberately: the property is that these paths do not DEPEND on
// `auth.Signup`, and a runtime test would prove one scenario while the dependency is what matters.
//
//	· /api/v1/auth/invitations/accept is `security: []` and calls CreateUser ITSELF — being invited IS the
//	  admission and the account is only the credential. An invited user's first sign-in is: click the link,
//	  set a password, land inside. They never see a signup form and never needed one.
//	· SSO domain capture creates the user on the CALLBACK (LinkCreate) and never touches this package.
//
// ⚠ SO CLOSING SIGNUP DOES NOT KILL DOMAIN CAPTURE — the question that had to be answered before shipping.
// A captured user arrives through their IdP; the account is minted by the callback, and capture then joins
// them to the claiming org.
func TestAdmissionPathsDoNotDependOnSignup(t *testing.T) {
	for _, tc := range []struct{ file, mustCall string }{
		{"../invites/invites.go", "CreateUser"},
		{"../sso/service.go", "LinkCreate"},
	} {
		b := mustRead(t, tc.file)
		if !strings.Contains(b, tc.mustCall) {
			t.Errorf("⛔ %s no longer mints its own account (%s missing). If it now routes through "+
				"auth.Signup, closing signup after setup has silently broken the only two ways anyone "+
				"can join a set-up deployment.", tc.file, tc.mustCall)
		}
		// ⛔ AND IT MUST NOT CALL Signup. That is the dependency this whole change rests on.
		if strings.Contains(b, ".Signup(") {
			t.Errorf("⛔ %s CALLS auth.Signup — which refuses `signup_closed` on any set-up deployment. "+
				"Invitations and domain capture would both stop working the moment the first org exists.",
				tc.file)
		}
	}
}

func mustRead(t *testing.T, p string) string {
	t.Helper()
	raw, err := os.ReadFile(p)
	b := string(raw)
	if err != nil {
		t.Fatalf("⛔ cannot read %s — this guard is checking nothing: %v", p, err)
	}
	return b
}
