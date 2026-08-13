package http

import (
	"os"
	"strings"
	"testing"
)

// TestSignupGateIsKeyedOnUsersNotOrganizations — ⛔ THE ASSERTION THAT CATCHES A REVERT.
//
// The zero-user state cannot be reached on a shared database (`audit_logs` is append-only at the DB layer,
// so users cannot be cleared), which means no live test can drive the OPEN→CLOSED transition end to end.
// A source census can, and it checks the one thing that actually changed: WHICH QUESTION the public signup
// door asks.
//
//	SetupComplete       -> "has this deployment ever had an ORGANIZATION"  ← the race
//	PublicSignupOpen    -> "has this deployment ever had a USER"           ← the fix
//
// ⚠ A CENSUS OF SOURCE IS A WEAK INSTRUMENT AND IS USED HERE DELIBERATELY, because the alternative is no
// instrument at all. It is scoped to the Signup handler rather than the file, so unrelated uses of
// SetupComplete elsewhere do not make it fire — and so a revert INSIDE the handler cannot hide behind them.
func TestSignupGateIsKeyedOnUsersNotOrganizations(t *testing.T) {
	b, err := os.ReadFile("auth_handlers.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)

	start := strings.Index(src, "func (s apiServer) Signup(")
	if start < 0 {
		t.Fatal("Signup handler not found — this census is checking a file that no longer contains its subject")
	}
	end := strings.Index(src[start:], "\nfunc ")
	if end < 0 {
		end = len(src) - start
	}
	body := stripComments(src[start : start+end])

	if !strings.Contains(body, "PublicSignupOpen") {
		t.Fatal("the public signup door must ask PublicSignupOpen (has this deployment ever had a USER). " +
			"Without it, signup stays open from `docker compose up` until the first organization exists — " +
			"and a one-click installer makes that window a product feature.")
	}
	if strings.Contains(body, "SetupComplete") {
		t.Fatal("the Signup handler is gating on SetupComplete again — that asks whether an ORGANIZATION " +
			"exists, which is zero on a fresh install. That is the race: the bootstrap administrator is " +
			"already minted and a stranger can still sign up and claim the deployment.")
	}
}

// stripComments removes // lines before matching.
//
// ⛔ WITHOUT IT THIS CENSUS READS PROSE AS CODE. The handler's own comment EXPLAINS the race by naming
// SetupComplete — so the first run of this test failed on the sentence documenting the fix. A census that
// matches comments cannot tell "we do this" from "we deliberately stopped doing this", and the second is
// exactly what a good comment says. Recorded once already this cycle; recorded again here because the same
// instrument made the same mistake.
func stripComments(s string) string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "//") {
			continue
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}
