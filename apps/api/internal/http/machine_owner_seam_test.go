package http

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/machineauth"
)

// ⛔ THE OWED RED FROM S15.1a, AND IT IS OWED FOR A REASON.
//
// 1a shipped the seam refusal at machine_bearer.go and mutation-testing reported honestly that REMOVING IT
// STILL PASSED — the constructor caught the case. The backstop worked, which meant the seam arm was a line
// nobody had shown could fail.
//
// > **A GUARD THAT HAS ONLY EVER PASSED IS INDISTINGUISHABLE FROM ONE THAT DOES NOTHING.**
//
// This exercises the seam ITSELF against a row whose owner is NULL, so the arm has its own red. The two are
// not redundant: the seam check makes the ROW impossible to use, the constructor makes the PRINCIPAL
// impossible to build wrong. Each needs its own proof.

type stubMachineQ struct {
	cred    sqlc.MachineCredential
	touched *int
	// D23: the owner's standing. Zero value = a live, in-org owner, so every pre-existing case in this
	// file keeps meaning what it meant.
	ownerGone        bool
	ownerDeactivated bool
	ownerOutOfOrg    bool
}

func (s stubMachineQ) GetMachineCredentialByHash(_ context.Context, _ []byte) (sqlc.MachineCredential, error) {
	return s.cred, nil
}
func (s stubMachineQ) TouchMachineCredentialUsed(_ context.Context, _ uuid.UUID) error {
	if s.touched != nil {
		*s.touched++
	}
	return nil
}

func (s stubMachineQ) GetMachineOwnerStanding(_ context.Context, _ uuid.UUID) (bool, error) {
	if s.ownerGone {
		return false, pgx.ErrNoRows // soft-deleted: users are read deleted_at IS NULL
	}
	return !s.ownerDeactivated, nil
}

func req(tok string) *http.Request {
	r := httptest.NewRequest("GET", "/api/v1/whatever", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	return r
}

func TestSeamRefusesAnUnassignedMachineCredential(t *testing.T) {
	tok := machineauth.TokenPrefix + "abc"
	base := sqlc.MachineCredential{ID: uuid.New(), OrgID: uuid.New(), Name: "gitops", Role: "operator"}

	// RED — owner NULL. The seam must refuse, with the same nil,nil shape as unknown/revoked (no oracle).
	unassigned := base
	unassigned.UserID = pgtype.UUID{Valid: false}
	var touched int
	if p, err := MachineAuth(stubMachineQ{cred: unassigned, touched: &touched})(req(tok)); p != nil || err != nil {
		t.Fatalf("an UNASSIGNED machine credential authenticated: principal=%+v err=%v", p, err)
	}

	// ⛔ THE ASSERTION THAT BELONGS TO THE SEAM ARM ALONE — the reason this test exists.
	//
	// Refusing to BUILD the principal is the constructor'''s job, and it happens with the arm deleted; that is
	// exactly what S15.1a'''s third mutation showed. The arm'''s own observable effect is that it returns BEFORE
	// the telemetry write, so an unassigned credential is never recorded as USED. Without this line the arm
	// has no independent red and the two guards are one assertion wearing two hats.
	if touched != 0 {
		t.Fatalf("an unassigned credential was stamped as used %d time(s) — the seam arm did not short-circuit", touched)
	}

	// AND THE OTHER DIRECTION — an owned credential still authenticates. A seam that refuses everything
	// passes the red above and breaks every machine principal in the product.
	owned := base
	owned.UserID = pgtype.UUID{Bytes: uuid.New(), Valid: true}
	var touchedOwned int
	p, err := MachineAuth(stubMachineQ{cred: owned, touched: &touchedOwned})(req(tok))
	if err != nil || p == nil {
		t.Fatalf("an OWNED machine credential was refused at the seam: err=%v", err)
	}
	if p.OwnerUserID == uuid.Nil {
		t.Fatal("the seam built a principal without carrying the owner")
	}
	// And an OWNED credential IS stamped — otherwise "not stamped" would be trivially true for everything.
	if touchedOwned != 1 {
		t.Fatalf("an owned credential was stamped %d time(s), want 1", touchedOwned)
	}
}

// ⛔ D23 (RULED) — THE BINDING WAS A COLUMN, NOT A CONTROL.
//
// ⚠ ONE STATE, DELIBERATELY. An earlier draft also refused removed-from-org and carried a fixture for it;
// the ruling removed both, because the exposed offboarding is DEACTIVATION and it preserves the membership
// row — so that arm could never have fired. A guard for an unreachable state is dormant machinery, and a
// test for it is a green that proves nothing.
//
// MachineAuth checked that `user_id` was SET and never that the person behind it was still accountable, so
// a credential outlived its owner's deactivation, soft-deletion or removal from the organization —
// indefinitely. D14 bound credentials to humans SO THAT accountability exists; a binding nothing re-reads
// at use is the ruling with its point removed.
//
// ⚠ REDS BOTH DIRECTIONS. A refusal with no permitted case would be indistinguishable from a broken seam,
// and the permitted case is asserted FIRST so a later failure cannot be read as "machine auth is down".
func TestSeamRefusesACredentialWhoseOwnerIsNoLongerAccountable(t *testing.T) {
	tok := machineauth.TokenPrefix + "abc"
	live := sqlc.MachineCredential{
		ID: uuid.New(), OrgID: uuid.New(), Name: "gitops", Role: "operator",
		UserID: pgtype.UUID{Bytes: [16]byte(uuid.New()), Valid: true},
	}

	// ── THE PERMITTED CASE: an active owner, still in the org, still authenticates.
	var touched int
	p, err := MachineAuth(stubMachineQ{cred: live, touched: &touched})(req(tok))
	if err != nil || p == nil {
		t.Fatalf("⛔ an ACTIVE owner's credential was refused — GitOps is down for everyone: p=%+v err=%v", p, err)
	}
	if !p.IsMachine() || p.OwnerUserID == uuid.Nil {
		t.Fatalf("the principal lost its machine identity or its owner: %+v", p)
	}

	// ── THE THREE REFUSALS. Each is a state a person can be in that ends their accountability.
	for _, tc := range []struct {
		who   string
		store stubMachineQ
	}{
		{"a DEACTIVATED owner — the state SessionAuth and the CLI bearer already refuse for humans",
			stubMachineQ{cred: live, ownerDeactivated: true}},
		{"a SOFT-DELETED owner — no user row at all",
			stubMachineQ{cred: live, ownerGone: true}},
	} {
		p, err := MachineAuth(tc.store)(req(tok))
		if p != nil || err != nil {
			t.Errorf("⛔ A CREDENTIAL OWNED BY %s STILL AUTHENTICATED: principal=%+v err=%v\n\n"+
				"An offboarded employee's GitOps operator keeps mutating this organization until somebody "+
				"remembers the credential exists.", tc.who, p, err)
		}
	}

	// ⛔ AND THE REFUSAL CARRIES NO ORACLE. Every arm returns the same (nil, nil) as unknown and revoked:
	// "your owner was deactivated" would tell whoever holds a stolen token something about a person.
	if _, err := MachineAuth(stubMachineQ{cred: live, ownerDeactivated: true})(req(tok)); err != nil {
		t.Error("the owner-standing refusal is distinguishable from unknown/revoked at the wire")
	}
}
