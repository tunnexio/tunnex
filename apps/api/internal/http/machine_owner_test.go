package http

import (
	"testing"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
)

// ⛔ THE TWO REDS D14/D19 REQUIRE, AND THEY ARE TWO ON PURPOSE.
//
// A guard that refuses everything passes the first red and is not a guard. `A count used as a guard must count
// what it guards against` — so the accept case is asserted beside the refuse case, never inferred from it.
func TestMachinePrincipalRequiresAnOwner(t *testing.T) {
	orgID, machineID, owner := uuid.New(), uuid.New(), uuid.New()

	// RED 1 — a machine credential with NO owner cannot become a principal. This is the grandfather clause
	// being refused: user_id is nullable for the length of the migration, and a nullable owner IS the clause
	// unless something refuses it.
	if p := authctx.NewMachinePrincipal(uuid.Nil, machineID, orgID, "gitops", "operator", ""); p != nil {
		t.Fatalf("a machine principal was built WITHOUT an owner: %+v", p)
	}

	// RED 2 — an OWNED credential is still ACCEPTED. Without this, a constructor that always returned nil
	// would pass red 1 and break every machine principal in the product.
	p := authctx.NewMachinePrincipal(owner, machineID, orgID, "gitops", "operator", "")
	if p == nil {
		t.Fatal("an OWNED machine credential was refused — the guard refuses everything")
	}
	if p.OwnerUserID != owner {
		t.Fatalf("owner not carried: got %v want %v", p.OwnerUserID, owner)
	}
	if !p.IsMachine() {
		t.Fatal("an owned machine principal does not report IsMachine")
	}
	if p.AuthMethod != authctx.AuthMachine {
		t.Fatalf("AuthMethod = %q, want %q", p.AuthMethod, authctx.AuthMachine)
	}
	if p.Roles[orgID] != "operator" {
		t.Fatalf("role not carried for the org: %+v", p.Roles)
	}
}
