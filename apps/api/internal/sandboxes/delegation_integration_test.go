package sandboxes

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
	"testing"
	"time"
)

func delegationFixture(t *testing.T) (fixture, context.Context, context.Context, Delegation) {
	t.Helper()
	f := newFixture(t)
	if _, err := f.pool.Exec(f.ctx, `UPDATE memberships SET role='owner',roles=ARRAY['owner'] WHERE org_id=$1 AND user_id=$2`, f.org, f.user); err != nil {
		t.Fatal(err)
	}
	human := authctx.WithPrincipal(f.ctx, &authctx.Principal{UserID: f.user, Roles: map[uuid.UUID]string{f.org: rbac.RoleOwner}, EmailVerified: true})
	machine := uuid.New()
	if _, err := f.pool.Exec(f.ctx, `INSERT INTO machine_credentials(id,org_id,user_id,name,token_hash,fingerprint) VALUES($1,$2,$3,'fixture',$4,'fixture')`, machine, f.org, f.user, []byte(machine.String())); err != nil {
		t.Fatal(err)
	}
	ctx := authctx.WithPrincipal(f.ctx, authctx.NewMachinePrincipal(f.user, machine, f.org, "fixture", rbac.RoleOperator, ""))
	d := Delegation{OrgID: f.org, OwnerID: f.user, MachineID: machine, TemplateID: f.template, MaxTTLSeconds: 900, MaxActive: 1, MaximumScope: f.input("x").Requested, ExpiresAt: time.Now().Add(time.Hour)}
	if _, err := f.store.IssueDelegation(human, f.org, f.user, d); !errors.Is(err, ErrDisabled) {
		t.Fatalf("default opt-in: %v", err)
	}
	if err := f.store.SetDelegationEnabled(human, f.org, f.user, true); err != nil {
		t.Fatal(err)
	}
	var err error
	d, err = f.store.IssueDelegation(human, f.org, f.user, d)
	if err != nil {
		t.Fatal(err)
	}
	return f, human, ctx, d
}
func TestDelegatedSandboxLifecyclePostgres(t *testing.T) {
	f, human, ctx, d := delegationFixture(t)
	in := f.input("delegated")
	in.TTLSeconds = 900
	first, replay, err := f.store.Create(ctx, f.org, f.user, in)
	if err != nil || replay {
		t.Fatalf("create: %v %v", replay, err)
	}
	again, replay, err := f.store.Create(ctx, f.org, f.user, in)
	if err != nil || !replay || again.Identity != first.Identity {
		t.Fatalf("replay: %v %v", replay, err)
	}
	if _, err = f.store.Get(ctx, f.org, f.user, first.Identity.ID); err != nil {
		t.Fatal(err)
	}
	changed := in
	changed.Name = "changed"
	if _, _, err = f.store.Create(ctx, f.org, f.user, changed); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed replay: %v", err)
	}
	stopped, err := f.store.SetDesired(ctx, f.org, f.user, first.Identity.ID, first.Revision, "stopped")
	if err != nil || stopped.Revision != first.Revision+1 {
		t.Fatalf("generation: %v", err)
	}
	if _, err = f.store.SetDesired(ctx, f.org, f.user, first.Identity.ID, first.Revision, "started"); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale generation: %v", err)
	}
	next := in
	next.IdempotencyKey = "next"
	if _, _, err = f.store.Create(ctx, f.org, f.user, next); !errors.Is(err, ErrQuota) {
		t.Fatalf("quota: %v", err)
	}
	var actor *string
	var metadata []byte
	if err = f.pool.QueryRow(f.ctx, `SELECT actor_system,metadata FROM audit_logs WHERE action='sandbox.create' AND target_id=$1`, first.Identity.ID.String()).Scan(&actor, &metadata); err != nil || actor == nil || *actor != "operator:fixture" {
		t.Fatalf("machine audit: %v", err)
	}
	if err = f.store.RevokeDelegation(human, f.org, f.user, d.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err = f.store.Create(ctx, f.org, f.user, in); !errors.Is(err, ErrForbidden) {
		t.Fatalf("revoked replay: %v", err)
	}
	if _, err = f.store.Get(ctx, f.org, f.user, first.Identity.ID); !errors.Is(err, ErrForbidden) {
		t.Fatalf("revoked connection/read: %v", err)
	}
	if _, err = f.store.SetDesired(ctx, f.org, f.user, first.Identity.ID, stopped.Revision, "started"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("revoked start: %v", err)
	}
	withdrawn, err := f.store.Get(human, f.org, f.user, first.Identity.ID)
	if err != nil || withdrawn.DesiredState != "deleted" || withdrawn.State == StateDeleted || withdrawn.Revision != stopped.Revision+1 {
		t.Fatalf("revocation pending cleanup: %+v %v", withdrawn, err)
	}
	if _, err = f.store.SetDesired(human, f.org, f.user, first.Identity.ID, withdrawn.Revision, "deleted"); err != nil {
		t.Fatalf("owner cleanup: %v", err)
	}
}
func TestDelegatedSandboxEscalationPostgres(t *testing.T) {
	f, human, ctx, d := delegationFixture(t)
	in := f.input("escape")
	in.TTLSeconds = 900
	for _, change := range []func(*CreateInput){func(v *CreateInput) { v.TTLSeconds = 901 }, func(v *CreateInput) { v.TemplateID = uuid.New() }, func(v *CreateInput) { v.Requested = []Scope{{CIDR: "0.0.0.0/0", Protocol: "any"}} }, func(v *CreateInput) { v.SelectedSkills = []SkillSelection{{RevisionID: uuid.New()}} }} {
		v := in
		change(&v)
		if _, _, err := f.store.Create(ctx, f.org, f.user, v); err == nil {
			t.Fatal("escalation accepted")
		}
	}
	if _, _, err := f.store.Create(ctx, f.org, f.other, in); !errors.Is(err, ErrForbidden) {
		t.Fatalf("cross owner: %v", err)
	}
	if _, _, err := f.store.Create(ctx, uuid.New(), f.user, in); !errors.Is(err, ErrForbidden) {
		t.Fatalf("cross org: %v", err)
	}
	node := authctx.WithPrincipal(f.ctx, authctx.NewAgentPrincipal(uuid.New(), f.org, "node", rbac.RoleAgent, f.user, ""))
	if _, _, err := f.store.Create(node, f.org, f.user, in); !errors.Is(err, ErrForbidden) {
		t.Fatalf("node agent: %v", err)
	}
	humanIn := in
	humanIn.IdempotencyKey = "human"
	v, _, err := f.store.Create(human, f.org, f.user, humanIn)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.store.Get(ctx, f.org, f.user, v.Identity.ID); !errors.Is(err, ErrForbidden) {
		t.Fatalf("human sandbox read: %v", err)
	}
	if err = f.store.SetDelegationEnabled(ctx, f.org, f.user, true); !errors.Is(err, ErrForbidden) {
		t.Fatalf("machine opt-in: %v", err)
	}
	if err = f.store.RevokeDelegation(ctx, f.org, f.user, d.ID); !errors.Is(err, ErrForbidden) {
		t.Fatalf("machine revoke: %v", err)
	}
	if _, err = f.pool.Exec(f.ctx, `UPDATE machine_credentials SET revoked_at=now() WHERE id=$1`, d.MachineID); err != nil {
		t.Fatal(err)
	}
	if _, _, err = f.store.Create(ctx, f.org, f.user, in); !errors.Is(err, ErrForbidden) {
		t.Fatalf("credential revocation: %v", err)
	}
}

func TestDelegatedSandboxExpiryOwnerStandingAndOptOutPostgres(t *testing.T) {
	for _, scenario := range []string{"grant-expiry", "owner-reassigned", "membership-removed", "org-opt-out"} {
		t.Run(scenario, func(t *testing.T) {
			f, _, ctx, d := delegationFixture(t)
			in := f.input("standing")
			in.TTLSeconds = 900
			v, _, err := f.store.Create(ctx, f.org, f.user, in)
			if err != nil {
				t.Fatal(err)
			}
			token := bindDelegatedRuntime(t, f, v)
			var query string
			var args []any
			switch scenario {
			case "grant-expiry":
				query = `UPDATE sandbox_delegations SET expires_at=created_at+interval '1 microsecond' WHERE id=$1`
				args = []any{d.ID}
			case "owner-reassigned":
				query = `UPDATE machine_credentials SET user_id=$2 WHERE id=$1`
				args = []any{d.MachineID, f.other}
			case "membership-removed":
				query = `DELETE FROM memberships WHERE org_id=$1 AND user_id=$2`
				args = []any{f.org, f.user}
			case "org-opt-out":
				query = `UPDATE organizations SET sandbox_delegation_enabled=false WHERE id=$1`
				args = []any{f.org}
			}
			if _, err = f.pool.Exec(f.ctx, query, args...); err != nil {
				t.Fatal(err)
			}
			if _, err = f.store.AuthenticateRuntime(f.ctx, token); !errors.Is(err, ErrRuntimeUnauthorized) {
				t.Fatalf("runtime standing denial: %v", err)
			}
			if _, err = f.store.Get(ctx, f.org, f.user, v.Identity.ID); !errors.Is(err, ErrForbidden) {
				t.Fatalf("standing read: %v", err)
			}
			if _, _, err = f.store.Create(ctx, f.org, f.user, in); !errors.Is(err, ErrForbidden) {
				t.Fatalf("standing replay: %v", err)
			}
			if err = f.store.SweepDelegations(f.ctx, f.org, 2); err != nil {
				t.Fatal(err)
			}
			var desired string
			var generation int64
			var observed State
			if err = f.pool.QueryRow(f.ctx, `SELECT desired_state,generation,observed_state FROM sandboxes WHERE id=$1`, v.Identity.ID).Scan(&desired, &generation, &observed); err != nil || desired != "deleted" || generation != v.Revision+1 || observed == StateDeleted {
				t.Fatalf("eventual withdrawal: %s %d %s %v", desired, generation, observed, err)
			}
			if err = f.store.SweepDelegations(f.ctx, f.org, 2); err != nil {
				t.Fatal(err)
			}
			if err = f.pool.QueryRow(f.ctx, `SELECT generation FROM sandboxes WHERE id=$1`, v.Identity.ID).Scan(&generation); err != nil || generation != v.Revision+1 {
				t.Fatal("repeated sweep advanced generation", err)
			}

		})
	}
}

func TestDelegatedRevocationOnlyOwnedInstancesAndCleanupPostgres(t *testing.T) {
	f, human, ctx, d := delegationFixture(t)
	in := f.input("withdraw")
	in.TTLSeconds = 900
	delegated, _, err := f.store.Create(ctx, f.org, f.user, in)
	if err != nil {
		t.Fatal(err)
	}
	humanInput := in
	humanInput.IdempotencyKey = "human-retained"
	humanSandbox, _, err := f.store.Create(human, f.org, f.user, humanInput)
	if err != nil {
		t.Fatal(err)
	}
	token := bindDelegatedRuntime(t, f, delegated)
	var peer uuid.UUID
	if err = f.pool.QueryRow(f.ctx, `SELECT peer_id FROM sandboxes WHERE id=$1`, delegated.Identity.ID).Scan(&peer); err != nil {
		t.Fatal(err)
	}
	if err = f.store.RevokeDelegation(human, f.org, f.user, d.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = f.store.AuthenticateRuntime(f.ctx, token); !errors.Is(err, ErrRuntimeUnauthorized) {
		t.Fatalf("revoked runtime: %v", err)
	}
	after, err := f.store.Get(human, f.org, f.user, humanSandbox.Identity.ID)
	if err != nil || after.Revision != humanSandbox.Revision || after.DesiredState != "started" {
		t.Fatalf("human sandbox touched: %v", err)
	}
	var generation int64
	var count int
	if err = f.pool.QueryRow(f.ctx, `SELECT generation FROM sandboxes WHERE id=$1`, delegated.Identity.ID).Scan(&generation); err != nil || generation != delegated.Revision+1 {
		t.Fatal("withdrawal generation", err)
	}
	if err = f.store.RevokeDelegation(human, f.org, f.user, d.ID); err != nil {
		t.Fatal(err)
	}
	if err = f.pool.QueryRow(f.ctx, `SELECT count(*) FROM audit_logs WHERE action='sandbox.delegation_withdraw' AND target_id=$1`, delegated.Identity.ID.String()).Scan(&count); err != nil || count != 1 {
		t.Fatal("withdrawal duplicated", err)
	}
	ids, err := f.store.PendingCleanup(f.ctx, 100)
	if err != nil || len(ids) != 1 || ids[0] != delegated.Identity.ID {
		t.Fatalf("pending cleanup %v %v", ids, err)
	}
	p := &cleanupProvider{exists: true, running: true}
	offline := errors.New("runner offline")
	if err = f.store.ReconcileCleanup(f.ctx, delegated.Identity.ID, p, cleanupNetworkFunc(func(context.Context, Sandbox) (Withdrawal, error) { return Withdrawal{}, offline })); !errors.Is(err, offline) || p.deletes != 0 {
		t.Fatalf("offline premature deletion: %v", err)
	}
	var address *string
	if err = f.pool.QueryRow(f.ctx, `SELECT assigned_ip FROM devices WHERE id=$1`, peer).Scan(&address); err != nil || address == nil {
		t.Fatal("offline allocation recycled", err)
	}
	if err = f.store.ReconcileCleanup(f.ctx, delegated.Identity.ID, p, cleanupNetworkFunc(func(_ context.Context, v Sandbox) (Withdrawal, error) { return matchingWithdrawal(v), nil })); err != nil {
		t.Fatal(err)
	}
	after, err = f.store.Get(human, f.org, f.user, delegated.Identity.ID)
	if err != nil || after.State != StateDeleted || p.deletes != 1 {
		t.Fatalf("qualified cleanup: %v", err)
	}
}
func bindDelegatedRuntime(t *testing.T, f fixture, v Sandbox) string {
	t.Helper()
	peer := bindCleanupPeer(t, f, v)
	raw := make([]byte, 32)
	raw[0] = 1
	token := "tnx_sandbox_runtime_" + base64.RawURLEncoding.EncodeToString(raw)
	hash := sha256.Sum256([]byte(token))
	if _, err := f.pool.Exec(f.ctx, `INSERT INTO sandbox_runtime_credentials(org_id,sandbox_id,peer_id,token_hash) VALUES($1,$2,$3,$4)`, f.org, v.Identity.ID, peer, hash[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.AuthenticateRuntime(f.ctx, token); err != nil {
		t.Fatalf("delegated runtime authentication: %v", err)
	}
	return token
}
func TestDelegatedRevocationFencesExternalStartPostgres(t *testing.T) {
	f, human, ctx, d := delegationFixture(t)
	in := f.input("external-start")
	in.TTLSeconds = 900
	v, _, err := f.store.Create(ctx, f.org, f.user, in)
	if err != nil {
		t.Fatal(err)
	}
	p := &runningProvider{}
	if err = f.store.ReconcileQuarantinedStart(f.ctx, v.Identity.ID, p); err != nil {
		t.Fatal(err)
	}
	p.afterStart = func() {
		if err := f.store.RevokeDelegation(human, f.org, f.user, d.ID); err != nil {
			t.Fatal(err)
		}
	}
	if err = f.store.StartBoundRuntime(f.ctx, v.Identity.ID, p); !errors.Is(err, ErrConflict) || p.stops != 1 || p.status.Running {
		t.Fatalf("revocation lost external-start race: %v", err)
	}
	current, err := f.store.Get(human, f.org, f.user, v.Identity.ID)
	if err != nil || current.DesiredState != "deleted" || current.Revision != v.Revision+1 {
		t.Fatalf("withdrawal lost: %v", err)
	}
}
func TestDelegatedExpiryFencesExternalStartBeforeSweepPostgres(t *testing.T) {
	f, human, ctx, d := delegationFixture(t)
	in := f.input("expiry-start")
	in.TTLSeconds = 900
	v, _, err := f.store.Create(ctx, f.org, f.user, in)
	if err != nil {
		t.Fatal(err)
	}
	p := &runningProvider{}
	if err = f.store.ReconcileQuarantinedStart(f.ctx, v.Identity.ID, p); err != nil {
		t.Fatal(err)
	}
	p.afterStart = func() {
		if _, err := f.pool.Exec(f.ctx, `UPDATE sandbox_delegations SET expires_at=created_at+interval '1 microsecond' WHERE id=$1`, d.ID); err != nil {
			t.Fatal(err)
		}
	}
	if err = f.store.StartBoundRuntime(f.ctx, v.Identity.ID, p); !errors.Is(err, ErrForbidden) || p.stops != 1 || p.status.Running {
		t.Fatalf("expiry lost external-start race: %v", err)
	}
	if err = f.store.SweepDelegations(f.ctx, f.org, 2); err != nil {
		t.Fatal(err)
	}
	current, err := f.store.Get(human, f.org, f.user, v.Identity.ID)
	if err != nil || current.DesiredState != "deleted" || current.Revision != v.Revision+1 {
		t.Fatalf("expiry cleanup lost: %v", err)
	}
}
func TestDelegatedRevocationDoesNotTouchOtherGrantPostgres(t *testing.T) {
	f, human, firstCtx, d := delegationFixture(t)
	in := f.input("first-grant")
	in.TTLSeconds = 900
	first, _, err := f.store.Create(firstCtx, f.org, f.user, in)
	if err != nil {
		t.Fatal(err)
	}
	secondMachine := uuid.New()
	if _, err = f.pool.Exec(f.ctx, `INSERT INTO machine_credentials(id,org_id,user_id,name,token_hash,fingerprint) VALUES($1,$2,$3,'second',$4,'second')`, secondMachine, f.org, f.user, []byte(secondMachine.String())); err != nil {
		t.Fatal(err)
	}
	secondGrant := d
	secondGrant.MachineID = secondMachine
	if _, err = f.store.IssueDelegation(human, f.org, f.user, secondGrant); err != nil {
		t.Fatal(err)
	}
	secondCtx := authctx.WithPrincipal(f.ctx, authctx.NewMachinePrincipal(f.user, secondMachine, f.org, "second", rbac.RoleOperator, ""))
	// The same caller key belongs to each existing machine identity independently.
	second, _, err := f.store.Create(secondCtx, f.org, f.user, in)
	if err != nil || second.Identity.ID == first.Identity.ID {
		t.Fatalf("machine idempotency namespace: %v", err)
	}
	if _, err = f.store.Get(firstCtx, f.org, f.user, second.Identity.ID); !errors.Is(err, ErrForbidden) {
		t.Fatalf("other grant read: %v", err)
	}
	if err = f.store.RevokeDelegation(human, f.org, f.user, d.ID); err != nil {
		t.Fatal(err)
	}
	after, err := f.store.Get(secondCtx, f.org, f.user, second.Identity.ID)
	if err != nil || after.DesiredState != "started" || after.Revision != second.Revision {
		t.Fatalf("other grant touched: %v", err)
	}
}
