package aigateway

import (
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/testpostgres"
	"slices"
	"testing"
)

func TestUserGroupModelAccess(t *testing.T) {
	ctx, pool := testpostgres.New(t)
	f := newPolicyFixture(t, ctx, pool)
	engine := newProviderFixtureEngine()
	f.policies.engine = engine
	f.policies.EnableProviderManagement(true)
	secret := "fixture-provider-secret"
	p, err := f.policies.CreateProvider(ctx, f.org, f.owner, ProviderInput{Provider: "openrouter", Name: "Engineering provider", Models: []string{"openrouter/engineering"}, Secret: &secret, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	group := uuid.New()
	f.exec(`INSERT INTO user_groups(id,org_id,name) VALUES($1,$2,'Engineering')`, group, f.org)
	users := []uuid.UUID{uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()}
	for i, user := range users {
		f.exec(`INSERT INTO users(id,email,name,email_verified_at) VALUES($1,$2,'Engineer',now())`, user, user.String()+"@test.local")
		f.exec(`INSERT INTO memberships(org_id,user_id,role) VALUES($1,$2,'member')`, f.org, user)
		if i < 4 {
			f.exec(`INSERT INTO group_members(org_id,group_id,user_id) VALUES($1,$2,$3)`, f.org, group, user)
		}
	}
	g, err := f.policies.PutUserModelGrant(ctx, f.org, f.owner, group, p.ID, "openrouter/engineering", true, 0)
	if err != nil || g.Status != "applied" {
		t.Fatalf("grant: %v %v", g, err)
	}
	if _, err := OpenKey(f.policies.sealer, f.org, g.ID, g.native, g.bindingRevision, g.sealed); err == nil {
		t.Fatal("human group key accepted in agent envelope")
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ids, err := bindingUsageIDs(ctx, tx, f.org, nil, nil)
	if err != nil || len(ids) != 1 || ids[0] != g.native {
		t.Fatal("human usage missing", err)
	}
	filtered, err := bindingUsageIDs(ctx, tx, f.org, &f.team, nil)
	if err != nil || len(filtered) != 0 {
		t.Fatal("human usage attributed to agent team", err)
	}
	rollbackAI(tx)

	for i, user := range users {
		grant, err := f.policies.ResolveUserModel(ctx, f.org, user, g.Model)
		if i < 4 && (err != nil || grant.VirtualKey == "") {
			t.Fatalf("Engineering member %d refused: %v", i, err)
		}
		if i == 4 && err == nil {
			t.Fatal("outsider received access")
		}
	}
	if _, err := f.policies.ResolveUserModel(ctx, f.org, f.owner, g.Model); err == nil {
		t.Fatal("org owner bypassed group grant")
	}
	f.exec(`DELETE FROM group_members WHERE org_id=$1 AND group_id=$2 AND user_id=$3`, f.org, group, users[0])
	if _, err := f.policies.ResolveUserModel(ctx, f.org, users[0], g.Model); err == nil {
		t.Fatal("removed member retained access")
	}
	if _, err := f.policies.ResolveUserModel(ctx, f.org, users[1], "openrouter/other"); err == nil {
		t.Fatal("ungranted model allowed")
	}
	if _, err := f.policies.ResolveUserModel(ctx, uuid.New(), users[1], g.Model); err == nil {
		t.Fatal("cross-tenant access allowed")
	}
	f.exec(`UPDATE users SET status='deactivated' WHERE id=$1`, users[1])
	if _, err := f.policies.ResolveUserModel(ctx, f.org, users[1], g.Model); err == nil {
		t.Fatal("deactivated user allowed")
	}
	f.exec(`UPDATE organizations SET ai_gateway_enabled=false WHERE id=$1`, f.org)
	if _, err := f.policies.ResolveUserModel(ctx, f.org, users[2], g.Model); err == nil {
		t.Fatal("disabled gateway allowed")
	}
	f.exec(`UPDATE organizations SET ai_gateway_enabled=true WHERE id=$1`, f.org)
	if err := f.policies.DeleteProvider(ctx, f.org, f.owner, p.ID, p.Revision); err == nil {
		t.Fatal("provider with active user grants deleted")
	}
	if _, err := f.policies.PutUserModelGrant(ctx, f.org, f.owner, group, p.ID, g.Model, false, 0); err == nil {
		t.Fatal("stale grant update accepted")
	}
	g, err = f.policies.PutUserModelGrant(ctx, f.org, f.owner, group, p.ID, g.Model, false, g.Revision)
	if err != nil || g.Status != "revoked" {
		t.Fatalf("revoke: %v %v", g, err)
	}
	if _, err := f.policies.ResolveUserModel(ctx, f.org, users[2], g.Model); err == nil {
		t.Fatal("revoked grant allowed")
	}
	engine.policyEngineFixture.fail = true
	g, err = f.policies.PutUserModelGrant(ctx, f.org, f.owner, group, p.ID, g.Model, true, g.Revision)
	if err != nil || g.Status != "error" {
		t.Fatalf("failed provisioning: %v %v", g, err)
	}
	if _, err := f.policies.ResolveUserModel(ctx, f.org, users[2], g.Model); err == nil {
		t.Fatal("failed provisioning conferred access")
	}
}

func TestDeletedUserGroupRetainsAccountingWithoutBlockingProvider(t *testing.T) {
	ctx, pool := testpostgres.New(t)
	f := newPolicyFixture(t, ctx, pool)
	engine := newProviderFixtureEngine()
	f.policies.engine = engine
	f.policies.EnableProviderManagement(true)
	secret := "fixture-provider-secret"
	p, err := f.policies.CreateProvider(ctx, f.org, f.owner, ProviderInput{Provider: "openrouter", Name: "Engineering provider", Models: []string{"openrouter/engineering"}, Secret: &secret, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	group := uuid.New()
	f.exec(`INSERT INTO user_groups(id,org_id,name) VALUES($1,$2,'Engineering')`, group, f.org)
	f.exec(`INSERT INTO group_members(org_id,group_id,user_id) VALUES($1,$2,$3)`, f.org, group, f.owner)
	f.exec(`UPDATE users SET email_verified_at=now() WHERE id=$1`, f.owner)
	g, err := f.policies.PutUserModelGrant(ctx, f.org, f.owner, group, p.ID, "openrouter/engineering", true, 0)
	if err != nil || g.Status != "applied" {
		t.Fatalf("grant: %+v %v", g, err)
	}
	if _, err := f.policies.ResolveUserModel(ctx, f.org, f.owner, g.Model); err != nil {
		t.Fatal("fixture member could not call model", err)
	}
	f.exec(`DELETE FROM user_groups WHERE org_id=$1 AND id=$2`, f.org, group)
	if _, err := f.policies.ResolveUserModel(ctx, f.org, f.owner, g.Model); err == nil {
		t.Fatal("deleted group retained access before reconciliation")
	}
	// Orphan grants cease to be active provider references immediately, even
	// before the background worker has disabled their private native key.
	p, err = f.policies.UpdateProvider(ctx, f.org, f.owner, p.ID, ProviderInput{Provider: "openrouter", Name: p.Name, Models: []string{"openrouter/replacement"}, Enabled: true}, p.Revision)
	if err != nil {
		t.Fatal("deleted group blocked model removal", err)
	}
	if err := f.policies.DeleteProvider(ctx, f.org, f.owner, p.ID, p.Revision); err != nil {
		t.Fatal("deleted group blocked provider deletion", err)
	}
	engine.policyEngineFixture.fail = true
	failed, err := f.policies.ReconcileUserGrant(ctx, f.org, g.ID)
	if err != nil || failed.Status != "error" || failed.Enabled || failed.GroupID != nil {
		t.Fatalf("failed native revoke lost desired revocation: %+v %v", failed, err)
	}
	engine.policyEngineFixture.fail = false
	if err := f.policies.ReconcilePending(ctx, 64); err != nil {
		t.Fatal("worker did not recover native revoke", err)
	}
	retained, err := scanUserGrant(pool.QueryRow(ctx, `SELECT `+userGrantColumns+` FROM ai_user_model_grants WHERE org_id=$1 AND id=$2`, f.org, g.ID))
	if err != nil || retained.Status != "revoked" || retained.Enabled || retained.GroupID != nil || retained.native != g.native || retained.sealed != g.sealed || retained.bindingRevision != g.bindingRevision || retained.AppliedRevision != retained.Revision {
		t.Fatalf("revocation lost retained accounting: %+v %v", retained, err)
	}
	if engine.active[g.native] {
		t.Fatal("worker left orphan native key active")
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackAI(tx)
	ids, err := bindingUsageIDs(ctx, tx, f.org, nil, nil)
	if err != nil || !slices.Contains(ids, g.native) {
		t.Fatal("deleted group disappeared from historical usage", err)
	}
}

func TestScopedTeamReconcileDoesNotReconcileOtherOrgUserGrants(t *testing.T) {
	ctx, pool := testpostgres.New(t)
	a, b := newPolicyFixture(t, ctx, pool), newPolicyFixture(t, ctx, pool)
	engine := newProviderFixtureEngine()
	a.policies.engine, b.policies.engine = engine, engine
	b.policies.EnableProviderManagement(true)
	secret := "fixture-provider-secret"
	p, err := b.policies.CreateProvider(ctx, b.org, b.owner, ProviderInput{Provider: "openrouter", Name: "Other organization", Models: []string{"openrouter/engineering"}, Secret: &secret, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	group := uuid.New()
	b.exec(`INSERT INTO user_groups(id,org_id,name) VALUES($1,$2,'Engineering')`, group, b.org)
	engine.policyEngineFixture.fail = true
	g, err := b.policies.PutUserModelGrant(ctx, b.org, b.owner, group, p.ID, "openrouter/engineering", true, 0)
	if err != nil || g.Status != "error" {
		t.Fatalf("fixture pending grant: %+v %v", g, err)
	}
	engine.policyEngineFixture.fail = false
	if err := a.policies.ReconcileTeam(ctx, a.org, a.team, 16); err != nil {
		t.Fatal("requested team's reconciliation failed", err)
	}
	untouched, err := scanUserGrant(pool.QueryRow(ctx, `SELECT `+userGrantColumns+` FROM ai_user_model_grants WHERE org_id=$1 AND id=$2`, b.org, g.ID))
	if err != nil || untouched.Status != "error" || untouched.native != "" || untouched.AppliedRevision != 0 {
		t.Fatalf("team write reconciled another organization's grant: %+v %v", untouched, err)
	}
	if len(engine.keys) != 1 {
		t.Fatal("team write created an unrelated native key")
	}
	// The dedicated global worker still performs the authorized pending work.
	if err := a.policies.ReconcilePending(ctx, 64); err != nil {
		t.Fatal(err)
	}
	recovered, err := scanUserGrant(pool.QueryRow(ctx, `SELECT `+userGrantColumns+` FROM ai_user_model_grants WHERE org_id=$1 AND id=$2`, b.org, g.ID))
	if err != nil || recovered.Status != "applied" || recovered.native == "" {
		t.Fatalf("global worker did not recover grant: %+v %v", recovered, err)
	}
}
