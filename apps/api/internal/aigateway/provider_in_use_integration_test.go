package aigateway

import (
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/testpostgres"
)

// AI-UX-1: deleting a provider credential that is in use lists the models, policies and agents that use
// it; an unused credential is deleted as before.
func TestAIProviderInUsePostgres(t *testing.T) {
	ctx, pool := testpostgres.New(t)
	f := newPolicyFixture(t, ctx, pool)
	other := newPolicyFixture(t, ctx, pool)
	f.policies.engine = newProviderFixtureEngine()
	f.policies.EnableProviderManagement(true)
	other.policies.engine = newProviderFixtureEngine()
	other.policies.EnableProviderManagement(true)
	create := func(name, model string) ProviderConnection {
		t.Helper()
		secret := "fixture-secret-never-public"
		p, err := f.policies.CreateProvider(ctx, f.org, f.owner, ProviderInput{Provider: "openrouter", Name: name, Models: []string{model}, Enabled: true, Secret: &secret})
		if err != nil || p.Status != "applied" {
			t.Fatalf("create: %+v %v", p, err)
		}
		return p
	}
	if has, err := f.policies.HasProvider(ctx, f.org); err != nil || !has {
		t.Fatalf("an organization with a credential must report one: %v %v", has, err)
	}
	if has, err := f.policies.HasProvider(ctx, uuid.New()); err != nil || has {
		t.Fatalf("an organization without a credential must report none: %v %v", has, err)
	}
	used, unused := create("Used", "openrouter/a"), create("Unused", "openrouter/c")
	f.exec(`UPDATE agent_groups SET name='Builders' WHERE id=$1`, f.team)
	f.exec(`UPDATE devices SET name='build-agent' WHERE id=$1`, f.device)
	if _, err := f.policies.PutTeam(ctx, f.org, f.owner, f.team, []string{"openrouter/a"}, []string{used.KeyID}, nil, 1); err != nil {
		t.Fatal(err)
	}
	group := uuid.New()
	f.exec(`INSERT INTO user_groups(id,org_id,name) VALUES($1,$2,'Engineering')`, group, f.org)
	f.exec(`UPDATE users SET email_verified_at=now() WHERE id=$1`, f.owner)
	grant, err := f.policies.PutUserModelGrant(ctx, f.org, f.owner, group, used.ID, "openrouter/a", true, 0)
	if err != nil {
		t.Fatal(err)
	}

	err = f.policies.DeleteProvider(ctx, f.org, f.owner, used.ID, used.Revision)
	var inUse *ProviderInUse
	if !errors.As(err, &inUse) {
		t.Fatalf("want the in-use refusal, got %v", err)
	}
	var standard *apierr.Error
	if !errors.As(err, &standard) || standard.Status != 409 || standard.Code != "ai_provider_in_use" {
		t.Fatalf("the refusal must still be a 409 ai_provider_in_use for a generic caller: %v", err)
	}
	if len(inUse.Models) != 1 || inUse.Models[0] != "openrouter/a" {
		t.Fatalf("models: %+v", inUse.Models)
	}
	if len(inUse.Policies) != 1 || inUse.Policies[0].TeamID != f.team || inUse.Policies[0].Name != "Builders" {
		t.Fatalf("policies: %+v", inUse.Policies)
	}
	if len(inUse.Agents) != 1 || inUse.Agents[0].DeviceID != f.device || inUse.Agents[0].Name != "build-agent" {
		t.Fatalf("agents: %+v", inUse.Agents)
	}
	var live int
	if pool.QueryRow(ctx, `SELECT count(*) FROM ai_provider_connections WHERE org_id=$1 AND id=$2 AND deleted_at IS NULL AND enabled`, f.org, used.ID).Scan(&live) != nil || live != 1 {
		t.Fatal("a refused deletion must leave the credential untouched")
	}

	// Another organization cannot learn anything about the credential.
	if err = other.policies.DeleteProvider(ctx, other.org, other.owner, used.ID, used.Revision); errors.As(err, &inUse) || usageStatus(err) != 404 {
		t.Fatalf("cross-organization delete: %v", err)
	}

	// An unused credential is deleted as before.
	if err = f.policies.DeleteProvider(ctx, f.org, f.owner, unused.ID, unused.Revision); err != nil {
		t.Fatal("unused credential not deleted: ", err)
	}

	// Once nothing uses it, the first one is deleted too. A user group grant alone still blocks.
	if _, err = f.policies.PutTeam(ctx, f.org, f.owner, f.team, []string{"openrouter/a"}, []string{"provider-key"}, nil, 2); err != nil {
		t.Fatal(err)
	}
	err = f.policies.DeleteProvider(ctx, f.org, f.owner, used.ID, used.Revision)
	if !errors.As(err, &inUse) || len(inUse.Models) != 1 || len(inUse.Policies) != 0 || len(inUse.Agents) != 0 {
		t.Fatalf("a user group grant alone must block and list its model: %v %+v", err, inUse)
	}
	if _, err = f.policies.PutUserModelGrant(ctx, f.org, f.owner, group, used.ID, "openrouter/a", false, grant.Revision); err != nil {
		t.Fatal(err)
	}
	if err = f.policies.DeleteProvider(ctx, f.org, f.owner, used.ID, used.Revision); err != nil {
		t.Fatal("credential no longer in use not deleted: ", err)
	}
}
