package sandboxes

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestQualificationDatabaseAndProfilesFailClosed(t *testing.T) {
	for _, name := range []string{"tunnex", "postgres", "tunnex_sandbox_qual_abc", "tunnex_sandbox_qual_abcdefgh/other", "tunnex_sandbox_qual_ABCDEFGH"} {
		if qualificationDatabase(name) {
			t.Fatal("nonfixture database admitted", name)
		}
	}
	if !qualificationDatabase("tunnex_sandbox_qual_1234abcd") {
		t.Fatal("fixture name rejected")
	}
	for _, digest := range []string{"latest", qualificationProfiles[0].digest + "a", "sha256:c47f93b143acbeb38b61895ffcc3870deb4e42e3ab44d8f2f4eefb1468dcc10a"} {
		if _, _, err := qualificationProfile(digest); err == nil {
			t.Fatal("unapproved image admitted", digest)
		}
	}
}
func TestQualificationProfilesPostgresSerialBudgetAndCAS(t *testing.T) {
	f := newFixture(t)
	f.store.WithQualificationOrg(f.org)
	// The public constructor must reject this ordinary test database even with
	// matching organization configuration. Only the package test injects its pool.
	if _, err := NewQualificationProfileOperator(f.ctx, f.store, f.org, f.node); !errors.Is(err, ErrDisabled) {
		t.Fatal("nonfixture database admitted", err)
	}
	op := &QualificationProfileOperator{f.store, f.org, f.node, f.user}
	if _, _, err := op.Create(f.ctx, qualificationProfiles[1].digest, []string{f.sshPublicKey}); !errors.Is(err, ErrQuota) {
		t.Fatal("profile order bypassed", err)
	}
	if _, _, err := op.CreateWithTTL(f.ctx, qualificationProfiles[0].digest, []string{f.sshPublicKey}, 901); !errors.Is(err, ErrInvalid) {
		t.Fatal("TTL ceiling exceeded", err)
	}
	first, replay, err := op.CreateWithTTL(f.ctx, qualificationProfiles[0].digest, []string{f.sshPublicKey}, 300)
	if err != nil || replay {
		t.Fatal(err)
	}
	if first.RequestedScope == nil || len(first.RequestedScope) != 0 || first.ExpiresAt.Sub(first.CreatedAt).Seconds() != 300 {
		t.Fatal("scope or TTL widened", first)
	}
	again, replay, err := op.CreateWithTTL(f.ctx, qualificationProfiles[0].digest, []string{f.sshPublicKey}, 300)
	if err != nil || !replay || again.Identity.ID != first.Identity.ID {
		t.Fatal("idempotency failed", err)
	}
	if _, _, err = op.Create(f.ctx, qualificationProfiles[1].digest, []string{f.sshPublicKey}); !errors.Is(err, ErrQuota) {
		t.Fatal("second active sandbox admitted", err)
	}
	if _, err = op.SetDesired(f.ctx, first.Identity.ID, first.Revision+1, "deleted"); !errors.Is(err, ErrConflict) {
		t.Fatal("CAS bypassed", err)
	}
	if err = op.Finish(f.ctx, first.Identity.ID); !errors.Is(err, ErrConflict) {
		t.Fatal("unproven cleanup accepted", err)
	}
	if _, err = op.Status(f.ctx, uuid.New()); err == nil {
		t.Fatal("unowned sandbox exposed")
	}
	for i, profile := range qualificationProfiles {
		current := first
		if i > 0 {
			current, _, err = op.Create(f.ctx, profile.digest, []string{f.sshPublicKey})
			if err != nil {
				t.Fatal(err)
			}
		}
		current, err = op.SetDesired(f.ctx, current.Identity.ID, current.Revision, "deleted")
		if err != nil {
			t.Fatal(err)
		}
		provider := &cleanupProvider{}
		if err = f.store.ReconcileCleanup(f.ctx, current.Identity.ID, provider, nil); err != nil {
			t.Fatal(err)
		}
		if err = op.Finish(f.ctx, current.Identity.ID); err != nil {
			t.Fatal(err)
		}
	}
	var accepted, enabled int
	if err = f.pool.QueryRow(f.ctx, `SELECT count(*) FROM sandboxes WHERE org_id=$1 AND idempotency_key LIKE $2`, f.org, qualificationBundle+":%").Scan(&accepted); err != nil || accepted != 3 {
		t.Fatal("bundle count wrong", accepted, err)
	}
	if err = f.pool.QueryRow(f.ctx, `SELECT count(*) FROM sandbox_templates WHERE org_id=$1 AND name LIKE $2 AND enabled`, f.org, qualificationBundle+":%").Scan(&enabled); err != nil || enabled != 0 {
		t.Fatal("temporary catalog still active", enabled, err)
	}
	if _, err = op.SetDesired(f.ctx, first.Identity.ID, 2, "started"); !errors.Is(err, ErrConflict) {
		t.Fatal("deleted fixture resurrected", err)
	}
}

func TestQualificationIdentityPostgresSchemaAndPrincipalBinding(t *testing.T) {
	f := newFixture(t)
	f.store.WithQualificationOrg(f.org)
	if _, err := f.pool.Exec(f.ctx, `UPDATE organizations SET name='Sandbox qualification 0',pool_cidr='10.254.242.0/24',max_sandboxes=1,max_sandboxes_per_user=1 WHERE id=$1`, f.org); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(f.ctx, `UPDATE users SET email=id::text||'@sandbox.example.test' WHERE id=$1`, f.user); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(f.ctx, `UPDATE memberships SET role='owner' WHERE org_id=$1 AND user_id=$2`, f.org, f.user); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(f.ctx, `UPDATE nodes SET name='sandbox-qualification-gateway',status='active' WHERE id=$1`, f.node); err != nil {
		t.Fatal(err)
	}
	creator, err := qualificationCreator(f.ctx, f.store, f.org, f.node)
	if err != nil || creator != f.user {
		t.Fatal("populated fixture identity SQL incompatible", creator, err)
	}
	if _, err = qualificationCreator(f.ctx, f.store, f.org, uuid.New()); !errors.Is(err, ErrDisabled) {
		t.Fatal("wrong gateway admitted", err)
	}
	if _, err = f.pool.Exec(f.ctx, `UPDATE memberships SET role='member' WHERE org_id=$1 AND user_id=$2`, f.org, f.user); err != nil {
		t.Fatal(err)
	}
	if _, err = qualificationCreator(f.ctx, f.store, f.org, f.node); !errors.Is(err, ErrDisabled) {
		t.Fatal("fixture principal changed", err)
	}
}

func TestQualificationRenewalHasFixedAdmissionEnd(t *testing.T) {
	first := time.Date(2026, time.October, 3, 13, 19, 53, 0, time.UTC)
	end := time.Date(2026, time.October, 3, 15, 30, 0, 0, time.UTC)
	if !qualificationAdmissionAllowed(end.Add(-901*time.Second), 900, first) {
		t.Fatal("approved remaining profile denied")
	}
	for _, now := range []time.Time{end.Add(-900 * time.Second), end, end.Add(time.Hour)} {
		if qualificationAdmissionAllowed(now, 900, first) {
			t.Fatal("profile exceeds fixed renewed window")
		}
	}
}

func TestQualificationSupplementalPostgresExactlyTwoAfterOriginalFinish(t *testing.T) {
	f := newFixture(t)
	f.store.WithQualificationOrg(f.org)
	op := &QualificationProfileOperator{f.store, f.org, f.node, f.user}
	finish := func(s Sandbox) {
		t.Helper()
		s, err := op.SetDesired(f.ctx, s.Identity.ID, s.Revision, "deleted")
		if err != nil {
			t.Fatal(err)
		}
		if err = f.store.ReconcileCleanup(f.ctx, s.Identity.ID, &cleanupProvider{}, nil); err != nil {
			t.Fatal(err)
		}
		if err = op.Finish(f.ctx, s.Identity.ID); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := op.CreateSupplementalWithTTL(f.ctx, qualificationProfiles[0].digest, []string{f.sshPublicKey}, 900); !errors.Is(err, ErrQuota) {
		t.Fatal("supplement admitted before original bundle", err)
	}
	for _, p := range qualificationProfiles {
		s, _, err := op.Create(f.ctx, p.digest, []string{f.sshPublicKey})
		if err != nil {
			t.Fatal(err)
		}
		finish(s)
	}
	if _, _, err := op.CreateSupplementalWithTTL(f.ctx, qualificationProfiles[2].digest, []string{f.sshPublicKey}, 900); !errors.Is(err, ErrInvalid) {
		t.Fatal("supplemental Node admitted", err)
	}
	if _, _, err := op.CreateSupplementalWithTTL(f.ctx, qualificationProfiles[1].digest, []string{f.sshPublicKey}, 900); !errors.Is(err, ErrQuota) {
		t.Fatal("supplement order bypassed", err)
	}
	first, _, err := op.CreateSupplementalWithTTL(f.ctx, qualificationProfiles[0].digest, []string{f.sshPublicKey}, 900)
	if err != nil {
		t.Fatal(err)
	}
	if first.TemplateVersionID == qualificationTemplate(f.org, qualificationProfiles[0].digest) {
		t.Fatal("original template reused")
	}
	if _, _, err = op.CreateSupplementalWithTTL(f.ctx, qualificationProfiles[1].digest, []string{f.sshPublicKey}, 900); !errors.Is(err, ErrQuota) {
		t.Fatal("two retained admitted", err)
	}
	finish(first)
	second, _, err := op.CreateSupplementalWithTTL(f.ctx, qualificationProfiles[1].digest, []string{f.sshPublicKey}, 900)
	if err != nil {
		t.Fatal(err)
	}
	finish(second)
	replay, reused, err := op.CreateSupplementalWithTTL(f.ctx, qualificationProfiles[0].digest, []string{f.sshPublicKey}, 900)
	if err != nil || !reused || replay.Identity.ID != first.Identity.ID || !replay.ExpiresAt.Equal(first.ExpiresAt) {
		t.Fatal("supplement counter or expiry reset", err)
	}
	var count int
	if err = f.pool.QueryRow(f.ctx, `SELECT count(*) FROM sandboxes WHERE org_id=$1 AND idempotency_key LIKE $2`, f.org, qualificationBundle+":%").Scan(&count); err != nil || count != 5 {
		t.Fatal("identity budget not exactly five", count, err)
	}
}
