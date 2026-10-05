package sandboxes

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/policy"
	"strings"
	"testing"
)

type moduleQueryCounter struct {
	sqlc.DBTX
	projections int
}

func (c *moduleQueryCounter) Query(ctx context.Context, sql string, args ...interface{}) (pgx.Rows, error) {
	if strings.Contains(sql, "-- name: ListActiveSandboxProjections") {
		c.projections++
	}
	return c.DBTX.Query(ctx, sql, args...)
}
func TestSandboxModulePostgresDisabledOrganizationWithdrawsAndRetires(t *testing.T) {
	f := newFixture(t)
	saved, err := f.store.SaveSSHKey(f.ctx, f.user, "Saved account key", f.sshPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if err = CheckModuleRetired(f.ctx, f.pool); !errors.Is(err, ErrModuleRetirementPending) {
		t.Fatal("enabled organization not fenced before off", err)
	}
	if _, err = f.pool.Exec(f.ctx, `UPDATE organizations SET sandboxes_enabled=false WHERE id=$1`, f.org); err != nil {
		t.Fatal(err)
	}
	if err = CheckModuleRetired(f.ctx, f.pool); err != nil {
		t.Fatal("saved keys blocked fresh off", err)
	}
	if _, err = f.pool.Exec(f.ctx, `UPDATE organizations SET sandboxes_enabled=true WHERE id=$1`, f.org); err != nil {
		t.Fatal(err)
	}
	sb, _, err := f.store.Create(f.ctx, f.org, f.user, f.input("optional-module"))
	if err != nil {
		t.Fatal(err)
	}
	bindCleanupPeer(t, f, sb)
	counter := &moduleQueryCounter{DBTX: f.pool}
	q := sqlc.New(counter)
	active, err := policy.BuildSnapshotWithQueries(f.ctx, q, f.org)
	if err != nil || len(active.Sandboxes) != 1 || counter.projections != 1 {
		t.Fatal("active projection missing", active.Sandboxes, counter.projections, err)
	}
	if _, err = f.pool.Exec(f.ctx, `INSERT INTO sandbox_runtime_bindings(sandbox_id,org_id,spec_hash,image_digest,memory_mib,cpus,pids) VALUES($1,$2,$3,$4,256,1,64)`, sb.Identity.ID, f.org, strings.Repeat("a", 64), "sha256:"+strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	if _, err = f.pool.Exec(f.ctx, `UPDATE organizations SET sandboxes_enabled=false WHERE id=$1`, f.org); err != nil {
		t.Fatal(err)
	}
	withdrawn, err := policy.BuildSnapshotWithQueries(f.ctx, q, f.org)
	if err != nil || len(withdrawn.Sandboxes) != 0 || counter.projections != 1 {
		t.Fatal("disabled org queried retained projections", counter.projections, err)
	}
	if len(policy.Compile(withdrawn)[f.node].Allow) != 0 {
		t.Fatal("disabled org retained sandbox grants")
	}
	if err = CheckModuleRetired(f.ctx, f.pool); !errors.Is(err, ErrModuleRetirementPending) {
		t.Fatal("organization off mistaken for physical retirement", err)
	}
	sb, err = f.store.SetDesired(f.ctx, f.org, f.user, sb.Identity.ID, sb.Revision, "deleted")
	if err != nil {
		t.Fatal("disabled org cannot delete", err)
	}
	pending, err := f.store.PendingCleanup(f.ctx, 100)
	if err != nil || len(pending) != 1 || pending[0] != sb.Identity.ID {
		t.Fatal("disabled org cleanup lost", pending, err)
	}
	provider := &cleanupProvider{exists: true, running: true}
	if err = f.store.ReconcileCleanup(f.ctx, sb.Identity.ID, provider, cleanupNetworkFunc(func(_ context.Context, s Sandbox) (Withdrawal, error) { return matchingWithdrawal(s), nil })); err != nil {
		t.Fatal(err)
	}
	if err = CheckModuleRetired(f.ctx, f.pool); !errors.Is(err, ErrModuleRetirementPending) {
		t.Fatal("missing worker receipt ignored", err)
	}
	if _, err = f.pool.Exec(f.ctx, `UPDATE sandbox_runtime_bindings SET worker_retired_at=now() WHERE sandbox_id=$1`, sb.Identity.ID); err != nil {
		t.Fatal(err)
	}
	if err = CheckModuleRetired(f.ctx, f.pool); err != nil {
		t.Fatal("confirmed retirement blocked", err)
	}
	keys, err := f.store.ListSavedSSHKeys(f.ctx, f.user)
	if err != nil || len(keys) != 1 || keys[0].ID != saved.ID {
		t.Fatal("off/drain discarded saved account keys", keys, err)
	}
}
