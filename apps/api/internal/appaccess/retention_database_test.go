package appaccess

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/tunnexio/tunnex/apps/api/db"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/auditretention"
)

// Every test uses grantPool's disposable child database, never the shared aa0
// parent or a live DSN. Synthetic timestamps are inserted only into that child.
func retentionClaim(t *testing.T, f *companyFixture, ttl time.Duration) sqlc.AppAccessRetentionRun {
	t.Helper()
	var anchor time.Time
	if err := f.pool.QueryRow(f.ctx, "SELECT clock_timestamp()").Scan(&anchor); err != nil {
		t.Fatal(err)
	}
	var id uuid.UUID
	if err := f.pool.QueryRow(f.ctx, `INSERT INTO app_access_retention_runs(org_id,started_at,grant_cutoff_at,audit_cutoff_at,lease_expires_at)
 VALUES($1,$2,$2::timestamptz-interval '2160 hours',$2::timestamptz-interval '8760 hours',$3) RETURNING id`, f.org, anchor, anchor.Add(ttl)).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return sqlc.AppAccessRetentionRun{ID: id, OrgID: f.org, StartedAt: anchor, GrantCutoffAt: anchor.Add(-90 * 24 * time.Hour), AuditCutoffAt: anchor.Add(-365 * 24 * time.Hour), LeaseExpiresAt: pgtype.Timestamptz{Time: anchor.Add(ttl), Valid: true}, Status: "running"}
}
func retentionCount(t *testing.T, f *companyFixture, statement string, args ...any) int64 {
	t.Helper()
	var count int64
	if err := f.pool.QueryRow(f.ctx, statement, args...).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}
func retentionGrant(t *testing.T, f *companyFixture, at time.Time) uuid.UUID {
	t.Helper()
	id := uuid.New()
	f.exec(`INSERT INTO app_access_grants(id,org_id,app_id,subject_kind,subject_id,subject_label,enabled,revoked_at)
 VALUES($1,$2,$3,'user',$4,'Retired synthetic subject',false,$5)`, id, f.org, f.app.ID, uuid.New(), at)
	return id
}
func retentionAudit(t *testing.T, f *companyFixture, org uuid.UUID, action, kind, target string, at time.Time) uuid.UUID {
	t.Helper()
	id := uuid.New()
	f.exec(`INSERT INTO audit_logs(id,org_id,actor_system,action,target_type,target_id,metadata,created_at)
 VALUES($1,$2,'retention-test',$3,$4,$5,'{"version":77}'::jsonb,$6)`, id, org, action, kind, target, at)
	return id
}

func TestGrantRetentionBoundariesAndIndependentHistoryLocalDatabase(t *testing.T) {
	f := newCompanyFixture(t)
	f.policy(&f.manager, true)
	request := f.request(f.member)
	approved, err := f.service.DecideAccessRequest(f.ctx, f.org, f.admin, request.ID, AccessDecision{Decision: "approved", ExpectedVersion: request.Version}, true)
	if err != nil || approved.GrantID == nil {
		t.Fatal(approved, err)
	}
	g, err := f.service.GetGrant(f.ctx, f.org, *approved.GrantID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.service.RevokeGrant(f.ctx, f.org, f.admin, g.ID, g.Version); err != nil {
		t.Fatal(err)
	}
	run := retentionClaim(t, f, 15*time.Minute)
	f.exec("UPDATE app_access_grants SET revoked_at=$2 WHERE id=$1", g.ID, run.GrantCutoffAt.Add(-time.Microsecond))
	boundary := retentionGrant(t, f, run.GrantCutoffAt)
	recent := retentionGrant(t, f, run.GrantCutoffAt.Add(time.Microsecond))
	// Expired but unrevoked grants retain their operational record indefinitely.
	expired := uuid.New()
	f.exec(`INSERT INTO app_access_grants(id,org_id,app_id,subject_kind,subject_id,user_id,subject_label,enabled,expires_at)
 VALUES($1,$2,$3,'user',$4,$4,'Expired only',true,$5)`, expired, f.org, f.app.ID, f.next, run.GrantCutoffAt.Add(-time.Hour))
	oldAudit := retentionAudit(t, f, f.org, "app_access.grant_updated", "app_access", g.ID.String(), run.AuditCutoffAt.Add(-time.Microsecond))
	exactAudit := retentionAudit(t, f, f.org, "app_access.grant_revoked", "app_access", g.ID.String(), run.AuditCutoffAt)
	legacy := retentionAudit(t, f, f.org, "app_access.grant_updated", "app_access", g.ID.String(), run.AuditCutoffAt.Add(time.Microsecond))
	unrelated := retentionAudit(t, f, f.org, "organization.updated", "app_access", g.ID.String(), run.AuditCutoffAt.Add(-time.Hour))
	wrongKind := retentionAudit(t, f, f.org, "app_access.grant_updated", "network", g.ID.String(), run.AuditCutoffAt.Add(-time.Hour))
	foreign := retentionAudit(t, f, f.other, "app_access.grant_updated", "app_access", g.ID.String(), run.AuditCutoffAt.Add(-time.Hour))
	q := sqlc.New(f.pool)
	deleted, err := q.PruneAppAccessRetentionBatch(f.ctx, run.ID)
	if err != nil || deleted != 2 {
		t.Fatal("strict grant/audit age batch", deleted, err)
	}
	if retentionCount(t, f, "SELECT count(*) FROM app_access_grants WHERE id=$1", g.ID) != 0 || retentionCount(t, f, "SELECT count(*) FROM audit_logs WHERE id=$1", oldAudit) != 0 {
		t.Fatal("eligible rows survived")
	}
	for _, id := range []uuid.UUID{boundary, recent, expired} {
		if retentionCount(t, f, "SELECT count(*) FROM app_access_grants WHERE id=$1", id) != 1 {
			t.Fatal("protected grant removed", id)
		}
	}
	for _, id := range []uuid.UUID{exactAudit, legacy, unrelated, wrongKind, foreign} {
		if retentionCount(t, f, "SELECT count(*) FROM audit_logs WHERE id=$1", id) != 1 {
			t.Fatal("protected audit removed", id)
		}
	}
	if retentionCount(t, f, `SELECT count(*) FROM audit_logs WHERE id=$1 AND metadata='{"version":77}'::jsonb`, legacy) != 1 {
		t.Fatal("legacy event metadata rewritten")
	}
	if retentionCount(t, f, `SELECT count(*) FROM audit_logs WHERE org_id=$1 AND target_id=$2 AND action='app_access.grant_retention_context'
 AND metadata->>'snapshot_kind'='retention_context' AND metadata->'grant'->>'id'=$2 AND metadata->'grant'->>'app_id'=$3
 AND metadata->'grant'->>'subject_id'=$4 AND metadata ? 'captured_at'`, f.org, g.ID.String(), f.app.ID.String(), f.member.String()) != 1 {
		t.Fatal("truthful independent context missing")
	}
	if retentionCount(t, f, "SELECT count(*) FROM app_access_requests WHERE id=$1 AND grant_id IS NULL AND approved_grant_id=$2", request.ID, g.ID) != 1 {
		t.Fatal("request lost immutable grant identity")
	}
	replayed, err := f.service.DecideAccessRequest(f.ctx, f.org, f.admin, request.ID, AccessDecision{Decision: "approved", ExpectedVersion: request.Version}, true)
	if err != nil || replayed.GrantID == nil || *replayed.GrantID != g.ID {
		t.Fatal("approved replay lost historical link", replayed, err)
	}
	if retentionCount(t, f, "SELECT count(*) FROM app_access_grants WHERE org_id=$1 AND app_id=$2 AND subject_id=$3 AND revoked_at IS NULL", f.org, f.app.ID, f.member) != 0 {
		t.Fatal("terminal replay recreated access")
	}
	if _, err = f.pool.Exec(f.ctx, "UPDATE app_access_requests SET approved_grant_id=$2 WHERE id=$1", request.ID, uuid.New()); err == nil {
		t.Fatal("historical identity mutable")
	}
	if _, err = f.pool.Exec(f.ctx, "DELETE FROM audit_logs WHERE id=$1", legacy); err == nil {
		t.Fatal("ordinary audit deletion became possible")
	}
	if _, err = f.pool.Exec(f.ctx, "UPDATE audit_logs SET metadata='{}'::jsonb WHERE id=$1", legacy); err == nil {
		t.Fatal("ordinary audit update became possible")
	}
	if n, err := q.PruneAppAccessRetentionBatch(f.ctx, run.ID); err != nil || n != 0 {
		t.Fatal("same cutoff not idempotent", n, err)
	}
}

func TestGrantRetentionBoundedBatchAndWorkerLocalDatabase(t *testing.T) {
	f := newCompanyFixture(t)
	f.exec(`INSERT INTO app_access_grants(org_id,app_id,subject_kind,subject_id,subject_label,enabled,revoked_at)
 SELECT $1,$2,'user',uuid_generate_v7(),'Old synthetic',false,now()-interval '91 days' FROM generate_series(1,501)`, f.org, f.app.ID)
	f.exec(`INSERT INTO audit_logs(org_id,actor_system,action,target_type,target_id,metadata,created_at)
 SELECT $1,'retention-test','app_access.grant_created','app_access',uuid_generate_v7()::text,'{}',now()-interval '366 days' FROM generate_series(1,501)`, f.org)
	run := retentionClaim(t, f, 15*time.Minute)
	q := sqlc.New(f.pool)
	if n, err := q.PruneAppAccessRetentionBatch(f.ctx, run.ID); err != nil || n != 1000 {
		t.Fatal("bounded batch", n, err)
	}
	if retentionCount(t, f, "SELECT count(*) FROM app_access_grants WHERE org_id=$1", f.org) != 1 {
		t.Fatal("grant batch exceeded500")
	}
	finished, err := f.service.executeRetentionRun(f.ctx, run)
	if err != nil || finished.GrantsDeleted != 501 || finished.AuditsDeleted != 501 || finished.Batches != 2 || finished.MorePending || finished.Status != "succeeded" {
		t.Fatal("durable counts", finished, err)
	}
	if retentionCount(t, f, "SELECT count(*) FROM app_access_retention_batch_authorizations") != 0 || retentionCount(t, f, "SELECT count(*) FROM audit_log_retention_authorizations") != 0 {
		t.Fatal("batch authorization leaked")
	}
	if _, claimed, err := f.service.RunRetentionScheduled(f.ctx, f.org); err != nil || claimed {
		t.Fatal("empty completed job repeated", claimed, err)
	}
	if _, err = q.PruneAppAccessRetentionBatch(f.ctx, run.ID); err == nil {
		t.Fatal("terminal run could prune")
	}
	if _, err = f.pool.Exec(f.ctx, "UPDATE app_access_retention_runs SET status='running',completed_at=NULL,lease_expires_at=now()+interval '15 minutes' WHERE id=$1", run.ID); err == nil {
		t.Fatal("terminal run revived")
	}
}

func TestGrantRetentionGeneralPolicyIsolationLocalDatabase(t *testing.T) {
	f := newCompanyFixture(t)
	now := time.Now().UTC()
	protected := retentionAudit(t, f, f.org, "app_access.grant_created", "app_access", uuid.NewString(), now.Add(-100*24*time.Hour))
	forever := retentionAudit(t, f, f.org, "organization.updated", "organization", f.org.String(), now.Add(-800*24*time.Hour))
	oldGrant := retentionAudit(t, f, f.org, "app_access.grant_revoked", "app_access", uuid.NewString(), now.Add(-366*24*time.Hour))
	run, claimed, err := f.service.RunRetentionScheduled(f.ctx, f.org)
	if err != nil || !claimed || run.AuditsDeleted != 1 {
		t.Fatal("fixed policy not scheduled", run, claimed, err)
	}
	if retentionCount(t, f, "SELECT count(*) FROM audit_logs WHERE id=$1", forever) != 1 || retentionCount(t, f, "SELECT count(*) FROM audit_logs WHERE id=$1", protected) != 1 || retentionCount(t, f, "SELECT count(*) FROM audit_logs WHERE id=$1", oldGrant) != 0 {
		t.Fatal("default forever or grant window changed")
	}
	general := auditretention.NewService(f.pool)
	days := int32(1)
	if _, err = general.SetSettings(f.ctx, f.org, f.admin, auditretention.SettingsInput{RetentionDays: &days, CleanupIntervalMinutes: 60, ExpectedRevision: 0}); err != nil {
		t.Fatal(err)
	}
	_, _, err = general.RunManual(f.ctx, f.org, f.admin, "retention-category-test")
	if err != nil {
		t.Fatal(err)
	}
	if retentionCount(t, f, "SELECT count(*) FROM audit_logs WHERE id=$1", forever) != 0 {
		t.Fatal("existing unrelated category policy no longer works")
	}
	if retentionCount(t, f, "SELECT count(*) FROM audit_logs WHERE id=$1", protected) != 1 {
		t.Fatal("short general policy erased grant evidence before365days")
	}
}

func TestGrantRetentionAtomicFailureAndIdentityGuardLocalDatabase(t *testing.T) {
	f := newCompanyFixture(t)
	run := retentionClaim(t, f, 15*time.Minute)
	g := retentionGrant(t, f, run.GrantCutoffAt.Add(-time.Hour))
	a := retentionAudit(t, f, f.org, "app_access.grant_created", "app_access", g.String(), run.AuditCutoffAt.Add(-time.Hour))
	for _, statement := range []string{
		"UPDATE app_access_retention_runs SET started_at=started_at-interval '1 day',grant_cutoff_at=grant_cutoff_at-interval '1 day',audit_cutoff_at=audit_cutoff_at-interval '1 day' WHERE id=$1",
		"UPDATE app_access_retention_runs SET grants_deleted=1,batches=1 WHERE id=$1",
	} {
		if _, err := f.pool.Exec(f.ctx, statement, run.ID); err == nil {
			t.Fatal("run identity/counters mutable")
		}
	}
	f.exec(`CREATE FUNCTION retention_test_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='app_access.grant_retention_context' THEN RAISE EXCEPTION 'injected_retention_failure'; END IF; RETURN NEW; END $$;
 CREATE TRIGGER retention_test_fault BEFORE INSERT ON audit_logs FOR EACH ROW EXECUTE FUNCTION retention_test_fault()`)
	if _, err := sqlc.New(f.pool).PruneAppAccessRetentionBatch(f.ctx, run.ID); err == nil {
		t.Fatal("injected audit failure ignored")
	}
	if retentionCount(t, f, "SELECT count(*) FROM app_access_grants WHERE id=$1", g) != 1 || retentionCount(t, f, "SELECT count(*) FROM audit_logs WHERE id=$1", a) != 1 || retentionCount(t, f, "SELECT batches FROM app_access_retention_runs WHERE id=$1", run.ID) != 0 {
		t.Fatal("partial prune committed")
	}
	f.exec("DROP TRIGGER retention_test_fault ON audit_logs; DROP FUNCTION retention_test_fault()")
	if n, err := sqlc.New(f.pool).PruneAppAccessRetentionBatch(f.ctx, run.ID); err != nil || n != 2 {
		t.Fatal("safe retry failed", n, err)
	}
}

func TestGrantRetentionLeaseAfterLockLocalDatabase(t *testing.T) {
	for _, operation := range []string{"renew", "finish", "prune"} {
		t.Run(operation, func(t *testing.T) {
			f := newCompanyFixture(t)
			run := retentionClaim(t, f, 500*time.Millisecond)
			g := retentionGrant(t, f, run.GrantCutoffAt.Add(-time.Hour))
			ctx, cancel := context.WithTimeout(f.ctx, 8*time.Second)
			defer cancel()
			blocker, err := f.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer blocker.Rollback(context.Background())
			if operation == "prune" {
				_, err = blocker.Exec(ctx, "SELECT id FROM organizations WHERE id=$1 FOR UPDATE", f.org)
			} else {
				_, err = blocker.Exec(ctx, "SELECT id FROM app_access_retention_runs WHERE id=$1 FOR UPDATE", run.ID)
			}
			if err != nil {
				t.Fatal(err)
			}
			conn, err := f.pool.Acquire(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Release()
			var pid int32
			if err = conn.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&pid); err != nil {
				t.Fatal(err)
			}
			result := make(chan error, 1)
			go func() {
				q := sqlc.New(conn)
				var e error
				switch operation {
				case "renew":
					var n int64
					n, e = q.RenewAppAccessRetentionRun(ctx, sqlc.RenewAppAccessRetentionRunParams{OrgID: f.org, ID: run.ID})
					if e == nil && n == 0 {
						e = ErrGrantRetentionOwnershipLost
					}
				case "finish":
					_, e = q.FinalizeAppAccessRetentionSuccess(ctx, sqlc.FinalizeAppAccessRetentionSuccessParams{OrgID: f.org, ID: run.ID})
				case "prune":
					_, e = q.PruneAppAccessRetentionBatch(ctx, run.ID)
				}
				result <- e
			}()
			locked := false
			for !locked && ctx.Err() == nil {
				if err = f.pool.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND wait_event_type='Lock')", pid).Scan(&locked); err != nil {
					t.Fatal(err)
				}
				if !locked {
					time.Sleep(5 * time.Millisecond)
				}
			}
			if !locked {
				t.Fatal("operation never waited for lock")
			}
			expired := false
			for !expired && ctx.Err() == nil {
				if err = f.pool.QueryRow(ctx, "SELECT clock_timestamp()>$1::timestamptz", run.LeaseExpiresAt.Time).Scan(&expired); err != nil {
					t.Fatal(err)
				}
				if !expired {
					time.Sleep(5 * time.Millisecond)
				}
			}
			if err = blocker.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			if err = <-result; err == nil {
				t.Fatal("expired owner renewed/finalized/pruned after waiting")
			}
			if retentionCount(t, f, "SELECT count(*) FROM app_access_grants WHERE id=$1", g) != 1 {
				t.Fatal("expired claim deleted grant")
			}
			if retentionCount(t, f, "SELECT count(*) FROM app_access_retention_runs WHERE id=$1 AND status='running' AND lease_expires_at<=clock_timestamp()", run.ID) != 1 {
				t.Fatal("expired run changed")
			}
			if _, err = sqlc.New(f.pool).ExpireAppAccessRetentionRun(ctx, f.org); err != nil {
				t.Fatal("recovery", err)
			}
			if _, claimed, err := f.service.RunRetentionScheduled(ctx, f.org); err != nil || !claimed {
				t.Fatal("expired run not recoverable", claimed, err)
			}
		})
	}
}

func TestGrantRetentionMigrationPreservesLegacyReferencesLocalDatabase(t *testing.T) {
	f := newCompanyFixture(t)
	f.policy(&f.manager, true)
	request := f.request(f.member)
	approved, err := f.service.DecideAccessRequest(f.ctx, f.org, f.admin, request.ID, AccessDecision{Decision: "approved", ExpectedVersion: request.Version}, true)
	if err != nil || approved.GrantID == nil {
		t.Fatal(approved, err)
	}
	if err = db.MigrateTo(f.pool.Config().ConnString(), 177); err != nil {
		t.Fatal("compatible rollback with live FK", err)
	}
	before := retentionCount(t, f, "SELECT count(*) FROM audit_logs")
	f.exec("UPDATE app_access_grants SET enabled=false,revoked_at=now()-interval '91 days' WHERE id=$1", *approved.GrantID)
	if err = db.MigrateTo(f.pool.Config().ConnString(), 178); err != nil {
		t.Fatal("forward", err)
	}
	if retentionCount(t, f, "SELECT count(*) FROM audit_logs") != before || retentionCount(t, f, "SELECT count(*) FROM app_access_grants WHERE id=$1", *approved.GrantID) != 1 {
		t.Fatal("migration purged or fabricated historical evidence")
	}
	if retentionCount(t, f, "SELECT count(*) FROM app_access_requests WHERE id=$1 AND approved_grant_id=$2", request.ID, *approved.GrantID) != 1 {
		t.Fatal("legacy approval reference not preserved")
	}
	if _, _, err = f.service.RunRetentionScheduled(f.ctx, f.org); err != nil {
		t.Fatal(err)
	}
	if err = db.MigrateTo(f.pool.Config().ConnString(), 177); err == nil || !strings.Contains(err.Error(), "app_access_retention_history_requires_preservation") {
		t.Fatal("unsafe history-losing rollback allowed", err)
	}
}

func TestGrantRetentionSubjectRemovalSnapshotLocalDatabase(t *testing.T) {
	f := newCompanyFixture(t)
	g, err := f.service.CreateGrant(f.ctx, f.org, f.admin, GrantInput{AppID: f.app.ID, SubjectKind: "user", SubjectID: f.member, Enabled: true}, true)
	if err != nil {
		t.Fatal(err)
	}
	f.exec("DELETE FROM memberships WHERE org_id=$1 AND user_id=$2", f.org, f.member)
	if retentionCount(t, f, `SELECT count(*) FROM audit_logs WHERE action='app_access.grant_subject_removed' AND target_id=$1
 AND metadata->>'snapshot_kind'='event_state' AND metadata->'grant'->>'subject_id'=$2
 AND (metadata->'grant'->>'enabled')::boolean=false AND metadata->'grant'->>'revoked_at' IS NOT NULL`, g.ID.String(), f.member.String()) != 1 {
		t.Fatal("directory removal lacked immutable event snapshot")
	}
}
