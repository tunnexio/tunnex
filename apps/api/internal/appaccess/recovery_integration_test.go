package appaccess

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/db"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
)

func TestOfflineRecoveryLocalDatabase(t *testing.T) {
	p := grantPool(t)
	if err := db.MigrateTo(p.Config().ConnString(), 173); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	q := sqlc.New(p)
	initial, err := q.GetAppAccessInstallationAuthority(ctx)
	if err != nil {
		t.Fatal(err)
	}
	user, proxyID := uuid.New(), uuid.New()
	if _, err = p.Exec(ctx, "INSERT INTO users(id,email,name)VALUES($1,$2,'Recovery fixture');", user, user.String()+"@fixture.test"); err != nil {
		t.Fatal(err)
	}
	if _, err = p.Exec(ctx, "INSERT INTO app_access_proxy_credentials(id,name,token_hash)VALUES($1,'Recovery fixture',decode(repeat('ab',32),'hex'))", proxyID); err != nil {
		t.Fatal(err)
	}
	s := NewRecoveryService(p)
	// Mutation auditing is part of the same transaction. A failed audit cannot
	// leave a new generation, credential revocation or user epoch behind.
	if _, err = p.Exec(ctx, `CREATE FUNCTION recovery_audit_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture audit failure'; END $$; CREATE TRIGGER recovery_audit_failure BEFORE INSERT ON audit_logs FOR EACH ROW EXECUTE FUNCTION recovery_audit_failure()`); err != nil {
		t.Fatal(err)
	}
	if _, err = s.RecoverAuthority(ctx, "owned-test-operator"); err == nil {
		t.Fatal("audit failure accepted")
	}
	current, err := q.GetAppAccessInstallationAuthority(ctx)
	if err != nil || current.Generation != initial.Generation || current.Version != initial.Version {
		t.Fatal("audit rollback lost authority", err)
	}
	var epoch int64
	var revoked bool
	if err = p.QueryRow(ctx, "SELECT app_auth_epoch FROM users WHERE id=$1", user).Scan(&epoch); err != nil || epoch != 1 {
		t.Fatal("audit rollback lost parent epoch", epoch, err)
	}
	if err = p.QueryRow(ctx, "SELECT revoked_at IS NOT NULL FROM app_access_proxy_credentials WHERE id=$1", proxyID).Scan(&revoked); err != nil || revoked {
		t.Fatal("audit rollback lost proxy", err)
	}
	if _, err = p.Exec(ctx, "DROP TRIGGER recovery_audit_failure ON audit_logs; DROP FUNCTION recovery_audit_failure()"); err != nil {
		t.Fatal(err)
	}
	// Simulate a command ending after durable invalidation commits but before
	// withdrawal confirmation. The incomplete generation must survive restart.
	recoverCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	resultCh := make(chan RecoveryResult, 1)
	errorCh := make(chan error, 1)
	go func() {
		result, e := s.RecoverAuthority(recoverCtx, "owned-test-operator")
		resultCh <- result
		errorCh <- e
	}()
	deadline := time.Now().Add(4 * time.Second)
	for {
		current, err = q.GetAppAccessInstallationAuthority(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if current.Generation != initial.Generation {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("recovery did not commit")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	result := <-resultCh
	if err = <-errorCh; !errors.Is(err, context.Canceled) || result.Confirmed || current.RecoveryCompletedAt.Valid {
		t.Fatal("cancelled command confirmed recovery", err)
	}
	if result.Generation != current.Generation || result.Users != 1 || result.ProxyCredentials != 1 {
		t.Fatal("recovery counts/tuple", result)
	}
	if err = p.QueryRow(ctx, "SELECT app_auth_epoch FROM users WHERE id=$1", user).Scan(&epoch); err != nil || epoch != 2 {
		t.Fatal("restored native parent not invalidated", epoch, err)
	}
	if err = p.QueryRow(ctx, "SELECT revoked_at IS NOT NULL FROM app_access_proxy_credentials WHERE id=$1", proxyID).Scan(&revoked); err != nil || !revoked {
		t.Fatal("restored proxy not invalidated", err)
	}
	if err = s.ConfirmRecovery(ctx, initial.Generation, initial.Version); err == nil {
		t.Fatal("old recovery tuple accepted")
	}
	started := time.Now()
	if err = s.ConfirmRecovery(ctx, result.Generation, result.Version); err != nil {
		t.Fatal(err)
	}
	if time.Since(started) < 5*time.Second {
		t.Fatal("restart reused earlier withdrawal time")
	}
	current, err = q.GetAppAccessInstallationAuthority(ctx)
	if err != nil || !current.RecoveryCompletedAt.Valid {
		t.Fatal("recovery confirmation", err)
	}
	if err = s.ConfirmRecovery(ctx, result.Generation, result.Version); err == nil {
		t.Fatal("persisted old completion reused")
	}
	var audits int
	if err = p.QueryRow(ctx, "SELECT count(*) FROM audit_logs WHERE action='app_access.authority.recovered'").Scan(&audits); err != nil || audits != 1 {
		t.Fatal("recovery audit", audits, err)
	}
}
