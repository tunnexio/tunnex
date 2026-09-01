package db_test

import (
	"context"
	"errors"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db"
)

// These are the exact SQL result shapes compiled into the N-1 control plane.
// Running them after 0131 proves the rolling bridge instead of merely testing a
// lifecycle-aware writer that already knows about the new columns.
const nMinusOneConsumeJoinToken = `
UPDATE node_join_tokens
SET consumed_at = now()
WHERE token_hash = $1 AND consumed_at IS NULL AND expires_at > now()
RETURNING id, org_id, node_name, token_hash, expires_at, consumed_at,
          consumed_node_id, created_at, issued_by, enrols_kind`

const nMinusOneCreateNode = `
INSERT INTO nodes
    (org_id, name, cert_serial, agent_version, cert_not_after,
     cert_public_key, owner_user_id, enrolled_kind)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
RETURNING id, org_id, name, status, cert_serial, agent_version, enrolled_at,
          last_seen_at, revoked_at, created_at, updated_at, wg_public_key,
          endpoint, capabilities, policy_desync_since, policy_reported_at,
          site_id, hub_priority, cert_not_after, cert_public_key,
          cert_key_fingerprint, cert_delivered_at, cert_delivered,
          owner_user_id, enrolled_kind`

func TestK8sLifecycleClaimRemintMigrationPostgres(t *testing.T) {
	adminURL := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if adminURL == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL for 0131 PostgreSQL mixed-version proof")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	admin, err := pgxpool.New(ctx, adminURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	base, err := url.Parse(adminURL)
	if err != nil {
		t.Fatal(err)
	}
	databaseName := "tnx_s205_lifecycle_" + uuid.NewString()[:8]
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+databaseName); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(context.Background(), "DROP DATABASE IF EXISTS "+databaseName+" WITH (FORCE)")
	})
	testURL := *base
	testURL.Path = "/" + databaseName
	dsn := testURL.String()

	if err := db.MigrateTo(dsn, 130); err != nil {
		t.Fatalf("migrate prerequisite chain through 0130: %v", err)
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	t.Run("up follows enrollment token then node lock order", func(t *testing.T) {
		tx := beginLifecycleMigrationTx(t, ctx, pool)
		defer tx.Rollback(ctx) //nolint:errcheck
		orgID := seedLifecycleMigrationOrg(t, ctx, tx)
		tokenID := uuid.New()
		tokenHash := []byte("d13b-up-lock-" + uuid.NewString())
		if _, err := tx.Exec(ctx, `
			INSERT INTO node_join_tokens
				(id,org_id,node_name,token_hash,expires_at,issued_by,enrols_kind)
			VALUES($1,$2,'gateway-up-lock',$3,now()+interval '1 hour',NULL,'gateway')`, tokenID, orgID, tokenHash); err != nil {
			t.Fatalf("seed 0130 join token: %v", err)
		}
		consumeNMinusOneLifecycleToken(t, ctx, tx, tokenHash)

		migrationDone := make(chan error, 1)
		go func() { migrationDone <- db.MigrateTo(dsn, 131) }()
		deadline := time.Now().Add(5 * time.Second)
		for {
			var waitType string
			queryErr := pool.QueryRow(ctx, `
				SELECT COALESCE(wait_event_type, '')
				FROM pg_stat_activity
				WHERE datname=current_database()
				  AND pid <> pg_backend_pid()
				  AND query LIKE '%LOCK TABLE node_join_tokens IN ACCESS EXCLUSIVE MODE%'
				ORDER BY query_start DESC
				LIMIT 1`).Scan(&waitType)
			if queryErr == nil && waitType == "Lock" {
				break
			}
			if queryErr != nil && !errors.Is(queryErr, pgx.ErrNoRows) {
				t.Fatalf("observe blocked 0131 up: %v", queryErr)
			}
			if time.Now().After(deadline) {
				t.Fatal("0131 up did not wait behind the in-flight token consumption")
			}
			time.Sleep(10 * time.Millisecond)
		}

		certSerial := "up-lock-" + uuid.NewString()
		createNMinusOneNode(t, ctx, tx, orgID, "gateway-up-lock", certSerial)
		if err := tx.Commit(ctx); err != nil {
			t.Fatalf("finish N-1 enrollment while migration waits: %v", err)
		}
		select {
		case migrationErr := <-migrationDone:
			if migrationErr != nil {
				t.Fatalf("0131 up after N-1 enrollment: %v", migrationErr)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("0131 up did not finish after the N-1 enrollment committed")
		}

		var nodeClaim *uuid.UUID
		if err := pool.QueryRow(ctx, `SELECT lifecycle_claim FROM nodes WHERE cert_serial=$1`, certSerial).Scan(&nodeClaim); err != nil {
			t.Fatalf("read pre-0131 enrolled node: %v", err)
		}
		if nodeClaim != nil {
			t.Fatalf("pre-0131 legacy enrollment unexpectedly gained claim %s", *nodeClaim)
		}
		if _, err := pool.Exec(ctx, `DELETE FROM nodes WHERE cert_serial=$1`, certSerial); err != nil {
			t.Fatalf("clean up-lock node: %v", err)
		}
		if _, err := pool.Exec(ctx, `DELETE FROM node_join_tokens WHERE id=$1`, tokenID); err != nil {
			t.Fatalf("clean up-lock token: %v", err)
		}
		if _, err := pool.Exec(ctx, `DELETE FROM organizations WHERE id=$1`, orgID); err != nil {
			t.Fatalf("clean up-lock organization: %v", err)
		}
	})
	if err := db.MigrateTo(dsn, 130); err != nil {
		t.Fatalf("empty 0131 down: %v", err)
	}
	if err := db.MigrateTo(dsn, 131); err != nil {
		t.Fatalf("0131 re-up: %v", err)
	}
	if version, dirty, ok, err := db.Version(dsn); err != nil || !ok || dirty || version != 131 {
		t.Fatalf("0131 version=%d dirty=%v ok=%v err=%v", version, dirty, ok, err)
	}

	t.Run("N-1 inherits exact claim and clears sealed response", func(t *testing.T) {
		tx := beginLifecycleMigrationTx(t, ctx, pool)
		defer tx.Rollback(ctx) //nolint:errcheck
		orgID, tokenID, claim, tokenHash := seedLifecycleMigrationToken(t, ctx, tx, "gateway-n-minus-one")
		consumeNMinusOneLifecycleToken(t, ctx, tx, tokenHash)

		var sealed *string
		var preLink *uuid.UUID
		if err := tx.QueryRow(ctx, `SELECT lifecycle_token_sealed,consumed_node_id FROM node_join_tokens WHERE id=$1`, tokenID).Scan(&sealed, &preLink); err != nil {
			t.Fatal(err)
		}
		if sealed != nil || preLink != nil {
			t.Fatalf("N-1 consume retained secret or pre-linked identity: sealed=%v node=%v", sealed, preLink)
		}

		certSerial := "n-minus-one-" + uuid.NewString()
		createNMinusOneNode(t, ctx, tx, orgID, "gateway-n-minus-one", certSerial)
		assertLifecycleMigrationBinding(t, ctx, tx, tokenID, certSerial, claim)
		forceLifecycleConstraintCheck(t, ctx, tx)
	})

	t.Run("N explicit claim binds the same transaction", func(t *testing.T) {
		tx := beginLifecycleMigrationTx(t, ctx, pool)
		defer tx.Rollback(ctx) //nolint:errcheck
		orgID, tokenID, claim, tokenHash := seedLifecycleMigrationToken(t, ctx, tx, "gateway-current")
		consumeNMinusOneLifecycleToken(t, ctx, tx, tokenHash)
		certSerial := "current-" + uuid.NewString()
		if _, err := tx.Exec(ctx, `
			INSERT INTO nodes(org_id,name,cert_serial,agent_version,lifecycle_claim)
			VALUES($1,$2,$3,'test',$4)`, orgID, "gateway-current", certSerial, claim); err != nil {
			t.Fatalf("current writer exact claim: %v", err)
		}
		assertLifecycleMigrationBinding(t, ctx, tx, tokenID, certSerial, claim)
		forceLifecycleConstraintCheck(t, ctx, tx)
	})

	t.Run("consumption without node cannot commit", func(t *testing.T) {
		tx := beginLifecycleMigrationTx(t, ctx, pool)
		_, _, _, tokenHash := seedLifecycleMigrationToken(t, ctx, tx, "gateway-no-node")
		consumeNMinusOneLifecycleToken(t, ctx, tx, tokenHash)
		err := tx.Commit(ctx)
		if err == nil || !strings.Contains(err.Error(), "node_lifecycle_consumption_is_not_bound_to_exact_node") {
			t.Fatalf("unbound lifecycle consumption commit error = %v", err)
		}
	})

	t.Run("N-1 cannot resurrect an aborted lifecycle claim", func(t *testing.T) {
		setup := beginLifecycleMigrationTx(t, ctx, pool)
		orgID, tokenID, _, tokenHash := seedLifecycleMigrationToken(t, ctx, setup, "gateway-aborted")
		if err := setup.Commit(ctx); err != nil {
			t.Fatalf("commit aborted-token fixture: %v", err)
		}
		t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, orgID) })
		// Keep expires_at in the future so this exercises the migration bridge,
		// not merely the old binary's expiry predicate. The schema permits this
		// shape even though the current abort query also shortens expiry.
		if _, err := pool.Exec(ctx, `
			UPDATE node_join_tokens
			SET lifecycle_aborted_at=now(), lifecycle_token_sealed=NULL,
			    expires_at=now()+interval '1 hour'
			WHERE id=$1`, tokenID); err != nil {
			t.Fatal(err)
		}

		attempt := beginLifecycleMigrationTx(t, ctx, pool)
		err := consumeNMinusOneLifecycleTokenRaw(ctx, attempt, tokenHash)
		if !errors.Is(err, pgx.ErrNoRows) {
			t.Fatalf("N-1 aborted claim consume error=%v, want pgx.ErrNoRows", err)
		}
		if err := attempt.Rollback(ctx); err != nil && err != pgx.ErrTxClosed {
			t.Fatal(err)
		}
		var consumedAt *time.Time
		if err := pool.QueryRow(ctx, `SELECT consumed_at FROM node_join_tokens WHERE id=$1`, tokenID).Scan(&consumedAt); err != nil {
			t.Fatal(err)
		}
		if consumedAt != nil {
			t.Fatalf("aborted lifecycle token was consumed at %v", consumedAt)
		}
	})

	t.Run("rename and explicit claim mismatch are refused", func(t *testing.T) {
		for _, testCase := range []struct {
			name       string
			nodeName   string
			explicit   bool
			claimDelta bool
		}{
			{name: "renamed N-1 node", nodeName: "gateway-renamed"},
			{name: "mismatched N claim", nodeName: "gateway-pinned", explicit: true, claimDelta: true},
		} {
			t.Run(testCase.name, func(t *testing.T) {
				setup := beginLifecycleMigrationTx(t, ctx, pool)
				orgID, tokenID, claim, tokenHash := seedLifecycleMigrationToken(t, ctx, setup, "gateway-pinned")
				if err := setup.Commit(ctx); err != nil {
					t.Fatalf("commit mismatch fixture: %v", err)
				}
				t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, orgID) })

				attempt := beginLifecycleMigrationTx(t, ctx, pool)
				consumeNMinusOneLifecycleToken(t, ctx, attempt, tokenHash)
				var err error
				if testCase.explicit {
					if testCase.claimDelta {
						claim = uuid.New()
					}
					_, err = attempt.Exec(ctx, `INSERT INTO nodes(org_id,name,cert_serial,agent_version,lifecycle_claim) VALUES($1,$2,$3,'test',$4)`, orgID, testCase.nodeName, uuid.NewString(), claim)
				} else {
					err = createNMinusOneNodeRaw(ctx, attempt, orgID, testCase.nodeName, uuid.NewString())
				}
				if err == nil || !strings.Contains(err.Error(), "node_lifecycle_enrollment_authorization_missing_or_ambiguous") {
					t.Fatalf("identity mismatch error = %v", err)
				}
				if err := attempt.Rollback(ctx); err != nil && err != pgx.ErrTxClosed {
					t.Fatalf("roll back refused enrollment: %v", err)
				}
				assertLifecycleMigrationTokenUnconsumed(t, ctx, pool, tokenID)
			})
		}
	})

	t.Run("two same-name candidates are ambiguous for N-1", func(t *testing.T) {
		tx := beginLifecycleMigrationTx(t, ctx, pool)
		defer tx.Rollback(ctx) //nolint:errcheck
		orgID := seedLifecycleMigrationOrg(t, ctx, tx)
		_, _, hashA := insertLifecycleMigrationToken(t, ctx, tx, orgID, "gateway-ambiguous")
		_, _, hashB := insertLifecycleMigrationToken(t, ctx, tx, orgID, "gateway-ambiguous")
		consumeNMinusOneLifecycleToken(t, ctx, tx, hashA)
		consumeNMinusOneLifecycleToken(t, ctx, tx, hashB)
		err := createNMinusOneNodeRaw(ctx, tx, orgID, "gateway-ambiguous", uuid.NewString())
		if err == nil || !strings.Contains(err.Error(), "node_lifecycle_enrollment_authorization_missing_or_ambiguous") {
			t.Fatalf("ambiguous N-1 binding error = %v", err)
		}
	})

	t.Run("authorization is transaction local", func(t *testing.T) {
		orgID := uuid.New()
		if _, err := pool.Exec(ctx, `INSERT INTO organizations(id,name,slug) VALUES($1,'D13b cross transaction',$2)`, orgID, "d13b-cross-"+orgID.String()[:8]); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, orgID) })
		tx1 := beginLifecycleMigrationTx(t, ctx, pool)
		defer tx1.Rollback(ctx) //nolint:errcheck
		_, claim, tokenHash := insertLifecycleMigrationToken(t, ctx, tx1, orgID, "gateway-cross-tx")
		consumeNMinusOneLifecycleToken(t, ctx, tx1, tokenHash)

		tx2 := beginLifecycleMigrationTx(t, ctx, pool)
		defer tx2.Rollback(ctx) //nolint:errcheck
		var backend1, backend2 int
		if err := tx1.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&backend1); err != nil {
			t.Fatal(err)
		}
		if err := tx2.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&backend2); err != nil {
			t.Fatal(err)
		}
		if backend1 == backend2 {
			t.Fatalf("pool did not lend distinct concurrent sessions: backend_pid=%d", backend1)
		}
		_, err := tx2.Exec(ctx, `INSERT INTO nodes(org_id,name,cert_serial,agent_version,lifecycle_claim) VALUES($1,$2,$3,'test',$4)`, orgID, "gateway-cross-tx", uuid.NewString(), claim)
		if err == nil || !strings.Contains(err.Error(), "node_lifecycle_claim_has_no_transaction_authorization") {
			t.Fatalf("cross-transaction authorization error = %v", err)
		}
	})

	t.Run("legacy token and node behavior is unchanged", func(t *testing.T) {
		tx := beginLifecycleMigrationTx(t, ctx, pool)
		defer tx.Rollback(ctx) //nolint:errcheck
		orgID := seedLifecycleMigrationOrg(t, ctx, tx)
		tokenID := uuid.New()
		tokenHash := []byte("legacy-" + uuid.NewString())
		if _, err := tx.Exec(ctx, `INSERT INTO node_join_tokens(id,org_id,node_name,token_hash,expires_at,enrols_kind) VALUES($1,$2,$3,$4,now()+interval '1 hour','gateway')`, tokenID, orgID, "legacy-gateway", tokenHash); err != nil {
			t.Fatal(err)
		}
		consumeNMinusOneLifecycleToken(t, ctx, tx, tokenHash)
		certSerial := "legacy-" + uuid.NewString()
		createNMinusOneNode(t, ctx, tx, orgID, "legacy-gateway", certSerial)
		var nodeClaim, consumedNode *uuid.UUID
		if err := tx.QueryRow(ctx, `SELECT lifecycle_claim FROM nodes WHERE cert_serial=$1`, certSerial).Scan(&nodeClaim); err != nil {
			t.Fatal(err)
		}
		if err := tx.QueryRow(ctx, `SELECT consumed_node_id FROM node_join_tokens WHERE id=$1`, tokenID).Scan(&consumedNode); err != nil {
			t.Fatal(err)
		}
		if nodeClaim != nil || consumedNode != nil {
			t.Fatalf("legacy path was rewritten: claim=%v consumed_node=%v", nodeClaim, consumedNode)
		}
		forceLifecycleConstraintCheck(t, ctx, tx)
	})

	var authorizations int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM node_lifecycle_enrollment_authorizations`).Scan(&authorizations); err != nil || authorizations != 0 {
		t.Fatalf("committed lifecycle transaction authorizations=%d err=%v", authorizations, err)
	}

	t.Run("usage sentinel survives lifecycle row deletion", func(t *testing.T) {
		tx := beginLifecycleMigrationTx(t, ctx, pool)
		defer tx.Rollback(ctx) //nolint:errcheck
		orgID, tokenID, _, _ := seedLifecycleMigrationToken(t, ctx, tx, "gateway-deleted-history")
		if err := tx.Commit(ctx); err != nil {
			t.Fatalf("commit first lifecycle persistence: %v", err)
		}
		if _, err := pool.Exec(ctx, `DELETE FROM node_join_tokens WHERE id=$1`, tokenID); err != nil {
			t.Fatalf("delete lifecycle token: %v", err)
		}
		if _, err := pool.Exec(ctx, `DELETE FROM organizations WHERE id=$1`, orgID); err != nil {
			t.Fatalf("delete lifecycle organization: %v", err)
		}
		var liveClaims, usage int
		if err := pool.QueryRow(ctx, `
			SELECT
				(SELECT count(*) FROM node_join_tokens WHERE lifecycle_claim IS NOT NULL) +
				(SELECT count(*) FROM nodes WHERE lifecycle_claim IS NOT NULL),
				(SELECT count(*) FROM k8s_lifecycle_claim_usage)`).Scan(&liveClaims, &usage); err != nil {
			t.Fatalf("read durable lifecycle usage: %v", err)
		}
		if liveClaims != 0 || usage != 1 {
			t.Fatalf("after lifecycle row deletion live_claims=%d usage=%d; want 0/1", liveClaims, usage)
		}

		downSQL, err := os.ReadFile("migrations/0131_k8s_lifecycle_claim_remint.down.sql")
		if err != nil {
			t.Fatal(err)
		}
		downConn, err := pool.Acquire(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer downConn.Release()
		if _, downErr := downConn.Conn().PgConn().Exec(ctx, string(downSQL)).ReadAll(); downErr == nil || !strings.Contains(downErr.Error(), "database lifecycle is forward-only") {
			t.Fatalf("0131 down after lifecycle row deletion = %v", downErr)
		}
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM k8s_lifecycle_claim_usage`).Scan(&usage); err != nil || usage != 1 {
			t.Fatalf("refused down lost durable lifecycle usage: count=%d err=%v", usage, err)
		}
	})

	t.Run("down locks writers before checking forward-only state", func(t *testing.T) {
		tx := beginLifecycleMigrationTx(t, ctx, pool)
		defer tx.Rollback(ctx) //nolint:errcheck
		orgID, tokenID, claim, _ := seedLifecycleMigrationToken(t, ctx, tx, "gateway-concurrent-down")

		downSQL, err := os.ReadFile("migrations/0131_k8s_lifecycle_claim_remint.down.sql")
		if err != nil {
			t.Fatal(err)
		}
		downConn, err := pool.Acquire(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer downConn.Release()
		const applicationName = "tnx_0131_down_lock_test"
		if _, err := downConn.Exec(ctx, "SET application_name = '"+applicationName+"'"); err != nil {
			t.Fatal(err)
		}
		downDone := make(chan error, 1)
		go func() {
			_, execErr := downConn.Conn().PgConn().Exec(ctx, string(downSQL)).ReadAll()
			downDone <- execErr
		}()

		deadline := time.Now().Add(5 * time.Second)
		for {
			var waitType string
			queryErr := pool.QueryRow(ctx, `
				SELECT COALESCE(wait_event_type, '')
				FROM pg_stat_activity
				WHERE application_name = $1`, applicationName).Scan(&waitType)
			if queryErr == nil && waitType == "Lock" {
				break
			}
			if queryErr != nil && !errors.Is(queryErr, pgx.ErrNoRows) {
				t.Fatalf("observe blocked down migration: %v", queryErr)
			}
			if time.Now().After(deadline) {
				t.Fatal("0131 down did not block behind the in-flight lifecycle writer")
			}
			time.Sleep(10 * time.Millisecond)
		}

		if err := tx.Commit(ctx); err != nil {
			t.Fatalf("commit lifecycle writer: %v", err)
		}
		select {
		case downErr := <-downDone:
			if downErr == nil || !strings.Contains(downErr.Error(), "database lifecycle is forward-only") {
				t.Fatalf("concurrent 0131 down error = %v", downErr)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("0131 down did not recheck the guard after the writer committed")
		}

		var storedClaim uuid.UUID
		if err := pool.QueryRow(ctx, `SELECT lifecycle_claim FROM node_join_tokens WHERE id=$1`, tokenID).Scan(&storedClaim); err != nil {
			t.Fatalf("read token after refused concurrent down: %v", err)
		}
		if storedClaim != claim {
			t.Fatalf("refused concurrent down changed lifecycle claim: got %s want %s", storedClaim, claim)
		}
		if _, err := pool.Exec(ctx, `DELETE FROM node_join_tokens WHERE id=$1`, tokenID); err != nil {
			t.Fatalf("clean concurrent-down token: %v", err)
		}
		if _, err := pool.Exec(ctx, `DELETE FROM organizations WHERE id=$1`, orgID); err != nil {
			t.Fatalf("clean concurrent-down organization: %v", err)
		}
	})

	// Once a lifecycle identity has been committed, contraction is deliberately
	// forward-only. Exercise the real golang-migrate refusal, including its dirty
	// version truth, and prove that the guard ran before any schema or data loss.
	t.Run("populated lifecycle state refuses down migration", func(t *testing.T) {
		tx := beginLifecycleMigrationTx(t, ctx, pool)
		orgID, tokenID, claim, tokenHash := seedLifecycleMigrationToken(t, ctx, tx, "gateway-forward-only")
		consumeNMinusOneLifecycleToken(t, ctx, tx, tokenHash)
		certSerial := "forward-only-" + uuid.NewString()
		createNMinusOneNode(t, ctx, tx, orgID, "gateway-forward-only", certSerial)
		if err := tx.Commit(ctx); err != nil {
			t.Fatalf("commit populated lifecycle state: %v", err)
		}

		err := db.MigrateTo(dsn, 130)
		if err == nil || !strings.Contains(err.Error(), "database lifecycle is forward-only") {
			t.Fatalf("populated 0131 down error = %v", err)
		}
		if version, dirty, ok, err := db.Version(dsn); err != nil || !ok || !dirty || version != 130 {
			t.Fatalf("refused 0131 down version=%d dirty=%v ok=%v err=%v; want 130/true/true", version, dirty, ok, err)
		}
		var tokenClaim, nodeClaim, consumedNode uuid.UUID
		if err := pool.QueryRow(ctx, `SELECT lifecycle_claim,consumed_node_id FROM node_join_tokens WHERE id=$1`, tokenID).Scan(&tokenClaim, &consumedNode); err != nil {
			t.Fatalf("read token after refused down: %v", err)
		}
		if err := pool.QueryRow(ctx, `SELECT lifecycle_claim FROM nodes WHERE cert_serial=$1`, certSerial).Scan(&nodeClaim); err != nil {
			t.Fatalf("read node after refused down: %v", err)
		}
		if tokenClaim != claim || nodeClaim != claim || consumedNode == uuid.Nil {
			t.Fatalf("refused down changed binding: token_claim=%s node_claim=%s node=%s want_claim=%s", tokenClaim, nodeClaim, consumedNode, claim)
		}
	})
}

func beginLifecycleMigrationTx(t *testing.T, ctx context.Context, pool *pgxpool.Pool) pgx.Tx {
	t.Helper()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return tx
}

func seedLifecycleMigrationOrg(t *testing.T, ctx context.Context, tx pgx.Tx) uuid.UUID {
	t.Helper()
	orgID := uuid.New()
	if _, err := tx.Exec(ctx, `INSERT INTO organizations(id,name,slug) VALUES($1,'D13b lifecycle',$2)`, orgID, "d13b-"+orgID.String()[:8]); err != nil {
		t.Fatal(err)
	}
	return orgID
}

func seedLifecycleMigrationToken(t *testing.T, ctx context.Context, tx pgx.Tx, nodeName string) (uuid.UUID, uuid.UUID, uuid.UUID, []byte) {
	t.Helper()
	orgID := seedLifecycleMigrationOrg(t, ctx, tx)
	tokenID, claim, tokenHash := insertLifecycleMigrationToken(t, ctx, tx, orgID, nodeName)
	return orgID, tokenID, claim, tokenHash
}

func insertLifecycleMigrationToken(t *testing.T, ctx context.Context, tx pgx.Tx, orgID uuid.UUID, nodeName string) (uuid.UUID, uuid.UUID, []byte) {
	t.Helper()
	tokenID, claim, requestID := uuid.New(), uuid.New(), uuid.New()
	tokenHash := []byte("lifecycle-" + uuid.NewString())
	if _, err := tx.Exec(ctx, `
		INSERT INTO node_join_tokens
			(id,org_id,node_name,token_hash,expires_at,enrols_kind,lifecycle_claim,
			 lifecycle_generation,lifecycle_request_id,lifecycle_token_sealed)
		VALUES($1,$2,$3,$4,now()+interval '1 hour','gateway',$5,1,$6,'sealed-test-token')`,
		tokenID, orgID, nodeName, tokenHash, claim, requestID); err != nil {
		t.Fatal(err)
	}
	return tokenID, claim, tokenHash
}

func consumeNMinusOneLifecycleToken(t *testing.T, ctx context.Context, tx pgx.Tx, tokenHash []byte) {
	t.Helper()
	if err := consumeNMinusOneLifecycleTokenRaw(ctx, tx, tokenHash); err != nil {
		t.Fatalf("N-1 ConsumeJoinToken shape: %v", err)
	}
}

func consumeNMinusOneLifecycleTokenRaw(ctx context.Context, tx pgx.Tx, tokenHash []byte) error {
	values, destinations := make([]any, 10), make([]any, 10)
	for i := range values {
		destinations[i] = &values[i]
	}
	return tx.QueryRow(ctx, nMinusOneConsumeJoinToken, tokenHash).Scan(destinations...)
}

func createNMinusOneNode(t *testing.T, ctx context.Context, tx pgx.Tx, orgID uuid.UUID, nodeName, certSerial string) {
	t.Helper()
	if err := createNMinusOneNodeRaw(ctx, tx, orgID, nodeName, certSerial); err != nil {
		t.Fatalf("N-1 CreateNode shape: %v", err)
	}
}

func createNMinusOneNodeRaw(ctx context.Context, tx pgx.Tx, orgID uuid.UUID, nodeName, certSerial string) error {
	values, destinations := make([]any, 25), make([]any, 25)
	for i := range values {
		destinations[i] = &values[i]
	}
	return tx.QueryRow(ctx, nMinusOneCreateNode,
		orgID, nodeName, certSerial, "test", time.Now().Add(time.Hour), nil, nil, "gateway",
	).Scan(destinations...)
}

func assertLifecycleMigrationBinding(t *testing.T, ctx context.Context, tx pgx.Tx, tokenID uuid.UUID, certSerial string, claim uuid.UUID) {
	t.Helper()
	var nodeID, nodeClaim, consumedNode uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT id,lifecycle_claim FROM nodes WHERE cert_serial=$1`, certSerial).Scan(&nodeID, &nodeClaim); err != nil {
		t.Fatal(err)
	}
	if err := tx.QueryRow(ctx, `SELECT consumed_node_id FROM node_join_tokens WHERE id=$1`, tokenID).Scan(&consumedNode); err != nil {
		t.Fatal(err)
	}
	if nodeClaim != claim || consumedNode != nodeID {
		t.Fatalf("claim binding node=%s claim=%s token_node=%s, want claim=%s", nodeID, nodeClaim, consumedNode, claim)
	}
	var authorizations int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM node_lifecycle_enrollment_authorizations WHERE token_id=$1`, tokenID).Scan(&authorizations); err != nil || authorizations != 0 {
		t.Fatalf("consumed authorization rows=%d err=%v", authorizations, err)
	}
}

func assertLifecycleMigrationTokenUnconsumed(t *testing.T, ctx context.Context, pool *pgxpool.Pool, tokenID uuid.UUID) {
	t.Helper()
	var consumedAt *time.Time
	var sealed *string
	var consumedNode *uuid.UUID
	if err := pool.QueryRow(ctx, `
		SELECT consumed_at,lifecycle_token_sealed,consumed_node_id
		FROM node_join_tokens WHERE id=$1`, tokenID).Scan(&consumedAt, &sealed, &consumedNode); err != nil {
		t.Fatalf("read token after refused enrollment rollback: %v", err)
	}
	if consumedAt != nil || consumedNode != nil || sealed == nil || *sealed != "sealed-test-token" {
		t.Fatalf("refused enrollment was not atomic: consumed_at=%v node=%v sealed=%v", consumedAt, consumedNode, sealed)
	}
}

func forceLifecycleConstraintCheck(t *testing.T, ctx context.Context, tx pgx.Tx) {
	t.Helper()
	if _, err := tx.Exec(ctx, `SET CONSTRAINTS node_lifecycle_consumption_must_bind IMMEDIATE`); err != nil {
		t.Fatalf("deferred lifecycle binding constraint: %v", err)
	}
}
