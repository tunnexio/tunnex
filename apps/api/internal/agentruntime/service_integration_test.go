package agentruntime

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
)

type recordingRuntimeNotifier struct {
	mu  sync.Mutex
	ids []uuid.UUID
}

func (n *recordingRuntimeNotifier) Notify(id uuid.UUID) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.ids = append(n.ids, id)
}

func (n *recordingRuntimeNotifier) snapshot() []uuid.UUID {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]uuid.UUID(nil), n.ids...)
}

func TestRuntimeServicePostgresContract(t *testing.T) {
	dsn := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL to run this integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()

	q := sqlc.New(pool)
	svc := New(q, func(context.Context, uuid.UUID) (OptInState, error) { return OptInEnabled, nil })
	org, otherOrg, owner, node := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	agent, human, otherDevice := uuid.New(), uuid.New(), uuid.New()
	seed := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	seed(`INSERT INTO organizations (id,name,slug,pool_cidr) VALUES ($1,'F04',$2,'10.97.0.0/24'),($3,'F04 other',$4,'10.98.0.0/24')`, org, "f04-"+org.String()[:8], otherOrg, "f04-"+otherOrg.String()[:8])
	seed(`INSERT INTO users (id,email) VALUES ($1,$2)`, owner, "f04-"+owner.String()[:8]+"@example.com")
	seed(`INSERT INTO nodes (id,org_id,name,cert_serial,wg_public_key,endpoint) VALUES ($1,$2,'gw',$3,$4,'gateway.example:51820')`, node, org, "f04-cert-"+node.String(), "f04-gateway-key-"+node.String())
	seed(`INSERT INTO devices (id,org_id,user_id,node_id,name,public_key,assigned_ip,status,kind) VALUES ($1,$2,$3,$4,'agent','f04-agent-key','10.97.0.2','active','agent'),($5,$2,$3,$4,'human','f04-human-key','10.97.0.3','active','human'),($6,$7,$3,$4,'other-org-agent','f04-other-key','10.98.0.2','active','agent')`, agent, org, owner, node, human, otherDevice, otherOrg)
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM organizations WHERE id IN ($1,$2)`, org, otherOrg)
	})

	valid := "tnx_runtime_valid_" + agent.String()
	h := sha256.Sum256([]byte(valid))
	seed(`INSERT INTO agent_runtime_credentials (org_id,device_id,token_hash) VALUES ($1,$2,$3)`, org, agent, h[:])
	if got, err := svc.Authenticate(ctx, valid); err != nil || got.OrgID != org || got.DeviceID != agent {
		t.Fatalf("valid runtime auth = %#v, %v", got, err)
	}
	seed(`UPDATE devices SET status='pending' WHERE id=$1`, agent)
	if got, err := svc.Authenticate(ctx, valid); err != nil || got.OrgID != org || got.DeviceID != agent {
		t.Fatalf("pending runtime auth = %#v, %v; want identity-only wait", got, err)
	}
	if cfg, unchanged, err := svc.Poll(ctx, Identity{OrgID: org, DeviceID: agent}, 0, 1, "v-f04"); err != nil || !unchanged || cfg.Revision != 0 {
		t.Fatalf("pending runtime poll = %#v, unchanged=%v, err=%v; want no-config wait", cfg, unchanged, err)
	}
	seed(`UPDATE devices SET status='active' WHERE id=$1`, agent)
	for name, token := range map[string]string{
		"malformed": "not-a-bearer", "unknown": "tnx_runtime_unknown", "human/session bearer": "tnx_human_like",
	} {
		if _, err := svc.Authenticate(ctx, token); err != ErrUnauthorized {
			t.Errorf("%s auth error = %v, want uniform unauthorized", name, err)
		}
	}
	seed(`UPDATE agent_runtime_credentials SET revoked_at=now() WHERE org_id=$1 AND device_id=$2`, org, agent)
	if _, err := svc.Authenticate(ctx, valid); err != ErrUnauthorized {
		t.Errorf("revoked auth error = %v, want uniform unauthorized", err)
	}
	seed(`UPDATE agent_runtime_credentials SET revoked_at=NULL WHERE org_id=$1 AND device_id=$2`, org, agent)
	cross := "tnx_runtime_cross_org_" + otherDevice.String()
	ch := sha256.Sum256([]byte(cross))
	seed(`INSERT INTO agent_runtime_credentials (org_id,device_id,token_hash) VALUES ($1,$2,$3)`, otherOrg, otherDevice, ch[:])
	if got, err := svc.Authenticate(ctx, cross); err != nil || got.OrgID != otherOrg || got.DeviceID != otherDevice {
		t.Errorf("cross-org credential binding = %#v, %v; credential must resolve only to its exact org/device", got, err)
	}

	id := Identity{OrgID: org, DeviceID: agent}
	cfg, unchanged, err := svc.Poll(ctx, id, 0, 1, "v-f04")
	if err != nil || unchanged || cfg.Revision != 1 || cfg.DeviceID != agent || cfg.OrgID != org || cfg.Address != "10.97.0.2/32" {
		t.Fatalf("poll initial = %#v, unchanged=%v, err=%v", cfg, unchanged, err)
	}
	if _, unchanged, err := svc.Poll(ctx, id, 1, 1, "v-f04"); err != nil || !unchanged {
		t.Fatalf("poll unchanged = unchanged=%v, err=%v", unchanged, err)
	}
	seed(`UPDATE devices SET status='suspended' WHERE id=$1`, agent)
	if _, err := svc.Authenticate(ctx, valid); err != ErrUnauthorized {
		t.Fatalf("suspended runtime auth = %v, want uniform unauthorized", err)
	}
	if _, _, err := svc.Poll(ctx, id, 0, 1, "v-f04"); err != ErrRuntimeStateMissing {
		t.Fatalf("suspended poll = %v, want no config", err)
	}
	seed(`UPDATE devices SET status='active' WHERE id=$1`, agent)
	if _, err := q.BumpAgentDesiredRevision(ctx, sqlc.BumpAgentDesiredRevisionParams{DeviceID: agent, OrgID: org}); err != nil {
		t.Fatal(err)
	}
	if cfg, unchanged, err := svc.Poll(ctx, id, 1, 1, "v-f04"); err != nil || unchanged || cfg.Revision != 2 {
		t.Fatalf("resumed poll = %#v, unchanged=%v, err=%v", cfg, unchanged, err)
	}
	if err := svc.Report(ctx, id, 0, 2, "v-f04", ""); err != ErrInvalidReport {
		t.Fatalf("ahead/errorless report = %v, want invalid report", err)
	}
	if err := svc.Report(ctx, id, 2, 1, "v-f04", "apply_failed"); err != ErrInvalidReport {
		t.Fatalf("backwards report = %v, want invalid report", err)
	}

	if _, err := q.BumpAgentDesiredRevision(ctx, sqlc.BumpAgentDesiredRevisionParams{DeviceID: agent, OrgID: org}); err != nil {
		t.Fatal(err)
	}
	if _, err := q.BumpAgentDesiredRevision(ctx, sqlc.BumpAgentDesiredRevisionParams{DeviceID: agent, OrgID: org}); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errCh := make(chan error, 2)
	for _, revision := range []int64{2, 3} {
		wg.Add(1)
		go func(revision int64) {
			defer wg.Done()
			errCh <- svc.Report(ctx, id, revision, revision, "v-f04", "")
		}(revision)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatalf("concurrent report: %v", err)
		}
	}
	state, err := q.GetAgentRuntimeState(ctx, sqlc.GetAgentRuntimeStateParams{DeviceID: agent, OrgID: org})
	if err != nil || state.AppliedRevision != 3 || state.LastAttemptedRevision != 3 {
		t.Fatalf("monotonic state = %#v, err=%v", state, err)
	}
	if err := svc.Report(ctx, id, 3, 4, "v-f04", "apply_failed"); err != nil {
		t.Fatalf("bounded apply error report: %v", err)
	}
	state, err = q.GetAgentRuntimeState(ctx, sqlc.GetAgentRuntimeStateParams{DeviceID: agent, OrgID: org})
	if err != nil || state.LastErrorCode == nil || *state.LastErrorCode != "apply_failed" {
		t.Fatalf("stored stable error = %#v, err=%v", state.LastErrorCode, err)
	}
	if err := svc.Report(ctx, id, 4, 4, "v-f04", ""); err != nil {
		t.Fatalf("last-good success report: %v", err)
	}
	state, err = q.GetAgentRuntimeState(ctx, sqlc.GetAgentRuntimeStateParams{DeviceID: agent, OrgID: org})
	if err != nil || state.AppliedRevision != 4 || state.LastErrorCode != nil {
		t.Fatalf("last-good cleared state = %#v, err=%v", state, err)
	}

	notifier := &recordingRuntimeNotifier{}
	svc.SetNotifier(notifier)
	if _, err := q.BumpAgentDesiredRevision(ctx, sqlc.BumpAgentDesiredRevisionParams{DeviceID: agent, OrgID: org}); err != nil {
		t.Fatal(err)
	}
	if err := svc.Report(ctx, id, 5, 5, "v-f07", ""); err != nil {
		t.Fatalf("revision-changing report: %v", err)
	}
	if err := svc.Report(ctx, id, 5, 5, "v-f07", ""); err != nil {
		t.Fatalf("same-revision heartbeat: %v", err)
	}
	if got := notifier.snapshot(); len(got) != 1 || got[0] != node {
		t.Fatalf("gateway notifications = %v, want exactly assigned node %s", got, node)
	}

	requested, err := q.RequestAgentRuntimeCredentialRotation(ctx, sqlc.RequestAgentRuntimeCredentialRotationParams{
		OrgID: org, DeviceID: agent,
		RotationDeadline:    pgtype.Timestamptz{Time: time.Now().Add(time.Hour), Valid: true},
		RotationRequestedBy: pgtype.UUID{Bytes: owner, Valid: true},
	})
	if err != nil || !requested.RotationRequestedAt.Valid {
		t.Fatalf("request rotation = %#v, %v", requested, err)
	}
	oldIdentity, err := svc.Authenticate(ctx, valid)
	if err != nil || oldIdentity.CredentialRevision != 1 {
		t.Fatalf("old identity = %#v, %v", oldIdentity, err)
	}
	if cfg, unchanged, err := svc.Poll(ctx, oldIdentity, 4, 1, "v-f05"); err != nil || unchanged || cfg.CredentialRotationRevision == nil || *cfg.CredentialRotationRevision != 2 {
		t.Fatalf("rotation poll = %#v, unchanged=%v, err=%v", cfg, unchanged, err)
	}
	candidate := "tnx_runtime_candidate_" + agent.String()
	candidateHash := sha256.Sum256([]byte(candidate))
	hashHex := fmt.Sprintf("%x", candidateHash[:])
	if err := svc.PrepareCredentialCandidate(ctx, oldIdentity, 2, hashHex); err != nil {
		t.Fatalf("prepare candidate: %v", err)
	}
	if err := svc.PrepareCredentialCandidate(ctx, oldIdentity, 2, hashHex); err != nil {
		t.Fatalf("idempotent prepare retry: %v", err)
	}
	if _, err := svc.AuthenticateCurrent(ctx, candidate); err != ErrUnauthorized {
		t.Fatalf("candidate must not promote on prepare authentication: %v", err)
	}
	if _, err := svc.Authenticate(ctx, valid); err != nil {
		t.Fatalf("old bearer before successor proof: %v", err)
	}
	candidateIdentity, err := svc.Authenticate(ctx, candidate)
	if err != nil || candidateIdentity.CredentialRevision != 2 {
		t.Fatalf("candidate promotion = %#v, %v", candidateIdentity, err)
	}
	if _, err := svc.Authenticate(ctx, valid); err != ErrUnauthorized {
		t.Fatalf("old bearer after promotion = %v, want uniform unauthorized", err)
	}

	if _, err := q.RequestAgentRuntimeCredentialRotation(ctx, sqlc.RequestAgentRuntimeCredentialRotationParams{
		OrgID: org, DeviceID: agent,
		RotationDeadline:    pgtype.Timestamptz{Time: time.Now().Add(time.Hour), Valid: true},
		RotationRequestedBy: pgtype.UUID{Bytes: owner, Valid: true},
	}); err != nil {
		t.Fatal(err)
	}
	wgRequested, err := q.RequestAgentWireGuardRotation(ctx, sqlc.RequestAgentWireGuardRotationParams{
		OrgID: org, ID: agent,
		Deadline:    pgtype.Timestamptz{Time: time.Now().Add(time.Hour), Valid: true},
		RequestedBy: pgtype.UUID{Bytes: owner, Valid: true},
	})
	if err != nil || wgRequested.RequestedRevision == nil || *wgRequested.RequestedRevision != 2 {
		t.Fatalf("request WireGuard rotation = %#v, %v", wgRequested, err)
	}
	if cfg, unchanged, err := svc.Poll(ctx, candidateIdentity, 4, 1, "v-f05"); err != nil || unchanged || cfg.WireGuardRotationRevision == nil || *cfg.WireGuardRotationRevision != 2 || cfg.WireGuardRotationState == nil || *cfg.WireGuardRotationState != "requested" {
		t.Fatalf("WireGuard rotation poll = %#v, unchanged=%v, err=%v", cfg, unchanged, err)
	}
	wgCandidate := "WlEiCXJIkuDu09Ji0dvI1RwdkbLwkZ+qdR/M0r6/I94="
	if err := svc.PrepareWireGuardCandidate(ctx, candidateIdentity, 2, wgCandidate); err != nil {
		t.Fatalf("prepare WireGuard candidate: %v", err)
	}
	if err := svc.PrepareWireGuardCandidate(ctx, candidateIdentity, 2, wgCandidate); err != nil {
		t.Fatalf("idempotent WireGuard prepare: %v", err)
	}
	next := "tnx_runtime_cancelled_" + agent.String()
	nextHash := sha256.Sum256([]byte(next))
	if err := svc.PrepareCredentialCandidate(ctx, candidateIdentity, 3, fmt.Sprintf("%x", nextHash[:])); err != nil {
		t.Fatal(err)
	}
	seed(`UPDATE devices SET status='suspended' WHERE id=$1`, agent)
	if wg, err := q.GetAgentWireGuardRotation(ctx, sqlc.GetAgentWireGuardRotationParams{OrgID: org, DeviceID: agent}); err != nil || wg.State != "current" || wg.CandidatePublicKey != nil {
		t.Fatalf("suspend did not cancel WireGuard candidate = %#v, %v", wg, err)
	}
	if _, err := svc.Authenticate(ctx, next); err != ErrUnauthorized {
		t.Fatalf("suspended candidate = %v, want unauthorized", err)
	}
	seed(`UPDATE devices SET status='active' WHERE id=$1`, agent)
	if _, err := svc.Authenticate(ctx, candidate); err != nil {
		t.Fatalf("current bearer after resume: %v", err)
	}
	seed(`UPDATE devices SET status='revoked' WHERE id=$1`, agent)
	if _, err := svc.Authenticate(ctx, candidate); err != ErrUnauthorized {
		t.Fatalf("revoked current bearer = %v, want unauthorized", err)
	}
}
