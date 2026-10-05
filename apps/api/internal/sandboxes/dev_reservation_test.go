package sandboxes

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/testpostgres"
	"github.com/tunnexio/tunnex/apps/api/internal/wgkey"
)

// Exact public historical IDs are seeded ONLY into separate disposable databases.
// Profile attestations and the unsaved peer status/gateway are synthetic fixtures,
// never evidence that production matches this contract or is ready to activate.
func devReservationTestBinding() BoundedRuntimeBinding {
	b := persistentTestBinding()
	b.OrgID, b.CreatorID, b.TerminalDeviceID, b.GatewayID = devReservedOrg, devReservedCreator, devReservedDevice, devOperationalGateway
	b.DevReservation = &DevHistoricalReservation{PeerStatus: "active", LaunchGatewayID: devOperationalGateway, PhysicalCleanupEvidence: "synthetic-fixture-physical-erasure"}
	return b
}
func TestPersistentDevReservationBindingAndLegacyEffectsDenied(t *testing.T) {
	b := devReservationTestBinding()
	if b.Validate() != nil {
		t.Fatal("fixture binding invalid")
	}
	for _, change := range []func(*BoundedRuntimeBinding){
		func(b *BoundedRuntimeBinding) { b.OrgID = uuid.New() }, func(b *BoundedRuntimeBinding) { b.CreatorID = uuid.New() }, func(b *BoundedRuntimeBinding) { b.GatewayID = uuid.New() }, func(b *BoundedRuntimeBinding) { b.TerminalDeviceID = uuid.New() },
		func(b *BoundedRuntimeBinding) { b.DevReservation.PeerStatus = "unknown" }, func(b *BoundedRuntimeBinding) { b.DevReservation.LaunchGatewayID = uuid.Nil }, func(b *BoundedRuntimeBinding) { b.DevReservation.PhysicalCleanupEvidence = "" }, func(b *BoundedRuntimeBinding) { b.Profiles[0].TemplateID = devReservedTemplate }, func(b *BoundedRuntimeBinding) { b.Mode = "trial" },
	} {
		copy := b
		r := *b.DevReservation
		copy.DevReservation = &r
		copy.Profiles = append([]QualifiedRuntimeProfile(nil), b.Profiles...)
		change(&copy)
		if copy.Validate() == nil {
			t.Fatal("reservation broadened", copy)
		}
	}
	for _, reservation := range []*DevHistoricalReservation{b.DevReservation, nil} {
		copy := b
		copy.DevReservation = reservation
		s, c, p := persistentRPCFixture(t, copy)
		a := testAuthorization(copy, 0)
		a.SandboxID = devReservedSandbox
		if err := c.AuthorizeRuntime(context.Background(), a); !errors.Is(err, ErrForbidden) {
			t.Fatal("legacy authorized", err)
		}
		for _, op := range []string{"inspect", "resolve", "materialize", "create", "start", "stop", "delete", "enroll", "apply-network", "remove-network", "gateway-absence", "retire", "retire-close"} {
			if _, err := s.dispatch(context.Background(), workerRequest{Version: workerRPCVersion, Operation: op, ID: devReservedSandbox, Generation: 2}); !errors.Is(err, ErrForbidden) {
				t.Fatal("legacy effect", op, err)
			}
		}
		if p.status.Exists || s.active != nil {
			t.Fatal("legacy effect/pin occurred")
		}
		// A protected old-identity pin cannot be loaded or removed as crash recovery.
		pin := workerPin{Binding: copy, SandboxID: devReservedSandbox, Authorization: &a}
		raw, _ := json.Marshal(pin)
		if err := s.writeRecord("api-binding.json", raw); err != nil {
			t.Fatal(err)
		}
		if s.loadPin() == nil {
			t.Fatal("legacy durable pin adopted")
		}
		if _, err := s.ControlRoot.Stat("api-binding.json"); err != nil {
			t.Fatal("legacy pin erased", err)
		}
	}
}

func newDevReservationFixture(t *testing.T) (fixture, BoundedRuntimeBinding, uuid.UUID) {
	t.Helper()
	ctx, pool := testpostgres.New(t)
	b := devReservationTestBinding()
	f := fixture{ctx: ctx, pool: pool, store: NewStore(pool), org: b.OrgID, user: b.CreatorID, other: uuid.New(), template: b.Profiles[0].TemplateID, node: b.GatewayID, sshPublicKey: publicTerminalKey(t)}
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO organizations(id,name,slug,pool_cidr,zero_trust_mode,sandboxes_enabled,max_sandboxes,max_sandboxes_per_user) VALUES($1,'dev reservation fixture',$2,'10.99.0.0/24','enforcing',true,2,2)`, f.org, f.org.String())
	for _, id := range []uuid.UUID{f.user, f.other} {
		exec(`INSERT INTO users(id,email,name,email_verified_at) VALUES($1,$2,'fixture',now())`, id, id.String()+"@example.test")
		exec(`INSERT INTO memberships(org_id,user_id,role,roles) VALUES($1,$2,'owner',ARRAY['owner'])`, f.org, id)
	}
	_, gatewayKey, _ := wgkey.Generate()
	exec(`INSERT INTO nodes(id,org_id,name,cert_serial,endpoint,wg_public_key,status,policy_reported_at) VALUES($1,$2,'fixture gateway',$3,'127.0.0.1:51820',$4,'active',now())`, f.node, f.org, f.node.String(), gatewayKey)
	seedBoundedTerminalDevice(t, f, b)
	for _, p := range b.Profiles {
		exec(`INSERT INTO sandbox_templates(id,org_id,name,image_digest,maximum_scope,memory_mib,max_ttl_seconds,enabled) VALUES($1,$2,$3,$4,'[]',128,900,true)`, p.TemplateID, f.org, p.QualificationEvidence, p.ConfigDigest)
	}
	exec(`INSERT INTO sandbox_templates(id,org_id,name,image_digest,maximum_scope,memory_mib,max_ttl_seconds,enabled) VALUES($1,$2,'historical fixture',$3,'[]',128,3600,false)`, devReservedTemplate, f.org, devReservedImage)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	txexec := func(q string, args ...any) {
		t.Helper()
		if _, err := tx.Exec(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	_, peerKey, _ := wgkey.Generate()
	txexec(`INSERT INTO devices(id,org_id,user_id,node_id,name,public_key,assigned_ip,kind,status,health_blocked) VALUES($1,$2,$3,$4,'historical fixture',$5,'10.99.0.10','sandbox','active',true)`, devReservedPeer, f.org, f.user, f.node, peerKey)
	txexec(`INSERT INTO sandboxes(id,org_id,creator_id,template_id,name,requested_scope,peer_id,desired_state,observed_state,generation,idempotency_key,request_hash,created_at,expires_at,terminal_device_id) VALUES($1,$2,$3,$4,'historical fixture','[]',$5,'deleted','deleting',2,'historical-fixture',$6,$7,$8,$9)`, devReservedSandbox, f.org, f.user, devReservedTemplate, devReservedPeer, make([]byte, 32), devReservedCreated, devReservedExpiry, b.TerminalDeviceID)
	txexec(`INSERT INTO sandbox_runtime_bindings(sandbox_id,org_id,spec_hash,image_digest,memory_mib,cpus,pids,runtime_id) VALUES($1,$2,$3,$4,128,1,128,$5)`, devReservedSandbox, f.org, devReservedSpec, devReservedImage, devReservedRuntime)
	txexec(`INSERT INTO sandbox_runtime_credentials(org_id,sandbox_id,peer_id,token_hash,revoked_at) VALUES($1,$2,$3,$4,now())`, f.org, devReservedSandbox, devReservedPeer, make([]byte, 32))
	token, operation := uuid.New(), uuid.New()
	txexec(`INSERT INTO sandbox_bootstrap_tokens(id,org_id,sandbox_id,gateway_node_id,generation,token_hash,created_at,expires_at,consumed_at) VALUES($1,$2,$3,$4,1,$5,$6,$7,$6)`, token, f.org, devReservedSandbox, f.node, make([]byte, 32), devReservedCreated, devReservedExpiry)
	txexec(`INSERT INTO sandbox_launch_operations(id,org_id,sandbox_id,generation,gateway_node_id,runtime_id,spec_hash,bootstrap_token_id,confirmed_at) VALUES($1,$2,$3,1,$4,$5,$6,$7,$8)`, operation, f.org, devReservedSandbox, f.node, devReservedRuntime, devReservedSpec, token, devReservedCreated)
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err = f.store.WithBoundedRuntime(b); err != nil {
		t.Fatal(err)
	}
	return f, b, operation
}
func devInput(f fixture, b BoundedRuntimeBinding, index int) CreateInput {
	return CreateInput{Name: "synthetic work", TemplateID: b.Profiles[index].TemplateID, TTLSeconds: 900, IdempotencyKey: uuid.NewString(), Requested: []Scope{}, SSHPublicKeys: []string{f.sshPublicKey}}
}
func devExec(t *testing.T, f fixture, q string, args ...any) {
	t.Helper()
	if _, err := f.pool.Exec(f.ctx, q, args...); err != nil {
		t.Fatal(err)
	}
}
func devStatus(t *testing.T, f fixture) SetupStatus {
	t.Helper()
	out, err := f.store.Setup(f.ctx, f.org, f.user)
	if err != nil {
		t.Fatal(err)
	}
	return out
}
func assertHistoricalPending(t *testing.T, f fixture, b BoundedRuntimeBinding) {
	t.Helper()
	state, err := b.reservationState(f.ctx, f.pool)
	if err != nil || state != "pending" {
		t.Fatal("historical changed", state, err)
	}
}
func TestPersistentDevReservationPostgresConcurrentOneWorkloadAndSequentialProfiles(t *testing.T) {
	f, b, _ := newDevReservationFixture(t)
	setup := devStatus(t, f)
	if len(setup.BlockedReasons) != 0 || setup.RuntimeLimits.MaxRetained != 2 || setup.RuntimeLimits.MaxWorkloads != 1 || setup.RuntimeLimits.Retained != 1 || setup.RuntimeLimits.Workloads != 0 || setup.RuntimeLimits.ReservationState != "pending" {
		t.Fatal("initial reservation/limits", setup)
	}
	server, client, provider := persistentRPCFixture(t, b)
	invoker := &enrollmentInvokerFixture{f: f}
	files, err := NewFileBootstrapTransport(server.ControlRoot, "https://fixture.example", invoker)
	if err != nil {
		t.Fatal(err)
	}
	network := &composedNetworkFixture{f: f}
	server.Files, server.Network, server.Gateway, server.Probe = files, network, network, network
	o, err := NewAPIOrchestrator(f.store, b, client, &readinessPolicyFixture{hash: "fixture-canonical"}, launchTestSealer(t))
	if err != nil {
		t.Fatal(err)
	}
	type result struct {
		sb  Sandbox
		err error
	}
	results := make(chan result, 2)
	var start sync.WaitGroup
	start.Add(2)
	for index := range 2 {
		go func(index int) {
			start.Done()
			start.Wait()
			sb, _, err := f.store.Create(f.ctx, f.org, f.user, devInput(f, b, index))
			results <- result{sb, err}
		}(index)
	}
	a, c := <-results, <-results
	if (a.err == nil) == (c.err == nil) || (!errors.Is(a.err, ErrQuota) && !errors.Is(c.err, ErrQuota)) {
		t.Fatal("reservation quota race", a.err, c.err)
	}
	if a.err != nil {
		a = c
	}
	busy := devStatus(t, f)
	if busy.RuntimeLimits.Retained != 2 || busy.RuntimeLimits.Workloads != 1 || !containsReason(busy.BlockedReasons, "runtime_workload_quota_reached") {
		t.Fatal("busy limits", busy)
	}
	// Exercise the full synthetic API/worker launch, fresh policy ACK and image
	// bootstrap before cleaning. This is source fixture evidence only.
	if err = o.batch(f.ctx, func(_ uuid.UUID, e error) { t.Error(e) }); err != nil {
		t.Fatal(err)
	}
	started, err := f.store.Get(f.ctx, f.org, f.user, a.sb.Identity.ID)
	if err != nil || started.State != StateReady {
		t.Fatal("first fixture profile", started, err)
	}
	assertHistoricalPending(t, f, b)
	// Genuine NEW-workload cleanup cannot bypass its retirement receipt or touch
	// the historical identity, allocation, credentials or missing proof.
	sb, err := f.store.SetDesired(f.ctx, f.org, f.user, a.sb.Identity.ID, 1, "deleted")
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err = o.batch(f.ctx, func(_ uuid.UUID, e error) { t.Error(e) }); err != nil {
			t.Fatal(err)
		}
	}
	sb, err = f.store.Get(f.ctx, f.org, f.user, sb.Identity.ID)
	if err != nil || sb.State != StateDeleted || server.active != nil || provider.starts != 1 {
		t.Fatal("new cleanup", sb, err)
	}
	assertHistoricalPending(t, f, b)
	// Actual admission of another immutable profile after new cleanup+retirement.
	index := 0
	if a.sb.TemplateVersionID == b.Profiles[0].TemplateID {
		index = 1
	}
	second, _, err := f.store.Create(f.ctx, f.org, f.user, devInput(f, b, index))
	if err != nil || second.TemplateVersionID == a.sb.TemplateVersionID {
		t.Fatal("sequential profile reuse", err)
	}
	if err = o.batch(f.ctx, func(_ uuid.UUID, e error) { t.Error(e) }); err != nil {
		t.Fatal(err)
	}
	started, err = f.store.Get(f.ctx, f.org, f.user, second.Identity.ID)
	if err != nil || started.State != StateReady || invoker.calls != 2 || provider.starts != 2 {
		t.Fatal("second fixture profile", started, err)
	}
	if _, err = o.authorizeJob(f.ctx, devReservedSandbox); !errors.Is(err, ErrForbidden) {
		t.Fatal("historical API authorization", err)
	}
	if err = o.retire(f.ctx, devReservedSandbox); !errors.Is(err, ErrForbidden) {
		t.Fatal("historical API retirement", err)
	}
	assertHistoricalPending(t, f, b)
}

func TestPersistentDevReservationPostgresCountsEntireOrgAndUnfinishedHistory(t *testing.T) {
	for _, state := range []string{"stopped", "deleting", "deleted-unretired", "deleted-no-binding", "deleted-retired"} {
		t.Run(state, func(t *testing.T) {
			f, b, _ := newDevReservationFixture(t)
			otherTemplate, id := uuid.New(), uuid.New()
			devExec(t, f, `INSERT INTO sandbox_templates(id,org_id,name,image_digest,maximum_scope,memory_mib,max_ttl_seconds) VALUES($1,$2,'outside allowlist',$3,'[]',128,900)`, otherTemplate, f.org, "sha256:"+strings.Repeat("f", 64))
			desired, observed := "deleted", "deleted"
			if state == "stopped" {
				desired, observed = "stopped", "stopped"
			}
			if state == "deleting" {
				observed = "deleting"
			}
			devExec(t, f, `INSERT INTO sandboxes(id,org_id,creator_id,template_id,name,requested_scope,desired_state,observed_state,idempotency_key,request_hash,expires_at) VALUES($1,$2,$3,$4,'outside fixture','[]',$5,$6,$7,$8,now()+interval '15 minutes')`, id, f.org, f.other, otherTemplate, desired, observed, id.String(), make([]byte, 32))
			if state != "deleted-no-binding" {
				devExec(t, f, `INSERT INTO sandbox_runtime_bindings(sandbox_id,org_id,spec_hash,image_digest,memory_mib,cpus,pids) VALUES($1,$2,$3,$4,128,1,64)`, id, f.org, strings.Repeat("f", 64), "sha256:"+strings.Repeat("f", 64))
			}
			if state == "deleted-retired" {
				devExec(t, f, `UPDATE sandbox_runtime_bindings SET worker_retired_at=now() WHERE sandbox_id=$1`, id)
			}
			_, _, err := f.store.Create(f.ctx, f.org, f.user, devInput(f, b, 0))
			if state == "deleted-retired" {
				if err != nil {
					t.Fatal("completed history held", err)
				}
			} else if !errors.Is(err, ErrQuota) {
				t.Fatal("outside unfinished record ignored", state, err)
			}
			out := devStatus(t, f)
			if !containsReason(out.BlockedReasons, "runtime_workload_quota_reached") {
				t.Fatal("Setup disagrees", out)
			}
		})
	}
}

func TestPersistentDevReservationPostgresDriftClosesAdmissionButAllowsCleanup(t *testing.T) {
	f, b, _ := newDevReservationFixture(t)
	_, client, _ := persistentRPCFixture(t, b)
	o, err := NewAPIOrchestrator(f.store, b, client, &readinessPolicyFixture{hash: "fixture-canonical"}, launchTestSealer(t))
	if err != nil {
		t.Fatal(err)
	}
	sb, _, err := f.store.Create(f.ctx, f.org, f.user, devInput(f, b, 0))
	if err != nil {
		t.Fatal(err)
	}
	devExec(t, f, `UPDATE devices SET health_blocked=false WHERE id=$1`, devReservedPeer)
	if _, _, err = f.store.Create(f.ctx, f.org, f.user, devInput(f, b, 1)); !errors.Is(err, ErrDisabled) {
		t.Fatal("drift admitted", err)
	}
	if !containsReason(devStatus(t, f).BlockedReasons, "historical_reservation_invalid") {
		t.Fatal("drift hidden")
	}
	if _, err = o.authorizeJob(f.ctx, sb.Identity.ID); !errors.Is(err, ErrDisabled) {
		t.Fatal("drift grant", err)
	}
	conn, release, err := f.store.acquireLifecycle(f.ctx, sb.Identity.ID)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.store.prepareStart(f.ctx, conn, sb.Identity.ID)
	release()
	if !errors.Is(err, ErrDisabled) {
		t.Fatal("drift direct launch", err)
	}
	if _, err = f.store.SetDesired(f.ctx, f.org, f.user, sb.Identity.ID, 1, "deleted"); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err = o.batch(f.ctx, func(_ uuid.UUID, e error) { t.Error(e) }); err != nil {
			t.Fatal(err)
		}
	}
	current, err := f.store.Get(f.ctx, f.org, f.user, sb.Identity.ID)
	if err != nil || current.State != StateDeleted {
		t.Fatal("cleanup blocked by drift", current, err)
	}
	var retired bool
	if err = f.pool.QueryRow(f.ctx, `SELECT worker_retired_at IS NOT NULL FROM sandbox_runtime_bindings WHERE sandbox_id=$1`, sb.Identity.ID).Scan(&retired); err != nil || !retired {
		t.Fatal("retirement blocked", err)
	}
	var blocked bool
	if err = f.pool.QueryRow(f.ctx, `SELECT health_blocked FROM devices WHERE id=$1`, devReservedPeer).Scan(&blocked); err != nil || blocked {
		t.Fatal("historical drift was mutated", err)
	}
}

func TestPersistentDevReservationPostgresWrongContractAndMissingProof(t *testing.T) {
	f, b, _ := newDevReservationFixture(t)
	for _, change := range []func(*BoundedRuntimeBinding){func(b *BoundedRuntimeBinding) { b.DevReservation.PeerStatus = "revoked" }, func(b *BoundedRuntimeBinding) { b.DevReservation.LaunchGatewayID = uuid.New() }} {
		copy := b
		r := *b.DevReservation
		copy.DevReservation = &r
		change(&copy)
		if _, err := f.store.WithBoundedRuntime(copy); err != nil {
			t.Fatal(err)
		}
		if _, _, err := f.store.Create(f.ctx, f.org, f.user, devInput(f, copy, 0)); !errors.Is(err, ErrDisabled) {
			t.Fatal("wrong exact reservation", err)
		}
	}
	if _, err := f.store.WithBoundedRuntime(b); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{`UPDATE sandbox_runtime_credentials SET revoked_at=NULL WHERE sandbox_id=$1`, `UPDATE sandboxes SET generation=3 WHERE id=$1`, `DELETE FROM sandbox_launch_operations WHERE sandbox_id=$1`, `UPDATE devices SET assigned_ip='10.99.0.11' WHERE id=$2`, `UPDATE sandboxes SET observed_state='deleted' WHERE id=$1`} {
		// Each corruption is rolled back in its isolated tx; immutable state never
		// needs a disabled trigger. No production row or proof is altered.
		tx, err := f.pool.Begin(f.ctx)
		if err != nil {
			t.Fatal(err)
		}
		// pgx parameter arity is specific to each statement.
		args := []any{devReservedSandbox}
		if strings.Contains(q, "$2") {
			q = strings.ReplaceAll(q, "$2", "$1")
			args = []any{devReservedPeer}
		}
		if _, err = tx.Exec(f.ctx, q, args...); err != nil {
			t.Fatal(err)
		}
		if _, err = b.reservationState(f.ctx, tx); !errors.Is(err, ErrDisabled) {
			t.Fatal("drift accepted", q, err)
		}
		tx.Rollback(f.ctx)
	}
	// Missing immutable historical identity is also closed (no magic reservation).
	tx, err := f.pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(f.ctx)
	if _, err = tx.Exec(f.ctx, `DELETE FROM sandbox_runtime_credentials WHERE sandbox_id=$1`, devReservedSandbox); err != nil {
		t.Fatal(err)
	}
	if _, err = b.reservationState(f.ctx, tx); !errors.Is(err, ErrDisabled) {
		t.Fatal("missing credential proof accepted", err)
	}
}

func TestPersistentDevReservationPostgresHistoricalCompletionNeverAddsWorkloadSlot(t *testing.T) {
	f, b, operation := newDevReservationFixture(t)
	// A synthetic already-verified withdrawal simulates completion by the separate
	// legacy cleanup authority. The persistent orchestrator cannot produce this.
	devExec(t, f, `INSERT INTO sandbox_network_withdrawals(sandbox_id,org_id,generation,operation_id,network_generation,peer_id,runtime_id,spec_hash) VALUES($1,$2,2,$3,1,$4,$5,$6)`, devReservedSandbox, f.org, operation, devReservedPeer, devReservedRuntime, devReservedSpec)
	if _, err := b.reservationState(f.ctx, f.pool); !errors.Is(err, ErrDisabled) {
		t.Fatal("partial completion accepted", err)
	}
	conn, release, err := f.store.acquireLifecycle(f.ctx, devReservedSandbox)
	if err != nil {
		t.Fatal(err)
	}
	historical, err := scanSandbox(conn.QueryRow(f.ctx, `SELECT `+sandboxColumns+` FROM sandboxes WHERE id=$1`, devReservedSandbox))
	if err != nil {
		t.Fatal(err)
	}
	err = completeCleanup(f.ctx, conn, historical)
	release()
	if err != nil {
		t.Fatal(err)
	}
	for _, retired := range []bool{false, true} {
		if retired {
			devExec(t, f, `UPDATE sandbox_runtime_bindings SET worker_retired_at=now() WHERE sandbox_id=$1`, devReservedSandbox)
		}
		state, err := b.reservationState(f.ctx, f.pool)
		if err != nil || state != "completed" {
			t.Fatal("legitimate completed history", state, err)
		}
		if _, _, err = f.store.Create(f.ctx, f.org, f.user, devInput(f, b, 0)); err != nil {
			t.Fatal(err)
		}
		if _, _, err = f.store.Create(f.ctx, f.org, f.user, devInput(f, b, 1)); !errors.Is(err, ErrQuota) {
			t.Fatal("historical completion opened second workload", retired, err)
		}
		out := devStatus(t, f)
		if out.RuntimeLimits.Workloads != 1 || out.RuntimeLimits.MaxWorkloads != 1 || out.RuntimeLimits.ReservationState != "completed" {
			t.Fatal("completed limits misrepresented", out)
		}
		// Clean the new identity through genuine worker/API retirement for the next
		// iteration, preserving the historical completed record throughout.
		_, client, _ := persistentRPCFixture(t, b)
		o, err := NewAPIOrchestrator(f.store, b, client, &readinessPolicyFixture{hash: "fixture-canonical"}, launchTestSealer(t))
		if err != nil {
			t.Fatal(err)
		}
		var id uuid.UUID
		if err = f.pool.QueryRow(f.ctx, `SELECT id FROM sandboxes WHERE org_id=$1 AND id<>$2 AND observed_state<>'deleted'`, f.org, devReservedSandbox).Scan(&id); err != nil {
			t.Fatal(err)
		}
		if _, err = f.store.SetDesired(f.ctx, f.org, f.user, id, 1, "deleted"); err != nil {
			t.Fatal(err)
		}
		for range 2 {
			if err = o.batch(f.ctx, func(_ uuid.UUID, e error) { t.Error(e) }); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestPersistentDevReservationPostgresSetupCASRequiresExactEnvelope(t *testing.T) {
	f, b, _ := newDevReservationFixture(t)
	out := devStatus(t, f)
	disabled := out.Settings
	disabled.Enabled = false
	if err := f.store.UpdateSetup(f.ctx, f.org, f.user, out.Settings, disabled, false); err != nil {
		t.Fatal(err)
	}
	wrong := disabled
	wrong.Enabled = true
	wrong.MaxTotal = 3
	if err := f.store.UpdateSetup(f.ctx, f.org, f.user, disabled, wrong, true); !errors.Is(err, ErrInvalid) {
		t.Fatal("generic quota increase accepted", err)
	}
	wrong.MaxPerUser, wrong.MaxTotal = 1, 1
	if err := f.store.UpdateSetup(f.ctx, f.org, f.user, disabled, wrong, true); !errors.Is(err, ErrInvalid) {
		t.Fatal("reservation not counted", err)
	}
	enabled := disabled
	enabled.Enabled = true
	if err := f.store.UpdateSetup(f.ctx, f.org, f.user, disabled, enabled, false); !errors.Is(err, ErrDisabled) {
		t.Fatal("unready enable", err)
	}
	devExec(t, f, `UPDATE sandbox_runtime_credentials SET revoked_at=NULL WHERE sandbox_id=$1`, devReservedSandbox)
	if err := f.store.UpdateSetup(f.ctx, f.org, f.user, disabled, enabled, true); !errors.Is(err, ErrDisabled) {
		t.Fatal("drift enable", err)
	}
	// Disablement remains available despite drift and stored larger legacy limits.
	off := disabled
	off.MaxTotal = 20
	if err := f.store.UpdateSetup(f.ctx, f.org, f.user, disabled, off, false); err != nil {
		t.Fatal("disable/update blocked", err)
	}
	devExec(t, f, `UPDATE sandbox_runtime_credentials SET revoked_at=now() WHERE sandbox_id=$1`, devReservedSandbox)
	if err := f.store.UpdateSetup(f.ctx, f.org, f.user, off, enabled, true); err != nil {
		t.Fatal("exact enable", err)
	}
	if err := f.store.UpdateSetup(f.ctx, f.org, f.user, off, enabled, true); !errors.Is(err, ErrConflict) {
		t.Fatal("stale CAS", err)
	}
	assertHistoricalPending(t, f, b)
}

func TestPersistentDevReservationCurrentMacPinsFutureWorkloadOnly(t *testing.T) {
	b := devReservationTestBinding()
	b.TerminalDeviceID = devCurrentDevice
	if err := b.Validate(); err != nil {
		t.Fatal("approved current Mac rejected", err)
	}
	_, client, _ := persistentRPCFixture(t, b)
	a := testAuthorization(b, 0)
	for _, change := range []func(*RuntimeAuthorization){func(a *RuntimeAuthorization) { a.TerminalDeviceID = devReservedDevice }, func(a *RuntimeAuthorization) { a.TerminalDeviceID = uuid.New() }, func(a *RuntimeAuthorization) { a.CreatorID = uuid.New() }, func(a *RuntimeAuthorization) { a.OrgID = uuid.New() }, func(a *RuntimeAuthorization) { a.GatewayID = uuid.New() }, func(a *RuntimeAuthorization) { a.SandboxID = devReservedSandbox }} {
		wrong := a
		change(&wrong)
		if err := client.AuthorizeRuntime(context.Background(), wrong); !errors.Is(err, ErrForbidden) {
			t.Fatal("foreign current-Mac grant", err)
		}
	}
	if err := client.AuthorizeRuntime(context.Background(), a); err != nil {
		t.Fatal("current-Mac exact grant", err)
	}
}

func seedCurrentDevMac(t *testing.T, f fixture) {
	t.Helper()
	_, key, _ := wgkey.Generate()
	devExec(t, f, `UPDATE devices SET assigned_ip='10.99.0.5' WHERE id=$1`, devReservedDevice)
	devExec(t, f, `INSERT INTO devices(id,org_id,user_id,node_id,name,public_key,assigned_ip,kind) VALUES($1,$2,$3,$4,'synthetic current Mac',$5,'10.99.0.11','human')`, devCurrentDevice, f.org, f.user, f.node, key)
}
func TestPersistentDevReservationPostgresCurrentMacAndHistoricalDeviceIndependent(t *testing.T) {
	f, b, _ := newDevReservationFixture(t)
	seedCurrentDevMac(t, f)
	b.TerminalDeviceID = devCurrentDevice
	if _, err := f.store.WithBoundedRuntime(b); err != nil {
		t.Fatal(err)
	}
	assertHistoricalPending(t, f, b)
	// Admission checks the exact current Mac's owner, gateway and health, rather
	// than discovering another device when the selected pin becomes invalid.
	otherGateway := uuid.New()
	devExec(t, f, `INSERT INTO nodes(id,org_id,name,cert_serial) VALUES($1,$2,'synthetic wrong gateway',$3)`, otherGateway, f.org, otherGateway.String())
	for _, mutation := range []struct {
		q       string
		value   any
		restore any
	}{
		{`UPDATE devices SET user_id=$2 WHERE id=$1`, f.other, f.user},
		{`UPDATE devices SET node_id=$2 WHERE id=$1`, otherGateway, f.node},
		{`UPDATE devices SET health_blocked=$2 WHERE id=$1`, true, false},
	} {
		devExec(t, f, mutation.q, devCurrentDevice, mutation.value)
		if _, _, err := f.store.Create(f.ctx, f.org, f.user, devInput(f, b, 0)); !errors.Is(err, ErrForbidden) {
			t.Fatal("wrong current device admitted", err)
		}
		devExec(t, f, mutation.q, devCurrentDevice, mutation.restore)
		assertHistoricalPending(t, f, b)
	}
	if _, _, err := f.store.Create(f.ctx, f.org, f.other, devInput(f, b, 0)); !errors.Is(err, ErrDisabled) {
		t.Fatal("wrong owner actor", err)
	}
	sb, _, err := f.store.Create(f.ctx, f.org, f.user, devInput(f, b, 0))
	if err != nil {
		t.Fatal("current Mac create", err)
	}
	var device, gateway uuid.UUID
	if err = f.pool.QueryRow(f.ctx, `SELECT terminal_device_id,local_terminal_gateway_id FROM sandboxes WHERE id=$1`, sb.Identity.ID).Scan(&device, &gateway); err != nil || device != devCurrentDevice || gateway != devOperationalGateway {
		t.Fatal("future pin", device, gateway, err)
	}
	var oldDevice uuid.UUID
	if err = f.pool.QueryRow(f.ctx, `SELECT terminal_device_id FROM sandboxes WHERE id=$1`, devReservedSandbox).Scan(&oldDevice); err != nil || oldDevice != devReservedDevice {
		t.Fatal("historical device changed", oldDevice, err)
	}
	conn, release, err := f.store.acquireLifecycle(f.ctx, sb.Identity.ID)
	if err != nil {
		t.Fatal(err)
	}
	target, err := f.store.prepareStart(f.ctx, conn, sb.Identity.ID)
	release()
	if err != nil || target.authorization == nil || target.authorization.TerminalDeviceID != devCurrentDevice {
		t.Fatal("current Mac start denied", err)
	}
	assertHistoricalPending(t, f, b)
	if _, _, err = f.store.Create(f.ctx, f.org, f.user, devInput(f, b, 1)); !errors.Is(err, ErrQuota) {
		t.Fatal("current Mac widened quota", err)
	}
}
func TestPersistentDevReservationPostgresDeviceChangeNeverRetargetsAcceptedWorkload(t *testing.T) {
	f, old, _ := newDevReservationFixture(t)
	seedCurrentDevMac(t, f)
	sb, _, err := f.store.Create(f.ctx, f.org, f.user, devInput(f, old, 0))
	if err != nil {
		t.Fatal(err)
	}
	current := old
	current.TerminalDeviceID = devCurrentDevice
	if _, err = f.store.WithBoundedRuntime(current); err != nil {
		t.Fatal(err)
	}
	conn, release, err := f.store.acquireLifecycle(f.ctx, sb.Identity.ID)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.store.prepareStart(f.ctx, conn, sb.Identity.ID)
	release()
	if !errors.Is(err, ErrForbidden) {
		t.Fatal("old accepted workload retargeted", err)
	}
	var device uuid.UUID
	if err = f.pool.QueryRow(f.ctx, `SELECT terminal_device_id FROM sandboxes WHERE id=$1`, sb.Identity.ID).Scan(&device); err != nil || device != devReservedDevice {
		t.Fatal("accepted pin mutated", device, err)
	}
	if _, _, err = f.store.Create(f.ctx, f.org, f.user, devInput(f, current, 1)); !errors.Is(err, ErrQuota) {
		t.Fatal("old workload bypassed", err)
	}
	assertHistoricalPending(t, f, current)
}
