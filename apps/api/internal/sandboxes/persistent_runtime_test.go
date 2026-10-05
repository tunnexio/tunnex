package sandboxes

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/sandboxruntime"
	"github.com/tunnexio/tunnex/apps/api/internal/wgkey"
	"golang.org/x/crypto/ssh"
)

// Synthetic qualification attestations exercise source contracts only. They do
// not establish native image qualification, actual SSH routing or live Ready.
func persistentTestBinding() BoundedRuntimeBinding {
	b := boundedTestBinding()
	b.Mode = "persistent"
	b.TemplateID = uuid.Nil
	b.ImageDigest = ""
	b.PIDs = 0
	b.ExpiresAt = time.Time{}
	b.MaxTTLSeconds = 900
	b.Profiles = []QualifiedRuntimeProfile{{uuid.New(), "sha256:" + strings.Repeat("a", 64), "amd64", "synthetic-fixture-Minimal", 64}, {uuid.New(), "sha256:" + strings.Repeat("b", 64), "amd64", "synthetic-fixture-Python", 64}, {uuid.New(), "sha256:" + strings.Repeat("c", 64), "amd64", "synthetic-fixture-Node", 64}, {uuid.New(), "sha256:" + strings.Repeat("d", 64), "amd64", "synthetic-fixture-Ubuntu-independent-128PID", 128}}
	return b
}
func TestPersistentBindingRequiresQualifiedExactNativeProfiles(t *testing.T) {
	b := persistentTestBinding()
	if b.Validate() != nil || !b.Allows(b.OrgID, b.CreatorID, time.Now().Add(24*time.Hour)) {
		t.Fatal("persistent lifetime still bound to trial deadline")
	}
	if b.Allows(uuid.New(), b.CreatorID, time.Now()) || b.Allows(b.OrgID, uuid.New(), time.Now()) {
		t.Fatal("persistent identity widened")
	}
	for _, change := range []func(*BoundedRuntimeBinding){
		func(b *BoundedRuntimeBinding) { b.Profiles[0].QualificationEvidence = "" },
		func(b *BoundedRuntimeBinding) { b.Profiles[0].Architecture = "arm64" },
		func(b *BoundedRuntimeBinding) { b.Profiles[0].ConfigDigest = "latest" },
		func(b *BoundedRuntimeBinding) { b.Profiles[0].PIDs = 256 },
		func(b *BoundedRuntimeBinding) { b.Profiles[0].ConfigDigest = CandidateImageProfiles()[0].ConfigDigest },
		func(b *BoundedRuntimeBinding) { b.Profiles[0].ConfigDigest = CandidateImageProfiles()[3].ImageDigest },
		func(b *BoundedRuntimeBinding) { b.Profiles[1].TemplateID = b.Profiles[0].TemplateID },
		func(b *BoundedRuntimeBinding) { b.ExpiresAt = time.Now() },
		func(b *BoundedRuntimeBinding) { b.MaxTTLSeconds = 901 },
	} {
		copy := b
		copy.Profiles = append([]QualifiedRuntimeProfile(nil), b.Profiles...)
		change(&copy)
		if copy.Validate() == nil {
			t.Fatal("unqualified/foreign/expanded persistent config accepted", copy)
		}
	}
	if (&APIOrchestrator{binding: b}).ConfigureInitialCreate(&CreateInput{}) == nil {
		t.Fatal("trial initial-create enabled persistent launch")
	}
}
func persistentRPCFixture(t *testing.T, b BoundedRuntimeBinding) (*WorkerRPCServer, *WorkerRPCClient, *rpcProviderFixture) {
	t.Helper()
	assetsRoot, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { assetsRoot.Close() })
	controlRoot, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { controlRoot.Close() })
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	identity, _ := ssh.NewSignerFromKey(key)
	assets, _ := sandboxruntime.NewFilesystemAssets(assetsRoot)
	files, err := NewFileBootstrapTransport(controlRoot, "https://fixture.example", &enrollmentInvokerFixture{})
	if err != nil {
		t.Fatal(err)
	}
	provider := &rpcProviderFixture{}
	network := &composedNetworkFixture{}
	server := &WorkerRPCServer{Binding: b, AssetsRoot: assetsRoot, ControlRoot: controlRoot, Assets: assets, Provider: provider, Files: files, Network: network, Gateway: network, Probe: network, Identity: identity}
	client := &WorkerRPCClient{client: &http.Client{Transport: rpcTestTransport{server}}, probe: identity.PublicKey()}
	return server, client, provider
}
func testAuthorization(b BoundedRuntimeBinding, index int) RuntimeAuthorization {
	now := time.Now().UTC()
	return RuntimeAuthorization{SandboxID: uuid.New(), OrgID: b.OrgID, CreatorID: b.CreatorID, GatewayID: b.GatewayID, TerminalDeviceID: b.TerminalDeviceID, TemplateID: b.Profiles[index].TemplateID, Profile: b.Profiles[index], Generation: 1, Desired: "started", CreatedAt: now, ExpiresAt: now.Add(300 * time.Second)}
}
func TestPersistentWorkerIdentityGenerationsCleanupAndCrashRecovery(t *testing.T) {
	b := persistentTestBinding()
	server, client, provider := persistentRPCFixture(t, b)
	ctx := context.Background()
	a := testAuthorization(b, 0)
	for _, change := range []func(*RuntimeAuthorization){func(a *RuntimeAuthorization) { a.OrgID = uuid.New() }, func(a *RuntimeAuthorization) { a.CreatorID = uuid.New() }, func(a *RuntimeAuthorization) { a.TerminalDeviceID = uuid.New() }, func(a *RuntimeAuthorization) { a.GatewayID = uuid.New() }, func(a *RuntimeAuthorization) { a.Profile.ConfigDigest = b.Profiles[1].ConfigDigest }, func(a *RuntimeAuthorization) { a.Profile.Architecture = "arm64" }, func(a *RuntimeAuthorization) { a.TemplateID = uuid.New() }, func(a *RuntimeAuthorization) { a.Profile.PIDs = 128 }} {
		copy := a
		change(&copy)
		if err := client.AuthorizeRuntime(ctx, copy); err == nil {
			t.Fatal("foreign identity/profile authorized")
		}
	}
	if err := client.AuthorizeRuntime(ctx, a); err != nil {
		t.Fatal(err)
	}
	spec := a.spec()
	hash, _ := sandboxruntime.Fingerprint(spec)
	plan := WorkspacePlan{SandboxID: a.SandboxID, OrgID: a.OrgID, Generation: 1, SpecHash: hash, Authorization: &a}
	assets, _, err := client.MaterializeCreationAssets(ctx, plan, []string{publicTerminalKey(t)})
	if err != nil {
		t.Fatal(err)
	}
	if err = client.Create(ctx, spec); err != nil {
		t.Fatal(err)
	}
	bad := spec
	bad.Architecture = "arm64"
	if err = client.Create(ctx, bad); err == nil {
		t.Fatal("wrong architecture create accepted")
	}
	if err = client.AuthorizeRuntime(ctx, testAuthorization(b, 1)); err == nil {
		t.Fatal("second retained workload accepted")
	}
	changed := a
	changed.ExpiresAt = changed.ExpiresAt.Add(time.Second)
	if err = client.AuthorizeRuntime(ctx, changed); err == nil {
		t.Fatal("TTL mutation accepted")
	}
	a.Generation = 2
	a.Desired = "stopped"
	if err = client.AuthorizeRuntime(ctx, a); err != nil {
		t.Fatal(err)
	}
	if _, err = server.dispatch(ctx, workerRequest{Version: workerRPCVersion, Operation: "start", ID: a.SandboxID, Generation: 1}); err == nil {
		t.Fatal("delayed generation started")
	}
	if err = client.Start(ctx, a.SandboxID); err == nil {
		t.Fatal("stopped grant started")
	}
	if err = client.Stop(ctx, a.SandboxID); err != nil {
		t.Fatal(err)
	}
	a.Generation = 3
	a.Desired = "deleted"
	if err = client.AuthorizeRuntime(ctx, a); err != nil {
		t.Fatal(err)
	}
	if err = client.RetireRuntime(ctx, a.SandboxID); err == nil {
		t.Fatal("retirement without provider absence")
	}
	if server.sandboxID != a.SandboxID {
		t.Fatal("cleanup failure released slot")
	}
	if err = client.Delete(ctx, a.SandboxID); err != nil {
		t.Fatal(err)
	}
	pin := server.currentPin() // simulate crash after marker fsync, before slot unlink
	if err = client.RetireRuntime(ctx, a.SandboxID); err != nil {
		t.Fatal(err)
	}
	if err = server.writePin(pin); err != nil {
		t.Fatal(err)
	}
	server.active = nil
	server.sandboxID = uuid.Nil
	if retired, err := server.CheckRetirement(); err != nil || retired || server.sandboxID != uuid.Nil {
		t.Fatal("persistent recovery failed", retired, err)
	}
	if _, err = server.AssetsRoot.Lstat(a.SandboxID.String()); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("assets retained", assets.Workspace, err)
	}
	if _, err = server.ControlRoot.Lstat(a.SandboxID.String()); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("control retained", err)
	}
	if err = client.AuthorizeRuntime(ctx, a); err != nil {
		t.Fatal("lost API acknowledgement cannot recover", err)
	}
	if err = client.RetireRuntime(ctx, a.SandboxID); err != nil {
		t.Fatal("retire retry failed", err)
	}
	a.Desired = "started"
	a.Generation = 4
	if err = client.AuthorizeRuntime(ctx, a); err == nil {
		t.Fatal("completed identity resurrected")
	}
	if err = client.CheckBinding(ctx, b); err != nil {
		t.Fatal("persistent authority retired", err)
	}
	if err = client.CloseRetiredRuntime(ctx, a.SandboxID); err == nil {
		t.Fatal("persistent listener closed by trial verb")
	}
	next := testAuthorization(b, 1)
	if err = client.AuthorizeRuntime(ctx, next); err != nil {
		t.Fatal("next profile denied", err)
	}
	if err = client.Start(ctx, a.SandboxID); err == nil {
		t.Fatal("delayed completed identity started next workload")
	}
	if provider.status.Exists {
		t.Fatal("old provider remained")
	}
}
func TestPersistentWorkerExpiredGrantCannotLaunchButCanClean(t *testing.T) {
	b := persistentTestBinding()
	_, client, _ := persistentRPCFixture(t, b)
	a := testAuthorization(b, 0)
	a.CreatedAt = time.Now().Add(-600 * time.Second)
	a.ExpiresAt = a.CreatedAt.Add(300 * time.Second)
	if err := client.AuthorizeRuntime(context.Background(), a); err == nil {
		t.Fatal("expired start grant accepted")
	}
	a.Desired = "deleted"
	a.Generation = 2
	if err := client.AuthorizeRuntime(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	if err := client.Delete(context.Background(), a.SandboxID); err != nil {
		t.Fatal(err)
	}
	if err := client.RetireRuntime(context.Background(), a.SandboxID); err != nil {
		t.Fatal(err)
	}
}
func TestPersistentPostgresSequentialProfilesResumePolicyAndRetirement(t *testing.T) {
	f := newFixture(t)
	b := persistentTestBinding()
	b.OrgID, b.CreatorID, b.GatewayID = f.org, f.user, f.node
	seedBoundedTerminalDevice(t, f, b)
	for i, p := range b.Profiles {
		if _, err := f.pool.Exec(f.ctx, `INSERT INTO sandbox_templates(id,org_id,name,image_digest,maximum_scope,memory_mib,max_ttl_seconds,enabled) VALUES($1,$2,$3,$4,'[]',128,900,true)`, p.TemplateID, b.OrgID, p.QualificationEvidence, p.ConfigDigest); err != nil {
			t.Fatal(i, err)
		}
	}
	_, gatewayKey, _ := wgkey.Generate()
	if _, err := f.pool.Exec(f.ctx, `UPDATE nodes SET endpoint='127.0.0.1:51820',wg_public_key=$2,status='active',policy_reported_at=now() WHERE id=$1`, f.node, gatewayKey); err != nil {
		t.Fatal(err)
	}
	server, client, _ := persistentRPCFixture(t, b)
	invoker := &enrollmentInvokerFixture{f: f}
	files, _ := NewFileBootstrapTransport(server.ControlRoot, "https://fixture.example", invoker)
	network := &composedNetworkFixture{f: f}
	server.Files, server.Network, server.Gateway, server.Probe = files, network, network, network
	orchestration, err := NewAPIOrchestrator(f.store, b, client, &readinessPolicyFixture{hash: "canonical-api"}, launchTestSealer(t))
	if err != nil {
		t.Fatal(err)
	}
	batch := func(wantError bool) {
		t.Helper()
		var reports []error
		if err := orchestration.batch(f.ctx, func(_ uuid.UUID, e error) { reports = append(reports, e) }); err != nil {
			t.Fatal(err)
		}
		if (len(reports) > 0) != wantError {
			t.Fatal("batch errors", reports)
		}
	}
	refresh := func() {
		t.Helper()
		if _, err := f.pool.Exec(f.ctx, `UPDATE nodes SET policy_reported_at=now() WHERE id=$1`, f.node); err != nil {
			t.Fatal(err)
		}
	}
	for index := range 2 {
		input := f.input(uuid.NewString())
		input.TemplateID = b.Profiles[index].TemplateID
		input.Requested = []Scope{}
		input.TTLSeconds = 900
		sb, _, err := f.store.Create(f.ctx, f.org, f.user, input)
		if err != nil {
			t.Fatal(err)
		}
		batch(false)
		current, err := f.store.Get(f.ctx, f.org, f.user, sb.Identity.ID)
		if err != nil || current.State != StateReady {
			t.Fatal("synthetic readiness", current.State, err)
		}
		originalEpoch := *server.epoch
		current, err = f.store.SetDesired(f.ctx, f.org, f.user, sb.Identity.ID, current.Revision, "stopped")
		if err != nil {
			t.Fatal(err)
		}
		batch(false)
		if _, _, err = f.store.Create(f.ctx, f.org, f.user, CreateInput{TemplateID: b.Profiles[1].TemplateID, Name: "retained", Requested: []Scope{}, TTLSeconds: 900, IdempotencyKey: uuid.NewString(), SSHPublicKeys: input.SSHPublicKeys}); !errors.Is(err, ErrQuota) {
			t.Fatal("stopped slot released", err)
		}
		current, err = f.store.SetDesired(f.ctx, f.org, f.user, sb.Identity.ID, current.Revision, "started")
		if err != nil {
			t.Fatal(err)
		}
		// Restart loads immutable profile and withdrawal proof; API restores its
		// generation grant before resume. Stale ACKs must keep connection withheld.
		server.active = nil
		server.epoch = nil
		server.sandboxID = uuid.Nil
		if retired, err := server.CheckRetirement(); err != nil || retired {
			t.Fatal(err)
		}
		if _, err = f.pool.Exec(f.ctx, `UPDATE nodes SET policy_reported_at='2000-01-01' WHERE id=$1`, f.node); err != nil {
			t.Fatal(err)
		}
		batch(true)
		current, err = f.store.Get(f.ctx, f.org, f.user, sb.Identity.ID)
		if err != nil || current.Connection != nil {
			t.Fatal("stale ACK became ready", err)
		}
		refresh()
		batch(false)
		if server.epoch.OperationID == originalEpoch.OperationID || server.epochGeneration != 3 {
			t.Fatal("resume reused old epoch")
		}
		if _, err = server.dispatch(f.ctx, workerRequest{Version: workerRPCVersion, Operation: "apply-network", ID: sb.Identity.ID, Generation: 1, Target: &originalEpoch}); err == nil {
			t.Fatal("delayed old epoch applied")
		}
		current, err = f.store.Get(f.ctx, f.org, f.user, sb.Identity.ID)
		if err != nil || current.State != StateReady {
			t.Fatal("resume failed", err)
		}
		current, err = f.store.SetDesired(f.ctx, f.org, f.user, sb.Identity.ID, current.Revision, "deleted")
		if err != nil {
			t.Fatal(err)
		}
		// Canonical-policy failure retains Deleting and its quota even when worker
		// has physically withdrawn the namespace and gateway peer.
		if _, err = f.pool.Exec(f.ctx, `UPDATE nodes SET policy_reported_at='2000-01-01' WHERE id=$1`, f.node); err != nil {
			t.Fatal(err)
		}
		batch(true)
		blocked, err := f.store.Setup(f.ctx, f.org, f.user)
		if err != nil || !containsReason(blocked.BlockedReasons, "organization_quota_reached") {
			t.Fatal("deleting quota not held", blocked.BlockedReasons, err)
		}
		refresh()
		batch(false)
		input.IdempotencyKey = uuid.NewString()
		if _, _, err = f.store.Create(f.ctx, f.org, f.user, input); !errors.Is(err, ErrQuota) {
			t.Fatal("Deleted before worker retirement reopened slot", err)
		}
		batch(false)
		setup, err := f.store.Setup(f.ctx, f.org, f.user)
		if err != nil || containsReason(setup.BlockedReasons, "runtime_launch_budget_used") || containsReason(setup.BlockedReasons, "organization_quota_reached") {
			t.Fatal("completed history blocked reuse", setup.BlockedReasons, err)
		}
		compatible := 0
		for _, entry := range setup.Catalog {
			if entry.RuntimeCompatible {
				compatible++
			}
		}
		if compatible != 4 {
			t.Fatal("registered qualified catalog not visible", compatible)
		}
		if err = client.CheckBinding(f.ctx, b); err != nil {
			t.Fatal("persistent worker unavailable", err)
		}
	}
	if invoker.calls != 2 {
		t.Fatal("profile enrollment replaced or repeated", invoker.calls)
	}
}
func containsReason(reasons []string, want string) bool {
	for _, s := range reasons {
		if s == want {
			return true
		}
	}
	return false
}
func TestPersistentPostgresConcurrentQuotaAndTerminalRestriction(t *testing.T) {
	f := newFixture(t)
	b := persistentTestBinding()
	b.OrgID, b.CreatorID, b.GatewayID = f.org, f.user, f.node
	seedBoundedTerminalDevice(t, f, b)
	for _, p := range b.Profiles[:2] {
		if _, err := f.pool.Exec(f.ctx, `INSERT INTO sandbox_templates(id,org_id,name,image_digest,maximum_scope,memory_mib,max_ttl_seconds,enabled) VALUES($1,$2,$3,$4,'[]',128,900,true)`, p.TemplateID, b.OrgID, p.QualificationEvidence, p.ConfigDigest); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.store.WithBoundedRuntime(b); err != nil {
		t.Fatal(err)
	}
	input := f.input("bad-device")
	input.TemplateID = b.Profiles[0].TemplateID
	input.Requested = []Scope{}
	input.TTLSeconds = 900
	if _, _, err := f.store.Create(f.ctx, f.org, f.other, input); !errors.Is(err, ErrDisabled) {
		t.Fatal("foreign creator admitted", err)
	}
	if _, err := f.pool.Exec(f.ctx, `UPDATE devices SET health_blocked=true WHERE id=$1`, b.TerminalDeviceID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.store.Create(f.ctx, f.org, f.user, input); !errors.Is(err, ErrForbidden) {
		t.Fatal("foreign gateway device admitted", err)
	}
	if _, err := f.pool.Exec(f.ctx, `UPDATE devices SET health_blocked=false WHERE id=$1`, b.TerminalDeviceID); err != nil {
		t.Fatal(err)
	}
	otherGateway := uuid.New()
	if _, err := f.pool.Exec(f.ctx, `INSERT INTO nodes(id,org_id,name,cert_serial) VALUES($1,$2,'foreign locality',$3)`, otherGateway, f.org, otherGateway.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(f.ctx, `UPDATE devices SET node_id=$2 WHERE id=$1`, b.TerminalDeviceID, otherGateway); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.store.Create(f.ctx, f.org, f.user, input); !errors.Is(err, ErrForbidden) {
		t.Fatal("same-org wrong-gateway terminal admitted", err)
	}
	if _, err := f.pool.Exec(f.ctx, `UPDATE devices SET node_id=$2 WHERE id=$1`, b.TerminalDeviceID, b.GatewayID); err != nil {
		t.Fatal(err)
	}
	badProfile := b.Profiles[2]
	if _, err := f.pool.Exec(f.ctx, `INSERT INTO sandbox_templates(id,org_id,name,image_digest,maximum_scope,memory_mib,max_ttl_seconds,enabled) VALUES($1,$2,'wrong immutable image',$3,'[]',128,900,true)`, badProfile.TemplateID, b.OrgID, "sha256:"+strings.Repeat("f", 64)); err != nil {
		t.Fatal(err)
	}
	input.TemplateID = badProfile.TemplateID
	if _, _, err := f.store.Create(f.ctx, f.org, f.user, input); !errors.Is(err, ErrDisabled) {
		t.Fatal("wrong template digest admitted", err)
	}
	input.TemplateID = b.Profiles[0].TemplateID
	input.Requested = f.input("scope").Requested
	if _, _, err := f.store.Create(f.ctx, f.org, f.user, input); !errors.Is(err, ErrInvalid) {
		t.Fatal("outbound scope accepted", err)
	}
	input.Requested = []Scope{}
	results := make(chan error, 2)
	var ready sync.WaitGroup
	ready.Add(2)
	for _, p := range b.Profiles[:2] {
		go func(p QualifiedRuntimeProfile) {
			in := input
			in.TemplateID = p.TemplateID
			in.IdempotencyKey = uuid.NewString()
			ready.Done()
			ready.Wait()
			_, _, err := f.store.Create(f.ctx, f.org, f.user, in)
			results <- err
		}(p)
	}
	a, c := <-results, <-results
	if (a == nil) == (c == nil) || (!errors.Is(a, ErrQuota) && !errors.Is(c, ErrQuota)) {
		t.Fatal("persistent quota race", a, c)
	}
}

func TestPersistentPostgresNaturalExpiryBeforeFirstEffectAndSetupCAS(t *testing.T) {
	f := newFixture(t)
	b := persistentTestBinding()
	b.OrgID, b.CreatorID, b.GatewayID = f.org, f.user, f.node
	seedBoundedTerminalDevice(t, f, b)
	p := b.Profiles[0]
	if _, err := f.pool.Exec(f.ctx, `INSERT INTO sandbox_templates(id,org_id,name,image_digest,maximum_scope,memory_mib,max_ttl_seconds,enabled) VALUES($1,$2,'expired fixture',$3,'[]',128,900,true)`, p.TemplateID, f.org, p.ConfigDigest); err != nil {
		t.Fatal(err)
	}
	server, client, provider := persistentRPCFixture(t, b)
	o, err := NewAPIOrchestrator(f.store, b, client, &readinessPolicyFixture{hash: "canonical-api"}, launchTestSealer(t))
	if err != nil {
		t.Fatal(err)
	}
	// A synthetic original TTL has already elapsed before worker recovery. This
	// exercises automatic expiry cleanup, without changing any admitted live TTL.
	id := uuid.New()
	if _, err = f.pool.Exec(f.ctx, `INSERT INTO sandboxes(id,org_id,creator_id,template_id,name,requested_scope,idempotency_key,request_hash,created_at,expires_at,ssh_public_keys,terminal_device_id,local_terminal_gateway_id) VALUES($1,$2,$3,$4,'original expired fixture','[]','expired',$5,now()-interval '301 seconds',now()-interval '1 second',$6,$7,$8)`, id, f.org, f.user, p.TemplateID, make([]byte, 32), []byte("["+strconv.Quote(f.sshPublicKey)+"]"), b.TerminalDeviceID, b.GatewayID); err != nil {
		t.Fatal(err)
	}
	spec := sandboxruntime.Spec{ID: id, ImageDigest: p.ConfigDigest, Architecture: p.Architecture, MemoryMiB: 128, CPUs: 1, PIDs: p.PIDs}
	hash, _ := sandboxruntime.Fingerprint(spec)
	if _, err = f.pool.Exec(f.ctx, `INSERT INTO sandbox_runtime_bindings(sandbox_id,org_id,spec_hash,image_digest,memory_mib,cpus,pids) VALUES($1,$2,$3,$4,128,1,64)`, id, f.org, hash, p.ConfigDigest); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err = o.batch(f.ctx, func(_ uuid.UUID, e error) { t.Error(e) }); err != nil {
			t.Fatal(err)
		}
	}
	sb, err := f.store.Get(f.ctx, f.org, f.user, id)
	if err != nil || sb.State != StateDeleted || sb.Revision != 2 || provider.starts != 0 || server.sandboxID != uuid.Nil {
		t.Fatal("expired generation launched/retained", sb, err)
	}
	if _, err = f.pool.Exec(f.ctx, `UPDATE memberships SET role='owner',roles=ARRAY['owner'] WHERE org_id=$1 AND user_id=$2`, f.org, f.user); err != nil {
		t.Fatal(err)
	}
	setup, err := f.store.Setup(f.ctx, f.org, f.user)
	if err != nil {
		t.Fatal(err)
	}
	disabled := setup.Settings
	disabled.Enabled = false
	if err = f.store.UpdateSetup(f.ctx, f.org, f.user, setup.Settings, disabled, true); err != nil {
		t.Fatal(err)
	}
	if err = f.store.UpdateSetup(f.ctx, f.org, f.user, setup.Settings, disabled, true); !errors.Is(err, ErrConflict) {
		t.Fatal("stale settings CAS accepted", err)
	}
	enabled := setup.Settings
	enabled.MaxPerUser, enabled.MaxTotal = 1, 1
	if err = f.store.UpdateSetup(f.ctx, f.org, f.user, disabled, setup.Settings, true); !errors.Is(err, ErrInvalid) {
		t.Fatal("expanded persistent admin quota accepted", err)
	}
	if err = f.store.UpdateSetup(f.ctx, f.org, f.user, disabled, enabled, false); !errors.Is(err, ErrDisabled) {
		t.Fatal("missing runtime health enabled org", err)
	}
	if err = f.store.UpdateSetup(f.ctx, f.org, f.user, disabled, enabled, true); err != nil {
		t.Fatal("qualified catalog enable failed", err)
	}
	if err = f.store.PublishTemplate(f.ctx, f.org, f.user, p.TemplateID, true, false); err != nil {
		t.Fatal(err)
	}
	if err = f.store.PublishTemplate(f.ctx, f.org, f.user, p.TemplateID, true, false); !errors.Is(err, ErrConflict) {
		t.Fatal("stale publication CAS accepted", err)
	}
}

func TestPersistentAPIConfigRequiresQualificationAndPreservesSocketContract(t *testing.T) {
	b := persistentTestBinding()
	cfg := APIWorkerConfig{Binding: b, Socket: "/run/tunnex-sandbox-worker/control.sock", WorkerUID: 10001, ProbePublicKey: publicTerminalKey(t)}
	path := filepath.Join(t.TempDir(), "operator.json")
	save := func() {
		t.Helper()
		raw, err := json.Marshal(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	save()
	loaded, err := LoadAPIWorkerConfig(path)
	if err != nil || !bindingEqual(loaded.Binding, b) {
		t.Fatal("persistent config round trip", err)
	}
	cfg.Binding.Profiles[0].QualificationEvidence = ""
	save()
	if _, err = LoadAPIWorkerConfig(path); err == nil {
		t.Fatal("unqualified operator config accepted")
	}
	cfg.Binding = persistentTestBinding()
	cfg.Socket = "/tmp/other.sock"
	save()
	if _, err = LoadAPIWorkerConfig(path); err == nil {
		t.Fatal("socket authority widened")
	}
}
func TestPersistentPostgresStopRaceBeforeFirstNetworkCanClean(t *testing.T) {
	f := newFixture(t)
	b := persistentTestBinding()
	b.OrgID, b.CreatorID, b.GatewayID = f.org, f.user, f.node
	seedBoundedTerminalDevice(t, f, b)
	p := b.Profiles[0]
	if _, err := f.pool.Exec(f.ctx, `INSERT INTO sandbox_templates(id,org_id,name,image_digest,maximum_scope,memory_mib,max_ttl_seconds,enabled) VALUES($1,$2,'first-network race',$3,'[]',128,900,true)`, p.TemplateID, f.org, p.ConfigDigest); err != nil {
		t.Fatal(err)
	}
	_, key, _ := wgkey.Generate()
	if _, err := f.pool.Exec(f.ctx, `UPDATE nodes SET endpoint='127.0.0.1:51820',wg_public_key=$2,status='active',policy_reported_at=now() WHERE id=$1`, f.node, key); err != nil {
		t.Fatal(err)
	}
	server, client, provider := persistentRPCFixture(t, b)
	files, _ := NewFileBootstrapTransport(server.ControlRoot, "https://fixture.example", &enrollmentInvokerFixture{f: f})
	network := &composedNetworkFixture{f: f}
	server.Files, server.Network, server.Gateway, server.Probe = files, network, network, network
	o, err := NewAPIOrchestrator(f.store, b, client, &readinessPolicyFixture{hash: "canonical-api"}, launchTestSealer(t))
	if err != nil {
		t.Fatal(err)
	}
	in := f.input("stop-before-network")
	in.Requested = []Scope{}
	in.TTLSeconds = 900
	in.TemplateID = p.TemplateID
	sb, _, err := f.store.Create(f.ctx, f.org, f.user, in)
	if err != nil {
		t.Fatal(err)
	}
	provider.afterStart = func() {
		provider.afterStart = nil
		if _, err := f.store.SetDesired(f.ctx, f.org, f.user, sb.Identity.ID, 1, "stopped"); err != nil {
			t.Fatal(err)
		}
	}
	var reports []error
	if err = o.batch(f.ctx, func(_ uuid.UUID, e error) { reports = append(reports, e) }); err != nil || len(reports) != 1 || server.epoch != nil {
		t.Fatal("stop race not exercised", reports, err)
	}
	if err = o.batch(f.ctx, func(_ uuid.UUID, e error) { t.Error(e) }); err != nil {
		t.Fatal(err)
	}
	current, err := f.store.Get(f.ctx, f.org, f.user, sb.Identity.ID)
	if err != nil || current.State != StateStopped || !server.withdrawn {
		t.Fatal("first-epoch cleanup blocked", current.State, err)
	}
	if _, err = f.store.SetDesired(f.ctx, f.org, f.user, sb.Identity.ID, current.Revision, "deleted"); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err = o.batch(f.ctx, func(_ uuid.UUID, e error) { t.Error(e) }); err != nil {
			t.Fatal(err)
		}
	}
	if server.sandboxID != uuid.Nil {
		t.Fatal("race retained worker slot")
	}
}

func TestTrialPostgresScopedStartRetainsLegacyPlacement(t *testing.T) {
	f := newFixture(t)
	b := boundedTestBinding()
	b.OrgID, b.CreatorID, b.GatewayID = f.org, f.user, f.node
	seedBoundedTerminalDevice(t, f, b)
	if _, err := f.pool.Exec(f.ctx, `INSERT INTO sandbox_templates(id,org_id,name,image_digest,maximum_scope,memory_mib,max_ttl_seconds,enabled) VALUES($1,$2,'legacy scoped trial',$3,'[{"cidr":"10.1.0.0/16","protocol":"any","port_low":0,"port_high":0}]',128,3600,true)`, b.TemplateID, f.org, b.ImageDigest); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.WithBoundedRuntime(b); err != nil {
		t.Fatal(err)
	}
	in := f.input("scoped-legacy-trial")
	in.TemplateID = b.TemplateID
	sb, _, err := f.store.Create(f.ctx, f.org, f.user, in)
	if err != nil {
		t.Fatal(err)
	}
	var local *uuid.UUID
	if err = f.pool.QueryRow(f.ctx, `SELECT local_terminal_gateway_id FROM sandboxes WHERE id=$1`, sb.Identity.ID).Scan(&local); err != nil || local != nil {
		t.Fatal("scoped trial placement changed", local, err)
	}
	conn, release, err := f.store.acquireLifecycle(f.ctx, sb.Identity.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	target, err := f.store.prepareStart(f.ctx, conn, sb.Identity.ID)
	if err != nil || target.spec.PIDs != 128 || target.spec.Architecture != "" {
		t.Fatal("legacy scoped trial cannot prepare start", err)
	}
}
