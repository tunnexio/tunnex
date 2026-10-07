package http

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	stdhttp "net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	appcrypto "github.com/tunnexio/tunnex/apps/api/internal/crypto"
	"github.com/tunnexio/tunnex/apps/api/internal/devices"
	"github.com/tunnexio/tunnex/apps/api/internal/nodes"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
	"github.com/tunnexio/tunnex/apps/api/internal/sandboxes"
	"github.com/tunnexio/tunnex/apps/api/internal/sandboxproduct"
	"github.com/tunnexio/tunnex/apps/api/internal/sandboxrunner"
	"github.com/tunnexio/tunnex/apps/api/internal/sandboxruntime"
	"github.com/tunnexio/tunnex/apps/api/internal/tenancy"
	"github.com/tunnexio/tunnex/apps/api/internal/testpostgres"
	"github.com/tunnexio/tunnex/apps/api/internal/wgkey"
	"golang.org/x/crypto/ssh"
)

// One real HTTP/Store/orchestrator/mTLS/worker sequence. Only the provider's
// subprocess output and privileged network/SSH/policy observations are fakes;
// a synthetic BootstrapInvoker calls real HTTPS bootstrap and persists its
// response through FileBootstrapTransport rather than launching the CLI binary.
// This cannot qualify a Linux namespace, UID ACL, WireGuard or a live image;
// those have separate native fixtures. No executable skill or real credentials
// are used. The clock is rebased ONCE before any worker authorization, keeping
// the admitted 300-second interval; the remote lease then expires naturally.
func TestSandboxRemoteHTTPFailureSequence(t *testing.T) {
	if sandboxproduct.Shelved {
		t.Skip("historical active sandbox router fixture; see docs/S-sandbox-shelved-main-reentry.md")
	}
	ctx, pool := testpostgres.New(t)
	org, owner, terminalID, template := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	terminalGW := uuid.MustParse("11111111-1111-4111-8111-111111111111")
	runtimeGW := uuid.MustParse("eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee")
	digest := "sha256:" + strings.Repeat("a", 64)
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO organizations(id,name,slug,pool_cidr,zero_trust_mode,sandboxes_enabled,max_sandboxes,max_sandboxes_per_user,cross_gateway_clients_enabled) VALUES($1,'sequence fixture',$2,'10.99.0.0/24','enforcing',true,2,2,true)`, org, org.String())
	exec(`INSERT INTO users(id,email,name,email_verified_at) VALUES($1,$2,'sequence owner',now())`, owner, owner.String()+"@example.test")
	exec(`INSERT INTO memberships(org_id,user_id,role,roles) VALUES($1,$2,'owner',ARRAY['owner'])`, org, owner)
	for i, id := range []uuid.UUID{terminalGW, runtimeGW} {
		_, key, err := wgkey.Generate()
		if err != nil {
			t.Fatal(err)
		}
		exec(`INSERT INTO nodes(id,org_id,name,cert_serial,endpoint,wg_public_key,status,policy_reported_at) VALUES($1,$2,$6,$3,$4,$5,'active',now())`, id, org, id.String(), []string{"172.31.18.43:51820", "172.31.18.44:51821"}[i], key, fmt.Sprintf("sequence gateway %d", i))
	}
	_, terminalWG, err := wgkey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	exec(`INSERT INTO devices(id,org_id,user_id,node_id,name,public_key,assigned_ip,kind,status) VALUES($1,$2,$3,$4,'sequence terminal',$5,'10.99.0.2','human','active')`, terminalID, org, owner, terminalGW, terminalWG)
	exec(`INSERT INTO sandbox_templates(id,org_id,name,image_digest,maximum_scope,memory_mib,max_ttl_seconds,enabled) VALUES($1,$2,'synthetic Minimal',$3,'[]',128,900,true)`, template, org, digest)
	binding := sandboxes.BoundedRuntimeBinding{Mode: "persistent", OrgID: org, CreatorID: owner, GatewayID: runtimeGW, TerminalDeviceID: terminalID, MemoryMiB: 128, CPUs: 1, MaxTTLSeconds: 900, Profiles: []sandboxes.QualifiedRuntimeProfile{{TemplateID: template, ConfigDigest: digest, Architecture: "amd64", QualificationEvidence: "synthetic-sequence-only", PIDs: 64}}, RemoteTerminal: &sandboxes.RemoteTerminalBinding{GatewayID: terminalGW, GatewayEndpoint: "172.31.18.43:51820", RuntimeGatewayEndpoint: "172.31.18.44:51821"}}
	store := sandboxes.NewStore(pool)
	if _, err = store.WithBoundedRuntime(binding); err != nil {
		t.Fatal(err)
	}
	skill, _, err := store.CreateCustomSkill(ctx, org, owner, "---\nname: sequence-notes\ndescription: Inert fixture notes\n---\n\nExplain the selected files.\n", "sequence-skill")
	if err != nil {
		t.Fatal(err)
	}
	openRoot := func() *os.Root {
		t.Helper()
		root, err := os.OpenRoot(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { root.Close() })
		return root
	}
	assetsRoot, controlRoot, protocolRoot := openRoot(), openRoot(), openRoot()
	assets, err := sandboxruntime.NewFilesystemAssets(assetsRoot)
	if err != nil {
		t.Fatal(err)
	}
	runnerEffects := &sequencePodmanRunner{image: digest}
	provider, err := sandboxruntime.NewPodmanWithAssets(runnerEffects, assets)
	if err != nil {
		t.Fatal(err)
	}
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	healthIdentity := &sequenceHealthSigner{Signer: identity, entered: make(chan struct{}), release: make(chan struct{})}
	network := &sequenceNetwork{pool: pool, provider: provider}
	worker := &sandboxes.WorkerRPCServer{Binding: binding, AssetsRoot: assetsRoot, ControlRoot: controlRoot, Assets: assets, Provider: provider, Network: network, Gateway: network, Probe: network, Identity: healthIdentity}
	remote, client := sequenceRemoteTLS(t, ctx, worker, protocolRoot)
	sealer, err := appcrypto.NewSealer(make([]byte, appcrypto.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	policies := &sequencePolicies{pool: pool, org: org, allowed: map[uuid.UUID]bool{terminalGW: true, runtimeGW: true}}
	orchestrator, err := sandboxes.NewAPIOrchestrator(store, binding, remote, policies, sealer)
	if err != nil {
		t.Fatal(err)
	}
	var overlapping atomic.Bool
	var checks atomic.Int32
	arrived, startedChecks, releaseChecks := make(chan struct{}, 3), make(chan struct{}, 3), make(chan struct{})
	available := func() bool {
		if overlapping.Load() {
			arrived <- struct{}{}
			select {
			case <-releaseChecks:
			case <-ctx.Done():
				return false
			}
		}
		checks.Add(1)
		if overlapping.Load() {
			startedChecks <- struct{}{}
		}
		probeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		return remote.CheckBinding(probeCtx, binding) == nil
	}
	deps := Deps{Sandboxes: store, Orgs: tenancy.NewService(pool), Devices: devices.NewService(pool, nil, nil), SandboxProvisioningReady: available, SandboxSkillsReady: available, SandboxWake: orchestrator.Wake, AuthFn: func(*stdhttp.Request) *authctx.Principal {
		return &authctx.Principal{UserID: owner, EmailVerified: true, Roles: map[uuid.UUID]string{org: rbac.RoleOwner}}
	}}
	router, err := NewRouter(slog.New(slog.NewTextHandler(io.Discard, nil)), deps)
	if err != nil {
		t.Fatal(err)
	}
	apiServer := httptest.NewTLSServer(router)
	t.Cleanup(apiServer.Close)
	bootstrap := &sequenceBootstrap{client: apiServer.Client(), entered: make(chan struct{}), release: make(chan struct{}), completed: make(chan error, 1)}
	defer func() {
		overlapping.Store(false)
		for _, barrier := range []chan struct{}{releaseChecks, bootstrap.release, healthIdentity.release} {
			select {
			case <-barrier:
			default:
				close(barrier)
			}
		}
	}()
	worker.Files, err = sandboxes.NewFileBootstrapTransport(controlRoot, apiServer.URL, bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	// Start the actual worker after every effect dependency is installed.
	workerCtx, cancelWorker := context.WithCancel(ctx)
	workerDone := make(chan error, 1)
	go func() {
		workerDone <- worker.RunRemoteWorker(workerCtx, client, sandboxrunner.LeaseStore{Root: protocolRoot})
	}()
	t.Cleanup(func() {
		cancelWorker()
		select {
		case <-workerDone:
		case <-time.After(3 * time.Second):
			t.Error("remote worker failed to stop")
		}
	})
	request := func(method, path string, body any, key string) (int, []byte, error) {
		var raw []byte
		if body != nil {
			encoded, marshalErr := json.Marshal(body)
			if marshalErr != nil {
				return 0, nil, marshalErr
			}
			raw = encoded
		}
		req, err := stdhttp.NewRequestWithContext(ctx, method, apiServer.URL+path, bytes.NewReader(raw))
		if err != nil {
			return 0, nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		if key != "" {
			req.Header.Set("Idempotency-Key", key)
		}
		res, err := apiServer.Client().Do(req)
		if err != nil {
			return 0, nil, err
		}
		defer res.Body.Close()
		out, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
		return res.StatusCode, out, err
	}
	base := "/api/v1/organizations/" + org.String()
	selected := []api.SandboxSkillSelection{{RevisionId: skill.RevisionID, Configuration: map[string]string{}}}
	create := api.SandboxCreate{Name: "sequence", TemplateId: template, TtlSeconds: 300, RequestedScope: []api.SandboxScope{}, SshPublicKeys: []string{sandboxFixtureSSHKey}, SelectedSkills: &selected}
	status, raw, err := request(stdhttp.MethodPost, base+"/sandboxes", create, "sequence-create")
	if err != nil || status != 202 {
		t.Fatalf("actual create: status=%d err=%v", status, err)
	}
	var accepted api.Sandbox
	if err = json.Unmarshal(raw, &accepted); err != nil || accepted.Id == uuid.Nil || accepted.Generation != 1 {
		t.Fatal("invalid accepted identity", err)
	}
	id := accepted.Id
	// Test-only clock preparation, while no orchestrator/worker authorization
	// exists. Preserve the 300s interval, then never modify either timestamp.
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	for _, q := range []string{`ALTER TABLE sandboxes DISABLE TRIGGER sandbox_immutable_identity`, `UPDATE sandboxes SET created_at=now()-interval '245 seconds',expires_at=now()+interval '55 seconds' WHERE id=$1`, `SET CONSTRAINTS ALL IMMEDIATE`, `ALTER TABLE sandboxes ENABLE TRIGGER sandbox_immutable_identity`} {
		var args []any
		if strings.Contains(q, "$1") {
			args = []any{id}
		}
		if _, err = tx.Exec(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	var originalCreated, originalExpiry time.Time
	if err = pool.QueryRow(ctx, `SELECT created_at,expires_at FROM sandboxes WHERE id=$1`, id).Scan(&originalCreated, &originalExpiry); err != nil {
		t.Fatal(err)
	}
	if originalExpiry.Sub(originalCreated) != 300*time.Second {
		t.Fatal("fixture widened original TTL")
	}
	var runCancel context.CancelFunc
	var runDone chan error
	startAPI := func() {
		runCtx, cancel := context.WithCancel(ctx)
		runCancel = cancel
		runDone = make(chan error, 1)
		go func() {
			runDone <- orchestrator.Run(runCtx, func(id uuid.UUID, err error) { t.Logf("coordinator %s: %v", id, err) })
		}()
	}
	stopAPI := func() {
		runCancel()
		select {
		case <-runDone:
		case <-time.After(3 * time.Second):
			t.Fatal("API coordinator failed to stop")
		}
	}
	startAPI()
	t.Cleanup(func() {
		if runCancel != nil {
			runCancel()
			select {
			case <-runDone:
			case <-time.After(3 * time.Second):
				t.Error("API coordinator failed to stop")
			}
		}
	})
	select {
	case <-bootstrap.entered:
	case <-ctx.Done():
		t.Fatal("enrollment did not reach actual bootstrap invoker")
	}
	// The effect is still pending. Three HTTP handlers must join the independent
	// binding check concurrently: inventory, skills and bootstrap itself.
	overlapping.Store(true)
	healthIdentity.enabled.Store(true)
	type reply struct {
		path   string
		status int
		body   []byte
		err    error
	}
	replies := make(chan reply, 2)
	for _, path := range []string{base + "/sandboxes", base + "/sandbox-skills"} {
		go func() { s, b, e := request(stdhttp.MethodGet, path, nil, ""); replies <- reply{path, s, b, e} }()
	}
	close(bootstrap.release)
	for range 3 {
		select {
		case <-arrived:
		case <-time.After(5 * time.Second):
			t.Fatal("inventory, skills and nested bootstrap did not overlap")
		}
	}
	beforeChecks := checks.Load()
	close(releaseChecks)
	for range 3 {
		select {
		case <-startedChecks:
		case <-time.After(3 * time.Second):
			t.Fatal("not all handlers began actual CheckBinding")
		}
	}
	select {
	case <-healthIdentity.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("actual worker health ping did not reach the held reply")
	}
	// Hold the actual authenticated worker ping reply. Busy-rejection errors
	// would complete a concurrent handler before this bounded hold ends.
	select {
	case got := <-replies:
		t.Fatalf("availability returned before actual health reply: %s status=%d", got.path, got.status)
	case err := <-bootstrap.completed:
		t.Fatal("bootstrap returned before actual health reply", err)
	case <-time.After(200 * time.Millisecond):
	}
	close(healthIdentity.release)
	for range 2 {
		got := <-replies
		if got.err != nil || got.status != 200 {
			t.Fatalf("concurrent %s: status=%d err=%v", got.path, got.status, got.err)
		}
		if strings.HasSuffix(got.path, "/sandboxes") {
			var inventory api.SandboxList
			if json.Unmarshal(got.body, &inventory) != nil || inventory.CreateAvailable || inventory.CreationStatus == nil || !inventory.CreationStatus.RuntimeReady || len(inventory.Items) != 1 || inventory.Items[0].Id != id {
				t.Fatal("inventory lost healthy runtime/current identity or retained-workload quota during enrollment")
			}
			workloadQuota := false
			for _, reason := range inventory.CreationStatus.BlockedReasons {
				switch reason {
				case "runtime_workload_quota_reached":
					workloadQuota = true
				case "user_quota_reached", "organization_quota_reached":
				default:
					t.Fatalf("healthy inventory unexpectedly blocked by %s", reason)
				}
			}
			if !workloadQuota {
				t.Fatal("retained workload did not close subsequent creation")
			}
		} else {
			var catalog api.SandboxSkillList
			if json.Unmarshal(got.body, &catalog) != nil || !catalog.ConfigurationAvailable || len(catalog.Items) != 1 || catalog.Items[0].Id != skill.RevisionID {
				t.Fatal("skills lost actual configuration availability during enrollment")
			}
		}
	}
	select {
	case err = <-bootstrap.completed:
		if err != nil {
			t.Fatal("actual bootstrap failed", err)
		}
	case <-ctx.Done():
		t.Fatal("actual bootstrap did not finish")
	}
	overlapping.Store(false)
	healthIdentity.enabled.Store(false)
	if checks.Load()-beforeChecks != 3 {
		t.Fatal("the three handlers did not actually call the real binding check")
	}
	if healthIdentity.pings.Load() != 1 {
		t.Fatalf("three concurrent handlers did not share one actual worker ping: pings=%d", healthIdentity.pings.Load())
	}
	get := func() api.Sandbox {
		t.Helper()
		status, raw, err := request(stdhttp.MethodGet, base+"/sandboxes/"+id.String(), nil, "")
		if err != nil || status != 200 {
			t.Fatalf("inventory get status=%d err=%v", status, err)
		}
		var out api.Sandbox
		if json.Unmarshal(raw, &out) != nil {
			t.Fatal("invalid public sandbox response")
		}
		return out
	}
	waitState := func(state string) api.Sandbox {
		t.Helper()
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			current := get()
			if string(current.ObservedState) == state {
				return current
			}
			select {
			case <-ticker.C:
			case <-ctx.Done():
				t.Fatalf("did not reach %s, last=%s", state, current.ObservedState)
			}
		}
	}
	ready := waitState("ready")
	if ready.Connection == nil || ready.Generation != 1 || !ready.ExpiresAt.Equal(originalExpiry) || !ready.CreatedAt.Equal(originalCreated) {
		t.Fatal("Ready lost original bounded identity/expiry")
	}
	var peer uuid.UUID
	var runtime, operation string
	if err = pool.QueryRow(ctx, `SELECT s.peer_id,r.runtime_id,l.id::text FROM sandboxes s JOIN sandbox_runtime_bindings r ON r.sandbox_id=s.id JOIN sandbox_launch_operations l ON l.sandbox_id=s.id WHERE s.id=$1`, id).Scan(&peer, &runtime, &operation); err != nil {
		t.Fatal(err)
	}
	workspace := filepath.Join(id.String(), "workspace", "sequence.txt")
	if err = assetsRoot.WriteFile(workspace, []byte("retained across stop/resume"), 0600); err != nil {
		t.Fatal(err)
	}
	action := func(desired string, generation int64) {
		t.Helper()
		status, _, err := request(stdhttp.MethodPost, base+"/sandboxes/"+id.String()+"/actions", api.SandboxAction{DesiredState: api.SandboxActionDesiredState(desired), Generation: generation}, "")
		if err != nil || status != 202 {
			t.Fatalf("actual %s status=%d err=%v", desired, status, err)
		}
		current := get()
		if current.Connection != nil && (desired != "started" || current.ObservedState != "ready" || current.Generation != generation+1 || ready.Connection == nil || *current.Connection != *ready.Connection) {
			t.Fatalf("%s intent exposed an unready or changed terminal", desired)
		}
	}
	action("stopped", ready.Generation)
	stopped := waitState("stopped")
	if stopped.Generation != 2 || stopped.Connection != nil {
		t.Fatal("stop failed current generation/connection fence")
	}
	action("started", stopped.Generation)
	resumed := waitState("ready")
	if resumed.Generation != 3 || resumed.Connection == nil || *resumed.Connection != *ready.Connection || !resumed.ExpiresAt.Equal(originalExpiry) || !resumed.CreatedAt.Equal(originalCreated) {
		t.Fatal("resume replaced host/address identity or extended expiry")
	}
	retained, err := assetsRoot.ReadFile(workspace)
	if err != nil || string(retained) != "retained across stop/resume" {
		t.Fatal("workspace did not persist", err)
	}
	var peerAfter uuid.UUID
	var runtimeAfter, operationAfter string
	if err = pool.QueryRow(ctx, `SELECT s.peer_id,r.runtime_id,l.id::text FROM sandboxes s JOIN sandbox_runtime_bindings r ON r.sandbox_id=s.id JOIN sandbox_launch_operations l ON l.sandbox_id=s.id WHERE s.id=$1`, id).Scan(&peerAfter, &runtimeAfter, &operationAfter); err != nil || peerAfter != peer || runtimeAfter != runtime || operationAfter != operation {
		t.Fatal("resume reenrolled/recreated pinned workload", err)
	}
	// Pause CP reconciliation while the remote TLS polling connection remains.
	// The actual LeaseStore supervisor must fence execution at its immutable
	// wall-clock TTL after the owned fixture's pre-authorization clock rebase.
	stopAPI()
	runCancel = nil
	var receipt sandboxrunner.ExpiryReceipt
	for {
		raw, e := protocolRoot.ReadFile(id.String() + ".expired.json")
		if e == nil {
			if json.Unmarshal(raw, &receipt) != nil {
				t.Fatal("invalid offline expiry receipt")
			}
			break
		}
		if !errors.Is(e, os.ErrNotExist) {
			t.Fatal(e)
		}
		select {
		case <-time.After(100 * time.Millisecond):
		case <-ctx.Done():
			t.Fatal("remote original TTL did not fence disconnected execution")
		}
	}
	physical, err := provider.Inspect(ctx, id)
	if err != nil || physical.Running || !physical.Exists || receipt.Lease.SandboxID != id || receipt.Lease.Generation != 3 || !receipt.Lease.CreatedAt.Equal(originalCreated) || !receipt.Lease.ExpiresAt.Equal(originalExpiry) || receipt.StoppedAt.Before(originalExpiry) {
		t.Fatal("offline fence did not prove original stopped runtime", err)
	}
	if get().Connection != nil {
		t.Fatal("expired public API still exposed connection")
	}
	startAPI()
	deleted := waitState("deleted")
	if deleted.Generation != 4 || deleted.DesiredState != "deleted" || deleted.Connection != nil || !deleted.ExpiresAt.Equal(originalExpiry) {
		t.Fatal("expiry cleanup lost deletion/generation/TTL fence")
	}
	for {
		var retired bool
		if err = pool.QueryRow(ctx, `SELECT worker_retired_at IS NOT NULL FROM sandbox_runtime_bindings WHERE sandbox_id=$1`, id).Scan(&retired); err != nil {
			t.Fatal(err)
		}
		if retired {
			break
		}
		select {
		case <-time.After(100 * time.Millisecond):
		case <-ctx.Done():
			t.Fatal("physical cleanup never retired worker")
		}
	}
	if _, err = provider.Inspect(ctx, id); !errors.Is(err, sandboxruntime.ErrMissing) {
		t.Fatal("provider remains after canonical deletion", err)
	}
	for _, root := range []*os.Root{assetsRoot, controlRoot} {
		if _, err = root.Stat(id.String()); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("owned assets/control remain after retired deletion", err)
		}
	}
	if _, err = controlRoot.Stat("api-binding.json"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("active worker pin retained", err)
	}
	if _, err = controlRoot.Stat("api-completed-" + id.String() + ".json"); err != nil {
		t.Fatal("worker completed receipt absent", err)
	}
	var safe, history bool
	if err = pool.QueryRow(ctx, `SELECT d.status='revoked' AND d.revoked_at IS NOT NULL AND d.health_blocked AND d.assigned_ip IS NULL AND NOT EXISTS(SELECT 1 FROM device_status ds WHERE ds.device_id=d.id) AND NOT EXISTS(SELECT 1 FROM sandbox_runtime_credentials c WHERE c.sandbox_id=s.id AND c.revoked_at IS NULL), EXISTS(SELECT 1 FROM sandbox_remote_terminal_routes r WHERE r.sandbox_id=s.id AND r.terminal_gateway_id=$2 AND r.runtime_gateway_id=$3) AND EXISTS(SELECT 1 FROM sandbox_network_withdrawals w WHERE w.sandbox_id=s.id AND w.generation=s.generation) AND (SELECT count(*) FROM sandbox_launch_operations l WHERE l.sandbox_id=s.id)=1 AND (SELECT count(*) FROM sandbox_bootstrap_tokens b WHERE b.sandbox_id=s.id AND b.consumed_at IS NOT NULL)=1 FROM sandboxes s JOIN devices d ON d.id=s.peer_id WHERE s.id=$1`, id, terminalGW, runtimeGW).Scan(&safe, &history); err != nil || !safe || !history {
		t.Fatal("cleanup released identity without proof or erased immutable history", err)
	}
	stopAPI()
	runCancel = nil
	runnerEffects.mu.Lock()
	counts := make(map[string]int, len(runnerEffects.counts))
	for step, count := range runnerEffects.counts {
		counts[step] = count
	}
	runnerEffects.mu.Unlock()
	if counts["create"] != 1 || counts["start"] != 2 || counts["rm"] != 1 || counts["stop"] < 2 || bootstrap.calls.Load() != 1 || network.inactiveRemovals.Load() < 1 || network.absences.Load() < 2 || policies.calls.Load() < 4 {
		t.Fatalf("sequence skipped effects: create=%d starts=%d deletes=%d stops=%d bootstrap=%d inactive=%d absence=%d policy=%d", counts["create"], counts["start"], counts["rm"], counts["stop"], bootstrap.calls.Load(), network.inactiveRemovals.Load(), network.absences.Load(), policies.calls.Load())
	}
	t.Log("PASS trace: actual HTTP create -> concurrent inventory/skills/nested-bootstrap health -> mTLS worker -> Podman adapter create/start -> same-ID stop/resume -> original remote TTL fence -> inactive cleanup, selected-gateway ACK, address release and worker retirement; kernel effects are explicit fakes")
}

// Existing Podman adapter, with fake argv/output rather than a fake Provider.
type sequencePodmanRunner struct {
	mu              sync.Mutex
	image           string
	exists, running bool
	labels          map[string]string
	mounts          []map[string]any
	counts          map[string]int
}

func (r *sequencePodmanRunner) Run(_ context.Context, args ...string) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.counts == nil {
		r.counts = map[string]int{}
	}
	r.counts[args[0]]++
	switch args[0] {
	case "info":
		return []byte("true"), nil
	case "image":
		return json.Marshal([]any{map[string]any{"Id": r.image, "Architecture": "amd64", "Os": "linux"}})
	case "container":
		if !r.exists {
			return nil, sandboxruntime.ErrMissing
		}
		return nil, nil
	case "create":
		joined := strings.Join(args, " ")
		for _, flag := range []string{"--pull=never", "--network=none", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--memory 128m", "--cpus 1", "--pids-limit 64"} {
			if !strings.Contains(joined, flag) {
				return nil, sandboxruntime.ErrOwnership
			}
		}
		r.labels = map[string]string{}
		r.mounts = nil
		for i, arg := range args {
			if arg == "--label" {
				key, val, _ := strings.Cut(args[i+1], "=")
				r.labels[key] = val
			}
			if arg == "--mount" {
				mount := map[string]any{"RW": true}
				for _, entry := range strings.Split(args[i+1], ",") {
					k, v, _ := strings.Cut(entry, "=")
					switch k {
					case "type":
						mount["Type"] = v
					case "src":
						mount["Source"] = v
					case "dst":
						mount["Destination"] = v
					case "readonly":
						mount["RW"] = v == "false"
					}
				}
				r.mounts = append(r.mounts, mount)
			}
		}
		r.exists = true
		r.running = false
		return nil, nil
	case "inspect":
		return json.Marshal([]any{map[string]any{"Id": strings.Repeat("b", 64), "Image": r.image, "Config": map[string]any{"Labels": r.labels}, "State": map[string]any{"Running": r.running}, "Mounts": r.mounts}})
	case "start":
		r.running = true
		return nil, nil
	case "stop":
		r.running = false
		return nil, nil
	case "rm":
		r.exists = false
		r.running = false
		return nil, nil
	}
	return nil, sandboxruntime.ErrUnavailable
}

type sequenceNetwork struct {
	pool                       *pgxpool.Pool
	provider                   sandboxruntime.Provider
	inactiveRemovals, absences atomic.Int32
}

func (*sequenceNetwork) ApplyPrivateNetwork(context.Context, sandboxes.PrivateNetworkTarget, []byte) error {
	return nil
}
func (n *sequenceNetwork) RemovePrivateNetwork(ctx context.Context, target sandboxes.PrivateNetworkTarget, _ []byte) error {
	status, err := n.provider.Inspect(ctx, target.SandboxID)
	if err != nil || !status.Exists || status.RuntimeID != target.RuntimeID || status.SpecHash != target.SpecHash {
		return sandboxes.ErrConflict
	}
	if !status.Running {
		n.inactiveRemovals.Add(1)
	}
	return nil
}
func (*sequenceNetwork) InspectPrivateNetwork(_ context.Context, target sandboxes.PrivateNetworkTarget) (sandboxes.PrivateNetworkObservation, error) {
	return sandboxes.PrivateNetworkObservation{Target: target, ObservedAt: time.Now().UTC()}, nil
}
func (n *sequenceNetwork) InspectGatewayAbsence(context.Context, sandboxes.PrivateNetworkTarget, []byte) error {
	n.absences.Add(1)
	return nil
}
func (n *sequenceNetwork) ProbePrivateTerminal(ctx context.Context, target sandboxes.PrivateNetworkTarget, host ssh.PublicKey, _ ssh.Signer) (sandboxruntime.SSHProbeResult, error) {
	node, err := sqlc.New(n.pool).GetNodeForOrg(ctx, sqlc.GetNodeForOrgParams{ID: target.GatewayID, OrgID: target.OrgID})
	if err != nil {
		return sandboxruntime.SSHProbeResult{}, err
	}
	if err = nodes.NewService(n.pool, nil, nil).ReportStatus(ctx, node, []nodes.PeerStatus{{PublicKey: target.PublicKey, LastHandshake: time.Now().UTC().Unix()}}); err != nil {
		return sandboxruntime.SSHProbeResult{}, err
	}
	return sandboxruntime.SSHProbeResult{HostKeyFingerprint: ssh.FingerprintSHA256(host), ObservedAt: time.Now().UTC(), UID: 1001}, nil
}

type sequencePolicies struct {
	pool    *pgxpool.Pool
	org     uuid.UUID
	allowed map[uuid.UUID]bool
	calls   atomic.Int32
}

func (p *sequencePolicies) PolicyHealthForNodes(ctx context.Context, org uuid.UUID, selected []sqlc.Node, _ ...nodes.SiteTopoBatch) map[uuid.UUID]nodes.PolicyHealth {
	out := map[uuid.UUID]nodes.PolicyHealth{}
	if org != p.org || len(selected) != 2 {
		return out
	}
	p.calls.Add(1)
	for _, node := range selected {
		if !p.allowed[node.ID] {
			return map[uuid.UUID]nodes.PolicyHealth{}
		}
		if _, err := p.pool.Exec(ctx, `UPDATE nodes SET policy_reported_at=now() WHERE id=$1 AND org_id=$2`, node.ID, org); err != nil {
			return map[uuid.UUID]nodes.PolicyHealth{}
		}
		out[node.ID] = nodes.PolicyHealth{Kind: nodes.KindHealthy, PushKnown: true, PushedHash: "sequence-finalized", AppliedHash: "sequence-finalized"}
	}
	return out
}

type sequenceBootstrap struct {
	client           *stdhttp.Client
	entered, release chan struct{}
	completed        chan error
	calls            atomic.Int32
}

// The fixed read-only worker ping calls Identity.PublicKey while preparing its
// reply. Delegate the real key unchanged; gate/count only the held enrollment
// phase, so serialization cannot masquerade as shared concurrent health.
type sequenceHealthSigner struct {
	ssh.Signer
	enabled          atomic.Bool
	pings            atomic.Int32
	once             sync.Once
	entered, release chan struct{}
}

func (s *sequenceHealthSigner) PublicKey() ssh.PublicKey {
	if s.enabled.Load() {
		s.pings.Add(1)
		s.once.Do(func() { close(s.entered) })
		<-s.release
	}
	return s.Signer.PublicKey()
}

func (b *sequenceBootstrap) Bootstrap(ctx context.Context, server string, id uuid.UUID, generation int64, directory, token string) (err error) {
	b.calls.Add(1)
	close(b.entered)
	defer func() { b.completed <- err }()
	select {
	case <-b.release:
	case <-ctx.Done():
		return ctx.Err()
	}
	private, public, err := wgkey.Generate()
	if err != nil {
		return err
	}
	body, _ := json.Marshal(api.SandboxBootstrapRequest{BootstrapToken: token, PublicKey: public})
	req, err := stdhttp.NewRequestWithContext(ctx, stdhttp.MethodPost, server+"/api/v1/sandbox/bootstrap", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := b.client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return fmt.Errorf("bootstrap status %d", res.StatusCode)
	}
	var response api.SandboxBootstrapResponse
	if err = json.NewDecoder(res.Body).Decode(&response); err != nil {
		return err
	}
	if response.SandboxId != id || response.Generation != generation || response.PeerId == uuid.Nil {
		return sandboxes.ErrConflict
	}
	if err = os.Mkdir(directory, 0700); err != nil {
		return err
	}
	state, _ := json.Marshal(map[string]any{"server": server, "sandbox_id": id, "peer_id": response.PeerId, "generation": generation})
	for name, content := range map[string][]byte{"state.json": state, "wireguard.conf": []byte(strings.Replace(response.Config, "__TUNNEX_PRIVATE_KEY__", private, 1)), "runtime-credential": []byte(response.RuntimeCredential + "\n")} {
		if err = os.WriteFile(filepath.Join(directory, name), content, 0600); err != nil {
			return err
		}
	}
	return nil
}

func sequenceRemoteTLS(t *testing.T, ctx context.Context, worker *sandboxes.WorkerRPCServer, protocol *os.Root) (*sandboxes.WorkerRPCClient, *sandboxrunner.Client) {
	t.Helper()
	// Production requires an existing private address. Never alter interfaces or
	// route to a VPN: select only an ordinary local ethernet/wifi interface.
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	var host string
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 || !(strings.HasPrefix(iface.Name, "en") || strings.HasPrefix(iface.Name, "eth")) {
			continue
		}
		addresses, _ := iface.Addrs()
		for _, address := range addresses {
			ip, _, e := net.ParseCIDR(address.String())
			if e == nil && ip.To4() != nil && ip.IsPrivate() {
				host = ip.String()
				break
			}
		}
		if host != "" {
			break
		}
	}
	if host == "" {
		t.Skip("actual remote constructor requires a bindable ordinary local RFC1918 interface")
	}
	enrollment, err := sandboxrunner.Enroll("localhost", "spiffe://tunnex/controller/sequence-fixture", "spiffe://tunnex/runner/sequence-fixture", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	files := t.TempDir()
	config := sandboxes.RemoteWorkerConfig{RunnerURI: "spiffe://tunnex/runner/sequence-fixture"}
	for name, content := range map[string][]byte{"controller.pem": enrollment.ControllerCertificate, "controller.key": enrollment.ControllerKey, "ca.pem": enrollment.CA, "ca.key": enrollment.ControllerCAKey} {
		if err = os.WriteFile(filepath.Join(files, name), content, 0600); err != nil {
			t.Fatal(err)
		}
	}
	config.CertificateFile = filepath.Join(files, "controller.pem")
	config.PrivateKeyFile = filepath.Join(files, "controller.key")
	config.CAFile = filepath.Join(files, "ca.pem")
	config.CAKeyFile = filepath.Join(files, "ca.key")
	var remote *sandboxes.WorkerRPCClient
	for range 3 {
		listener, e := net.Listen("tcp", net.JoinHostPort(host, "0"))
		if e != nil {
			t.Fatal("private fixture listener", e)
		}
		config.Listen = listener.Addr().String()
		listener.Close()
		remote, err = sandboxes.NewRemoteWorkerRPCClient(config, worker.Identity.PublicKey())
		if err == nil {
			break
		}
	}
	if err != nil {
		t.Fatal("actual remote constructor", err)
	}
	t.Cleanup(func() { remote.Close() })
	certificate, err := tls.X509KeyPair(enrollment.RunnerCertificate, enrollment.RunnerKey)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(enrollment.CA) {
		t.Fatal("generated fixture CA")
	}
	client, err := sandboxrunner.NewClient("https://"+config.Listen, "localhost", "spiffe://tunnex/controller/sequence-fixture", certificate, roots, protocol)
	if err != nil {
		t.Fatal(err)
	}
	return remote, client
}
