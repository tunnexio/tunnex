package sandboxes

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/sandboxruntime"
	"github.com/tunnexio/tunnex/apps/api/internal/wgkey"
	"golang.org/x/crypto/ssh"
)

func organizationAdmissionFixture(t *testing.T) (fixture, BoundedRuntimeBinding, map[uuid.UUID]uuid.UUID) {
	t.Helper()
	f := newFixture(t)
	b := persistentTestBinding()
	b.Admission, b.OrgID, b.GatewayID = "organization", f.org, f.node
	b.CreatorID, b.TerminalDeviceID = uuid.Nil, uuid.Nil
	b.Profiles = b.Profiles[:1]
	_, gatewayKey, _ := wgkey.Generate()
	devExec(t, f, `UPDATE nodes SET status='active',endpoint='10.0.0.1:51820',wg_public_key=$2 WHERE id=$1`, f.node, gatewayKey)
	devExec(t, f, `UPDATE organizations SET max_sandboxes_per_user=20,max_sandboxes=30 WHERE id=$1`, f.org)
	p := b.Profiles[0]
	devExec(t, f, `INSERT INTO sandbox_templates(id,org_id,name,image_digest,maximum_scope,memory_mib,max_ttl_seconds,enabled) VALUES($1,$2,'qualified organization terminal',$3,'[]',128,900,true)`, p.TemplateID, f.org, p.ConfigDigest)
	devices := map[uuid.UUID]uuid.UUID{}
	for i, owner := range []uuid.UUID{f.user, f.other} {
		id := uuid.New()
		_, public, _ := wgkey.Generate()
		devExec(t, f, `INSERT INTO devices(id,org_id,user_id,node_id,name,public_key,assigned_ip,kind) VALUES($1,$2,$3,$4,'owned terminal',$5,$6,'human')`, id, f.org, owner, f.node, public, []string{"10.99.0.2", "10.99.0.3"}[i])
		devices[owner] = id
	}
	if _, err := f.store.WithBoundedRuntime(b); err != nil {
		t.Fatal(err)
	}
	return f, b, devices
}

func organizationInput(f fixture, b BoundedRuntimeBinding, device uuid.UUID, key string) CreateInput {
	return CreateInput{TemplateID: b.Profiles[0].TemplateID, TerminalDeviceID: &device, Name: "owned work", TTLSeconds: 900, IdempotencyKey: key, SSHPublicKeys: []string{f.sshPublicKey}}
}

func TestOrganizationPostgresConcurrentMembersShareRetainedCapacity(t *testing.T) {
	f, b, devices := organizationAdmissionFixture(t)
	type result struct {
		actor uuid.UUID
		value Sandbox
		err   error
	}
	results := make(chan result, 2)
	var ready sync.WaitGroup
	ready.Add(2)
	for _, actor := range []uuid.UUID{f.user, f.other} {
		go func(actor uuid.UUID) {
			ready.Done()
			ready.Wait()
			value, _, err := f.store.Create(f.ctx, f.org, actor, organizationInput(f, b, devices[actor], "shared-text-key"))
			results <- result{actor, value, err}
		}(actor)
	}
	a, c := <-results, <-results
	if (a.err == nil) == (c.err == nil) || (!errors.Is(a.err, ErrQuota) && !errors.Is(c.err, ErrQuota)) {
		t.Fatalf("shared capacity race: %v %v", a.err, c.err)
	}
	winner, denied := a, c
	if c.err == nil {
		winner, denied = c, a
	}
	var terminal uuid.UUID
	if err := f.pool.QueryRow(f.ctx, `SELECT terminal_device_id FROM sandboxes WHERE id=$1`, winner.value.Identity.ID).Scan(&terminal); err != nil || terminal != devices[winner.actor] || winner.value.Identity.CreatorID != winner.actor {
		t.Fatal("accepted owner/device identity changed", err)
	}
	if _, err := f.store.Get(f.ctx, f.org, denied.actor, winner.value.Identity.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("other creator read accepted", err)
	}
	if _, err := f.store.SetDesired(f.ctx, f.org, denied.actor, winner.value.Identity.ID, 1, "stopped"); !errors.Is(err, ErrNotFound) {
		t.Fatal("other creator mutation accepted", err)
	}
	in := organizationInput(f, b, devices[winner.actor], "shared-text-key")
	again, replay, err := f.store.Create(f.ctx, f.org, winner.actor, in)
	if err != nil || !replay || again.Identity.ID != winner.value.Identity.ID {
		t.Fatal("owner replay changed", err)
	}
	otherDevice := uuid.New()
	_, public, _ := wgkey.Generate()
	devExec(t, f, `INSERT INTO devices(id,org_id,user_id,node_id,name,public_key,assigned_ip,kind) VALUES($1,$2,$3,$4,'second owned terminal',$5,'10.99.0.4','human')`, otherDevice, f.org, winner.actor, f.node, public)
	in.TerminalDeviceID = &otherDevice
	if _, _, err = f.store.Create(f.ctx, f.org, winner.actor, in); !errors.Is(err, ErrConflict) {
		t.Fatal("same request key rebound terminal", err)
	}
	// These fixture-only tombstones model confirmed cleanup, not physical proof.
	devExec(t, f, `UPDATE sandboxes SET desired_state='deleted',observed_state='deleted' WHERE id=$1`, winner.value.Identity.ID)
	if _, _, err = f.store.Create(f.ctx, f.org, denied.actor, organizationInput(f, b, devices[denied.actor], "shared-text-key")); !errors.Is(err, ErrQuota) {
		t.Fatal("unretired deletion released capacity", err)
	}
	devExec(t, f, `UPDATE sandbox_runtime_bindings SET worker_retired_at=now() WHERE sandbox_id=$1`, winner.value.Identity.ID)
	next, replay, err := f.store.Create(f.ctx, f.org, denied.actor, organizationInput(f, b, devices[denied.actor], "shared-text-key"))
	if err != nil || replay || next.Identity.ID == winner.value.Identity.ID || next.Identity.CreatorID != denied.actor {
		t.Fatal("second owner sequential admission/idempotency failed", err)
	}
}

func TestOrganizationPostgresRejectsUnownedOrIneligibleTerminal(t *testing.T) {
	for _, scenario := range []string{"omitted", "zero", "other owner", "foreign org", "agent", "blocked", "revoked", "deleted", "gateway", "inactive gateway", "reassigned"} {
		t.Run(scenario, func(t *testing.T) {
			f, b, devices := organizationAdmissionFixture(t)
			device := devices[f.user]
			in := organizationInput(f, b, device, "denied")
			want := ErrForbidden
			switch scenario {
			case "omitted":
				in.TerminalDeviceID = nil
				want = ErrInvalid
			case "zero":
				zero := uuid.Nil
				in.TerminalDeviceID = &zero
				want = ErrInvalid
			case "other owner":
				other := devices[f.other]
				in.TerminalDeviceID = &other
			case "foreign org":
				foreign := uuid.New()
				devExec(t, f, `INSERT INTO organizations(id,name,slug,pool_cidr) VALUES($1,'foreign',$2,'10.100.0.0/24')`, foreign, foreign.String())
				foreignNode := uuid.New()
				devExec(t, f, `INSERT INTO nodes(id,org_id,name,cert_serial) VALUES($1,$2,'foreign gateway',$3)`, foreignNode, foreign, foreignNode.String())
				_, public, _ := wgkey.Generate()
				foreignDevice := uuid.New()
				devExec(t, f, `INSERT INTO devices(id,org_id,user_id,node_id,name,public_key,kind) VALUES($1,$2,$3,$4,'foreign terminal',$5,'human')`, foreignDevice, foreign, f.user, foreignNode, public)
				in.TerminalDeviceID = &foreignDevice
			case "agent":
				devExec(t, f, `UPDATE devices SET kind='agent' WHERE id=$1`, device)
			case "blocked":
				devExec(t, f, `UPDATE devices SET health_blocked=true WHERE id=$1`, device)
			case "revoked":
				devExec(t, f, `UPDATE devices SET status='revoked',revoked_at=now(),revoked_cause='deliberate' WHERE id=$1`, device)
			case "deleted":
				devExec(t, f, `UPDATE devices SET deleted_at=now() WHERE id=$1`, device)
			case "gateway":
				node := uuid.New()
				devExec(t, f, `INSERT INTO nodes(id,org_id,name,cert_serial) VALUES($1,$2,'other gateway',$3)`, node, f.org, node.String())
				devExec(t, f, `UPDATE devices SET node_id=$2 WHERE id=$1`, device, node)
			case "inactive gateway":
				devExec(t, f, `UPDATE nodes SET status='revoked' WHERE id=$1`, f.node)
			case "reassigned":
				devExec(t, f, `UPDATE devices SET user_id=$2 WHERE id=$1`, device, f.other)
			}
			if _, _, err := f.store.Create(f.ctx, f.org, f.user, in); !errors.Is(err, want) {
				t.Fatal("ineligible terminal admission", err, "want", want)
			}
			var count int
			if err := f.pool.QueryRow(f.ctx, `SELECT count(*) FROM sandboxes`).Scan(&count); err != nil || count != 0 {
				t.Fatal("denied create persisted a sandbox", count, err)
			}
		})
	}
}

func TestOrganizationPostgresStartUsesImmutableOwnerTerminal(t *testing.T) {
	f, b, devices := organizationAdmissionFixture(t)
	value, _, err := f.store.Create(f.ctx, f.org, f.other, organizationInput(f, b, devices[f.other], "stored-owner"))
	if err != nil {
		t.Fatal(err)
	}
	conn, err := f.pool.Acquire(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()
	target, err := f.store.prepareStart(f.ctx, conn, value.Identity.ID)
	if err != nil || target.authorization == nil || target.authorization.CreatorID != f.other || target.authorization.TerminalDeviceID != devices[f.other] {
		t.Fatal("start substituted configured/current creator/device", err)
	}
	devExec(t, f, `UPDATE devices SET user_id=$2 WHERE id=$1`, devices[f.other], f.user)
	if err = bindStart(f.ctx, conn, target, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"); !errors.Is(err, ErrConflict) {
		t.Fatal("stale pre-effect eligibility bound a reassigned terminal", err)
	}
	var bound bool
	if err = f.pool.QueryRow(f.ctx, `SELECT runtime_id IS NOT NULL FROM sandbox_runtime_bindings WHERE sandbox_id=$1`, value.Identity.ID).Scan(&bound); err != nil || bound {
		t.Fatal("eligibility race persisted runtime binding", bound, err)
	}
	if _, err = f.store.prepareStart(f.ctx, conn, value.Identity.ID); !errors.Is(err, ErrForbidden) {
		t.Fatal("start accepted reassigned terminal", err)
	}
	if _, err = f.store.SetDesired(f.ctx, f.org, f.other, value.Identity.ID, value.Revision, "started"); !errors.Is(err, ErrForbidden) {
		t.Fatal("start intent accepted reassigned terminal", err)
	}
}

type organizationReadinessRaceProvider struct {
	runningProvider
	afterInspect func()
}

func (p *organizationReadinessRaceProvider) Inspect(ctx context.Context, id uuid.UUID) (sandboxruntime.Status, error) {
	status, err := p.runningProvider.Inspect(ctx, id)
	if p.afterInspect != nil {
		after := p.afterInspect
		p.afterInspect = nil
		after()
	}
	return status, err
}

func TestOrganizationPostgresReadyCASRejectsWithdrawnAuthority(t *testing.T) {
	for _, scenario := range []string{"ready", "device reassigned", "membership revoked"} {
		t.Run(scenario, func(t *testing.T) {
			f, b, devices := organizationAdmissionFixture(t)
			devExec(t, f, `UPDATE nodes SET policy_reported_at=now() WHERE id=$1`, f.node)
			value, _, err := f.store.Create(f.ctx, f.org, f.user, organizationInput(f, b, devices[f.user], "ready-race"))
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
			assetRoot, err := os.OpenRoot(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer assetRoot.Close()
			assets, err := sandboxruntime.NewFilesystemAssets(assetRoot)
			if err != nil {
				t.Fatal(err)
			}
			controlRoot, err := os.OpenRoot(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer controlRoot.Close()
			files, err := NewFileBootstrapTransport(controlRoot, "https://fixture.example", &enrollmentInvokerFixture{f: f})
			if err != nil {
				t.Fatal(err)
			}
			provider := &organizationReadinessRaceProvider{}
			network := &composedNetworkFixture{f: f}
			network.afterProbe = func() {
				// Arm the last provider observation: current prepareStart already
				// passed when this change races the final Ready UPDATE.
				provider.afterInspect = func() {
					switch scenario {
					case "device reassigned":
						devExec(t, f, `UPDATE devices SET user_id=$2 WHERE id=$1`, devices[f.user], f.other)
					case "membership revoked":
						devExec(t, f, `UPDATE memberships SET access_revoked_at=now() WHERE org_id=$1 AND user_id=$2`, f.org, f.user)
					}
				}
			}
			initial := &InitialLaunchCoordinator{Store: f.store, Provider: provider, AssetsRoot: assetRoot, Assets: assets, Files: files, Network: network, Probe: network, ProbeIdentity: identity, Policies: &readinessPolicyFixture{hash: "finalized"}, Sealer: launchTestSealer(t), GatewayID: f.node}
			err = initial.Reconcile(f.ctx, value.Identity.ID)
			if scenario == "ready" && err != nil || scenario != "ready" && !errors.Is(err, ErrConflict) {
				t.Fatal("unexpected Ready race result", err)
			}
			var state string
			if err = f.pool.QueryRow(f.ctx, `SELECT observed_state FROM sandboxes WHERE id=$1`, value.Identity.ID).Scan(&state); err != nil || (state == "ready") != (scenario == "ready") {
				t.Fatal("withdrawn authority became Ready", state, err)
			}
			var readyAudits int
			if err = f.pool.QueryRow(f.ctx, `SELECT count(*) FROM audit_logs WHERE action='sandbox.ready' AND target_id=$1`, value.Identity.ID.String()).Scan(&readyAudits); err != nil || (readyAudits == 1) != (scenario == "ready") {
				t.Fatal("invalid Ready audit persisted", readyAudits, err)
			}
		})
	}
}
