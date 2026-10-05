package sandboxes

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/nodes"
	"github.com/tunnexio/tunnex/apps/api/internal/sandboxruntime"
	"github.com/tunnexio/tunnex/apps/api/internal/wgkey"
	"golang.org/x/crypto/ssh"
)

type composedNetworkFixture struct {
	readinessNetworkFixture
	f                                        fixture
	applications, removals, absences, probes int
	appliedMTUs                              []int
	appliedConfigs                           [][]byte
	pendingProbe                             bool
	rejectRepeatedRemove                     bool
	afterProbe                               func()
}

func (n *composedNetworkFixture) ApplyPrivateNetwork(_ context.Context, target PrivateNetworkTarget, config []byte) error {
	plan, _, err := privateNetworkPlan(target, config)
	if err != nil {
		return err
	}
	n.appliedMTUs = append(n.appliedMTUs, plan.MTU)
	n.appliedConfigs = append(n.appliedConfigs, append([]byte(nil), config...))
	n.applications++
	return nil
}
func (n *composedNetworkFixture) RemovePrivateNetwork(_ context.Context, _ PrivateNetworkTarget, _ []byte) error {
	n.removals++
	if n.rejectRepeatedRemove && n.removals > 1 {
		return ErrDisabled
	}
	return nil
}
func (n *composedNetworkFixture) InspectGatewayAbsence(_ context.Context, _ PrivateNetworkTarget, _ []byte) error {
	n.absences++
	return nil
}
func (n *composedNetworkFixture) ProbePrivateTerminal(ctx context.Context, target PrivateNetworkTarget, host ssh.PublicKey, _ ssh.Signer) (sandboxruntime.SSHProbeResult, error) {
	n.probes++
	if n.afterProbe != nil {
		n.afterProbe()
	}
	if n.pendingProbe {
		n.pendingProbe = false
		return sandboxruntime.SSHProbeResult{}, sandboxruntime.ErrUnavailable
	}
	node, err := sqlc.New(n.f.pool).GetNodeForOrg(ctx, sqlc.GetNodeForOrgParams{ID: target.GatewayID, OrgID: target.OrgID})
	if err != nil {
		return sandboxruntime.SSHProbeResult{}, err
	}
	if err = nodes.NewService(n.f.pool, nil, nil).ReportStatus(ctx, node, []nodes.PeerStatus{{PublicKey: target.PublicKey, LastHandshake: time.Now().UTC().Unix()}}); err != nil {
		return sandboxruntime.SSHProbeResult{}, err
	}
	return sandboxruntime.SSHProbeResult{HostKeyFingerprint: ssh.FingerprintSHA256(host), ObservedAt: time.Now().UTC(), UID: 1001}, nil
}

type uncertainStopProvider struct {
	runningProvider
	uncertainStop bool
}

func (p *uncertainStopProvider) Delete(context.Context, uuid.UUID) error {
	p.status = sandboxruntime.Status{}
	return nil
}

func (p *uncertainStopProvider) Stop(ctx context.Context, id uuid.UUID) error {
	_ = p.runningProvider.Stop(ctx, id)
	if p.uncertainStop {
		p.uncertainStop = false
		return sandboxruntime.ErrUnavailable
	}
	return nil
}

func TestInitialLaunchPostgresCompositionAndLostStopRecovery(t *testing.T) {
	f := newFixture(t)
	_, gatewayKey, _ := wgkey.Generate()
	if _, err := f.pool.Exec(f.ctx, `UPDATE nodes SET endpoint='127.0.0.1:51820',wg_public_key=$2,status='active',policy_reported_at=now() WHERE id=$1`, f.node, gatewayKey); err != nil {
		t.Fatal(err)
	}
	sandbox, _, err := f.store.Create(f.ctx, f.org, f.user, f.input("composed-launch"))
	if err != nil {
		t.Fatal(err)
	}
	_, private, _ := ed25519.GenerateKey(rand.Reader)
	identity, _ := ssh.NewSignerFromKey(private)
	assetRoot, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer assetRoot.Close()
	assets, _ := sandboxruntime.NewFilesystemAssets(assetRoot)
	controlRoot, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer controlRoot.Close()
	invoker := &enrollmentInvokerFixture{f: f, uncertain: true}
	files, err := NewFileBootstrapTransport(controlRoot, "https://fixture.example", invoker)
	if err != nil {
		t.Fatal(err)
	}
	provider := &uncertainStopProvider{}
	network := &composedNetworkFixture{f: f, pendingProbe: true}
	policies := &readinessPolicyFixture{hash: "finalized"}
	coordinator := &InitialLaunchCoordinator{Store: f.store, Provider: provider, AssetsRoot: assetRoot, Assets: assets, Files: files, Network: network, Probe: network, ProbeIdentity: identity, Policies: policies, Sealer: launchTestSealer(t), GatewayID: f.node}
	// Recover the same persisted response, assets and runtime after uncertain
	// bootstrap, then wait for independent SSH readiness without another enrollment.
	if err = coordinator.Reconcile(f.ctx, sandbox.Identity.ID); !errors.Is(err, ErrDisabled) {
		t.Fatal("uncertain bootstrap not retained", err)
	}
	if err = coordinator.Reconcile(f.ctx, sandbox.Identity.ID); !errors.Is(err, sandboxruntime.ErrUnavailable) {
		t.Fatal("pending SSH was admitted", err)
	}
	// Model published immutable files surviving a lost metadata write. Ready
	// recovery must derive the original public pin from those verified assets.
	if _, err = f.pool.Exec(f.ctx, `DELETE FROM sandbox_terminal_identities WHERE sandbox_id=$1`, sandbox.Identity.ID); err != nil {
		t.Fatal(err)
	}
	if err = coordinator.Reconcile(f.ctx, sandbox.Identity.ID); err != nil {
		t.Fatal("composed recovery failed", err)
	}
	current, err := f.store.Get(f.ctx, f.org, f.user, sandbox.Identity.ID)
	if err != nil || current.State != StateReady || current.PeerID == nil {
		t.Fatal("not ready", current, err)
	}
	if current.Connection == nil || current.Connection.Address == "" || current.Connection.HostPublicKey == "" || current.Connection.Username != "sandbox" || current.Connection.Port != 22 {
		t.Fatal("ready public connection absent")
	}
	// Existing cross-gateway transport may carry ordinary clients, but must not
	// acquire sandbox identities through its legacy organization-wide roster.
	carriers, err := sqlc.New(f.pool).ListCrossGatewayClients(f.ctx, f.org)
	if err != nil || len(carriers) != 0 {
		t.Fatal("sandbox entered ordinary cross-gateway transport", carriers, err)
	}

	if _, err = f.store.Get(f.ctx, uuid.New(), f.user, sandbox.Identity.ID); err == nil {
		t.Fatal("foreign organization exposed terminal")
	}
	if _, err = f.pool.Exec(f.ctx, `UPDATE sandbox_templates SET enabled=false WHERE id=$1`, current.TemplateVersionID); err != nil {
		t.Fatal(err)
	}
	hidden, err := f.store.Get(f.ctx, f.org, f.user, sandbox.Identity.ID)
	if err != nil || hidden.Connection != nil {
		t.Fatal("stale Ready exposed disabled template", err)
	}
	if _, err = f.pool.Exec(f.ctx, `UPDATE sandbox_templates SET enabled=true WHERE id=$1`, current.TemplateVersionID); err != nil {
		t.Fatal(err)
	}
	if invoker.calls != 1 || provider.creates != 1 || provider.starts != 1 {
		t.Fatal("recovery replaced an identity", invoker.calls, provider.creates, provider.starts)
	}
	stopped, err := f.store.SetDesired(f.ctx, f.org, f.user, sandbox.Identity.ID, current.Revision, "stopped")
	if err != nil {
		t.Fatal(err)
	}
	hidden, err = f.store.Get(f.ctx, f.org, f.user, sandbox.Identity.ID)
	if err != nil || hidden.Connection != nil {
		t.Fatal("stop intent exposed connection", err)
	}
	network.rejectRepeatedRemove = true
	provider.uncertainStop = true
	cleanup := &PrivateNetworkCleanup{Store: f.store, Network: network, Gateway: network, Files: files, Policies: policies}
	if err = f.store.ReconcileCleanup(f.ctx, sandbox.Identity.ID, provider, cleanup); !errors.Is(err, sandboxruntime.ErrUnavailable) {
		t.Fatal("lost stop not exercised", err)
	}
	if err = f.store.ReconcileCleanup(f.ctx, sandbox.Identity.ID, provider, cleanup); err != nil {
		t.Fatal("durable withdrawal did not recover stop", err)
	}
	current, err = f.store.Get(f.ctx, f.org, f.user, sandbox.Identity.ID)
	if err != nil || current.State != StateStopped || current.Revision != stopped.Revision || network.removals != 1 || network.absences != 1 || provider.starts != 1 {
		t.Fatal("withdrawal repeated or stop failed", current, network.removals, network.absences, err)
	}
	// Resume must retain the original assets, peer and enrollment operation.
	// Stopped inventory hides connection; recover original public pin from metadata.
	var public, fingerprint, address string
	if err = f.pool.QueryRow(f.ctx, `SELECT t.host_public_key,t.host_key_fingerprint,d.assigned_ip FROM sandbox_terminal_identities t JOIN sandboxes s ON s.id=t.sandbox_id JOIN devices d ON d.id=s.peer_id WHERE s.id=$1`, sandbox.Identity.ID).Scan(&public, &fingerprint, &address); err != nil {
		t.Fatal(err)
	}
	started, err := f.store.SetDesired(f.ctx, f.org, f.user, sandbox.Identity.ID, current.Revision, "started")
	if err != nil {
		t.Fatal(err)
	}
	resume := &ResumeCoordinator{Initial: coordinator}
	if err = resume.Reconcile(f.ctx, sandbox.Identity.ID); !errors.Is(err, ErrConflict) {
		t.Fatal("stale policy ACK admitted", err)
	}
	hidden, err = f.store.Get(f.ctx, f.org, f.user, sandbox.Identity.ID)
	if err != nil || hidden.Connection != nil || hidden.State != StateStarting {
		t.Fatal("resume exposed pending connection", hidden, err)
	}
	var epoch time.Time
	if err = f.pool.QueryRow(f.ctx, `SELECT created_at FROM sandbox_start_epochs WHERE sandbox_id=$1 AND generation=$2`, sandbox.Identity.ID, started.Revision).Scan(&epoch); err != nil {
		t.Fatal(err)
	}
	if _, err = f.pool.Exec(f.ctx, `UPDATE nodes SET policy_reported_at=now() WHERE id=$1`, f.node); err != nil {
		t.Fatal(err)
	}
	// Reconstruct coordinator after an uncertain worker restart; epoch stays fixed.
	if err = (&ResumeCoordinator{Initial: coordinator}).Reconcile(f.ctx, sandbox.Identity.ID); err != nil {
		t.Fatal("resume failed", err)
	}
	resumed, err := f.store.Get(f.ctx, f.org, f.user, sandbox.Identity.ID)
	if err != nil || resumed.State != StateReady || resumed.Connection == nil || *resumed.PeerID != *current.PeerID || resumed.Connection.HostPublicKey != strings.TrimSpace(public) || resumed.Connection.HostKeyFingerprint != fingerprint || resumed.Connection.Address != address || provider.starts != 2 || provider.creates != 1 || invoker.calls != 1 {
		t.Fatal("resume replaced identity", resumed, err)
	}
	if len(network.appliedMTUs) < 2 {
		t.Fatal("initial/resume application absent")
	}
	for i, mtu := range network.appliedMTUs {
		if mtu != 1280 || string(network.appliedConfigs[i]) != string(network.appliedConfigs[0]) {
			t.Fatal("initial/resume retry changed persisted MTU/config", network.appliedMTUs)
		}
	}

	var retained time.Time
	if err = f.pool.QueryRow(f.ctx, `SELECT created_at FROM sandbox_start_epochs WHERE sandbox_id=$1 AND generation=$2`, sandbox.Identity.ID, started.Revision).Scan(&retained); err != nil || !epoch.Equal(retained) {
		t.Fatal("resume epoch changed", err)
	}
	// Missing completed withdrawal fails closed before an external restart.
	network.rejectRepeatedRemove = false
	stopped, err = f.store.SetDesired(f.ctx, f.org, f.user, sandbox.Identity.ID, resumed.Revision, "stopped")
	if err != nil {
		t.Fatal(err)
	}
	if err = f.store.ReconcileCleanup(f.ctx, sandbox.Identity.ID, provider, cleanup); err != nil {
		t.Fatal(err)
	}
	if _, err = f.store.SetDesired(f.ctx, f.org, f.user, sandbox.Identity.ID, stopped.Revision, "started"); err != nil {
		t.Fatal(err)
	}
	if _, err = f.pool.Exec(f.ctx, `DELETE FROM sandbox_network_withdrawals WHERE sandbox_id=$1`, sandbox.Identity.ID); err != nil {
		t.Fatal(err)
	}
	if err = resume.Reconcile(f.ctx, sandbox.Identity.ID); !errors.Is(err, ErrConflict) || provider.starts != 2 {
		t.Fatal("missing withdrawal admitted", err)
	}

}
