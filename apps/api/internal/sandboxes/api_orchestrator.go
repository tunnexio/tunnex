package sandboxes

import (
	"context"
	"io"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/sandboxruntime"
	"golang.org/x/crypto/ssh"
)

// WorkerRuntime contains external effects only. Main DB, canonical enterprise
// policy, credentials and the sealer remain in the API process. A Unix RPC
// implementation must authenticate the API process, bind the exact org/gateway
// and pin each sandbox, image and resource envelope before executing effects.
type WorkerRuntime interface {
	sandboxruntime.Provider
	sandboxruntime.AssetResolver
	CreationAssetMaterializer
	TerminalAssetVerifier
	LaunchControlTransport
	PrivateNetworkControl
	GatewayAbsenceInspector
	TargetSSHProber
	ProbePublicKey() ssh.PublicKey
}

// RuntimeRetirer completes durable per-sandbox cleanup. Trial mode also closes
// worker authority. API acknowledgement follows the physical-cleanup tombstone.
type RuntimeRetirer interface {
	RetireRuntime(context.Context, uuid.UUID) error
	CloseRetiredRuntime(context.Context, uuid.UUID) error
}

// PublicProbeIdentity cannot sign. The worker owns its separate private probe
// key; the API needs only its public key for admission and receipt validation.
type PublicProbeIdentity struct{ Key ssh.PublicKey }

func (p PublicProbeIdentity) PublicKey() ssh.PublicKey                       { return p.Key }
func (p PublicProbeIdentity) Sign(io.Reader, []byte) (*ssh.Signature, error) { return nil, ErrDisabled }

// APIOrchestrator runs the existing durable lifecycle operations in the API,
// with its existing sealer and exact node policy provider. Construction enables
// no organization/template, mount, socket ACL, policy or live runtime.
type APIOrchestrator struct {
	store               *Store
	binding             BoundedRuntimeBinding
	worker              WorkerRuntime
	initial             *InitialLaunchCoordinator
	cleanup             *PrivateNetworkCleanup
	wake                chan struct{}
	retired             bool
	initialCreate       *CreateInput
	lastEnrollmentProbe time.Time
}

func NewAPIOrchestrator(store *Store, b BoundedRuntimeBinding, worker WorkerRuntime, policies canonicalPolicyReader, sealer handoffSealer) (*APIOrchestrator, error) {
	if store == nil || store.pool == nil || b.Validate() != nil || worker == nil || policies == nil || sealer == nil {
		return nil, ErrDisabled
	}
	if worker.ProbePublicKey() == nil {
		// Only the explicit typed enrollment client may start disconnected. A
		// generic/static worker must still supply its configured public identity.
		client, ok := worker.(*WorkerRPCClient)
		if !ok || client.enrollment == nil || !b.OrganizationScoped() {
			return nil, ErrDisabled
		}
	}
	if _, err := store.WithBoundedRuntime(b); err != nil {
		return nil, err
	}
	initial := &InitialLaunchCoordinator{Store: store, Provider: worker, Materializer: worker, Assets: worker, Files: worker, Network: worker, Probe: worker, ProbeIdentity: PublicProbeIdentity{worker.ProbePublicKey()}, Policies: policies, Sealer: sealer, GatewayID: b.GatewayID}
	cleanup := &PrivateNetworkCleanup{Store: store, Network: worker, Gateway: worker, Files: worker, Policies: policies}
	return &APIOrchestrator{store: store, binding: b, worker: worker, initial: initial, cleanup: cleanup, wake: make(chan struct{}, 1)}, nil
}
func (o *APIOrchestrator) Wake() {
	if o == nil {
		return
	}
	select {
	case o.wake <- struct{}{}:
	default:
	}
}
func (o *APIOrchestrator) Run(ctx context.Context, report func(uuid.UUID, error)) error {
	if o == nil || o.initial == nil || o.cleanup == nil {
		return ErrDisabled
	}
	if o.initialCreate != nil {
		var exists bool
		if err := o.store.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM sandboxes WHERE org_id=$1 AND creator_id=$2 AND idempotency_key=$3)`, o.binding.OrgID, o.binding.CreatorID, o.initialCreate.IdempotencyKey).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			if _, _, err := o.store.Create(ctx, o.binding.OrgID, o.binding.CreatorID, *o.initialCreate); err != nil {
				return err
			}
		}
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := o.batch(ctx, report); err != nil && report != nil {
			report(uuid.Nil, err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		case <-o.wake:
		}
	}
}
func (o *APIOrchestrator) batch(ctx context.Context, report func(uuid.UUID, error)) error {
	if sweeper, ok := o.worker.(interface{ SweepRunnerEnrollment(context.Context) error }); ok {
		if err := sweeper.SweepRunnerEnrollment(ctx); err != nil {
			return err
		}
	}
	o.refreshEnrollmentHealth(ctx)
	if o.binding.OrganizationScoped() {
		if err := o.store.SweepEligibility(ctx, o.binding.OrgID, 2); err != nil {
			return err
		}
	}
	if err := o.store.SweepDelegations(ctx, o.binding.OrgID, 2); err != nil {
		return err
	}

	// Select only the configured org/profiles; legacy mode also pins the creator.
	// Expiry closes launches; expired/stopped records still receive cleanup.
	rows, err := o.store.pool.Query(ctx, `SELECT id,generation,desired_state,observed_state,expires_at FROM sandboxes WHERE org_id=$1 AND ($6 OR creator_id=$2) AND template_id=ANY($3) AND (NOT $4 OR id<>$5) AND (NOT $4 OR `+retainedBoundedWorkload+`) ORDER BY id LIMIT 2`, o.binding.OrgID, o.binding.CreatorID, o.binding.templateIDs(), o.binding.Persistent(), devReservedSandbox, o.binding.OrganizationScoped())
	if err != nil {
		return err
	}
	type job struct {
		id             uuid.UUID
		generation     int64
		desired, state string
		expiry         time.Time
	}
	jobs := []job{}
	for rows.Next() {
		var j job
		if err = rows.Scan(&j.id, &j.generation, &j.desired, &j.state, &j.expiry); err != nil {
			rows.Close()
			return err
		}
		jobs = append(jobs, j)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, j := range jobs {
		if o.binding.Persistent() {
			a, e := o.authorizeJob(ctx, j.id)
			if e != nil {
				if report != nil {
					report(j.id, e)
				}
				continue
			}
			j.generation = a.Generation
			j.desired = a.Desired
			j.expiry = a.ExpiresAt
		}
		if j.state == "deleted" {
			if o.binding.Persistent() || !o.retired {
				if err := o.retire(ctx, j.id); err != nil && report != nil {
					report(j.id, err)
				}
			}
			continue
		}

		work, cancel := context.WithTimeout(ctx, 30*time.Second)
		if j.desired == "deleted" || j.desired == "stopped" || !time.Now().Before(j.expiry) {
			if !(j.desired == "stopped" && j.state == "stopped" && time.Now().Before(j.expiry)) {
				err = o.store.ReconcileCleanup(work, j.id, o.worker, o.cleanup)
			} else {
				err = nil
			}
		} else if len(jobs) == 1 && o.binding.available(time.Now()) && ((j.generation == 1 && (j.state == "creating" || j.state == "starting")) || (j.generation > 1 && (j.state == "stopped" || j.state == "starting"))) {
			err = nil
			// A retained workload prevents enrollment identity replacement. Use a
			// fresh authoritative immutable snapshot for this launch, rather than
			// the probe that happened to exist when the API process was started.
			if client, ok := o.worker.(*WorkerRPCClient); ok && client.enrollment != nil {
				var probe ssh.PublicKey
				probe, err = client.resolveProbe(work)
				if err == nil {
					o.initial.ProbeIdentity = PublicProbeIdentity{probe}
				}
			}
			// Missing/revoked enrollment cannot materialize assets or launch.
			if err == nil {
				if j.generation == 1 {
					err = o.initial.Reconcile(work, j.id)
				} else {
					err = (&ResumeCoordinator{Initial: o.initial}).Reconcile(work, j.id)
				}
			}
		} else {
			err = nil
		}
		cancel()
		if err != nil && report != nil {
			report(j.id, err)
		}
	}
	return nil
}

// Refresh connectivity even while the organization has no workloads, so the
// enrollment UI can observe a real worker reply. Offline/unqualified workers
// remain unavailable, and their failed health attempt never prevents cleanup.
func (o *APIOrchestrator) refreshEnrollmentHealth(ctx context.Context) {
	client, ok := o.worker.(*WorkerRPCClient)
	if !ok || client.enrollment == nil || time.Since(o.lastEnrollmentProbe) < 5*time.Second {
		return
	}
	o.lastEnrollmentProbe = time.Now()
	probeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	credential, err := client.enrollment.CurrentCredential(probeCtx)
	if err != nil || credential.CleanupOnly {
		return
	}
	_ = client.CheckBinding(probeCtx, o.binding)
}

func (o *APIOrchestrator) retire(ctx context.Context, id uuid.UUID) error {
	if o.binding.deniesRuntimeID(id) {
		return ErrForbidden
	}
	worker, ok := o.worker.(RuntimeRetirer)
	if !ok {
		return ErrDisabled
	}
	var marked bool
	if err := o.store.pool.QueryRow(ctx, `SELECT r.worker_retired_at IS NOT NULL FROM sandbox_runtime_bindings r JOIN sandboxes s ON s.id=r.sandbox_id AND s.org_id=r.org_id WHERE s.id=$1 AND s.org_id=$2 AND ($5 OR s.creator_id=$3) AND s.template_id=ANY($4) AND s.observed_state='deleted' AND s.desired_state='deleted'`, id, o.binding.OrgID, o.binding.CreatorID, o.binding.templateIDs(), o.binding.OrganizationScoped()).Scan(&marked); err != nil {
		return ErrConflict
	}
	if !marked {
		if err := worker.RetireRuntime(ctx, id); err != nil {
			return err
		}
		result, err := o.store.pool.Exec(ctx, `UPDATE sandbox_runtime_bindings r SET worker_retired_at=COALESCE(worker_retired_at,now()) FROM sandboxes s WHERE s.id=r.sandbox_id AND s.org_id=r.org_id AND s.id=$1 AND s.org_id=$2 AND ($5 OR s.creator_id=$3) AND s.template_id=ANY($4) AND s.observed_state='deleted' AND s.desired_state='deleted'`, id, o.binding.OrgID, o.binding.CreatorID, o.binding.templateIDs(), o.binding.OrganizationScoped())
		if err != nil {
			return err
		}
		if result.RowsAffected() != 1 {
			return ErrConflict
		}
	}
	if o.binding.Persistent() {
		return nil
	}
	if err := worker.CloseRetiredRuntime(ctx, id); err != nil {
		return err
	}
	o.retired = true
	return nil
}

// ConfigureInitialCreate is an explicit trusted operator intent for one approved
// native qualification. Store.Create still performs current human authorization,
// scope/key admission, immutable template checks, idempotency and quota locking.
func (o *APIOrchestrator) ConfigureInitialCreate(in *CreateInput) error {
	if in == nil {
		return nil
	}
	if o.binding.Persistent() || len(strings.TrimSpace(in.Name)) == 0 || len(in.Name) > 80 || in.TemplateID != o.binding.TemplateID || in.TTLSeconds != 3600 || len(in.Requested) != 0 || len(in.SSHPublicKeys) != 1 || len(in.SelectedSkills) != 0 {
		return ErrInvalid
	}
	keys, err := NormalizeSSHPublicKeys(in.SSHPublicKeys, 1)
	if err != nil {
		return err
	}
	copy := *in
	copy.SSHPublicKeys = keys
	copy.IdempotencyKey = "native-mac-only-approved-20261003"
	o.initialCreate = &copy
	return nil
}

// Refresh authority from durable state, including expiry-driven generation
// changes, before any RPC effect. It carries no credential or policy snapshot.
func (o *APIOrchestrator) authorizeJob(ctx context.Context, id uuid.UUID) (RuntimeAuthorization, error) {
	if o.binding.deniesRuntimeID(id) {
		return RuntimeAuthorization{}, ErrForbidden
	}
	w, ok := o.worker.(RuntimeAuthorizer)
	if !ok {
		return RuntimeAuthorization{}, ErrDisabled
	}
	conn, release, err := o.store.acquireLifecycle(ctx, id)
	if err != nil {
		return RuntimeAuthorization{}, err
	}
	defer func() {
		if release != nil {
			release()
		}
	}()
	sb, err := scanSandbox(conn.QueryRow(ctx, `SELECT `+sandboxColumns+` FROM sandboxes WHERE id=$1 AND org_id=$2 AND ($4 OR creator_id=$3) AND template_id=ANY($5)`, id, o.binding.OrgID, o.binding.CreatorID, o.binding.OrganizationScoped(), o.binding.templateIDs()))
	if err != nil {
		return RuntimeAuthorization{}, err
	}
	var device, gateway uuid.UUID
	if r := o.binding.RemoteTerminal; r != nil {
		err = conn.QueryRow(ctx, `SELECT s.terminal_device_id,r.runtime_gateway_id FROM sandboxes s JOIN sandbox_remote_terminal_routes r ON r.sandbox_id=s.id AND r.org_id=s.org_id AND r.terminal_device_id=s.terminal_device_id WHERE s.id=$1 AND s.org_id=$2 AND s.local_terminal_gateway_id IS NULL AND r.terminal_gateway_id=$3 AND r.runtime_gateway_id=$4 AND r.terminal_gateway_endpoint=$5 AND r.runtime_gateway_endpoint=$6`, id, o.binding.OrgID, r.GatewayID, o.binding.GatewayID, r.GatewayEndpoint, r.RuntimeGatewayEndpoint).Scan(&device, &gateway)
	} else {
		err = conn.QueryRow(ctx, `SELECT terminal_device_id,local_terminal_gateway_id FROM sandboxes WHERE id=$1 AND org_id=$2`, id, o.binding.OrgID).Scan(&device, &gateway)
	}
	if err != nil {
		return RuntimeAuthorization{}, ErrForbidden
	}
	p, ok := o.binding.profile(sb.TemplateVersionID)
	if !ok || device == uuid.Nil || (!o.binding.OrganizationScoped() && device != o.binding.TerminalDeviceID) || gateway != o.binding.GatewayID {
		return RuntimeAuthorization{}, ErrForbidden
	}
	a := RuntimeAuthorization{SandboxID: id, OrgID: sb.Identity.OrgID, CreatorID: sb.Identity.CreatorID, GatewayID: gateway, TerminalDeviceID: device, TemplateID: sb.TemplateVersionID, Profile: p, Generation: sb.Revision, Desired: sb.DesiredState, CreatedAt: sb.CreatedAt, ExpiresAt: sb.ExpiresAt}
	if !a.valid(o.binding) {
		return RuntimeAuthorization{}, ErrForbidden
	}
	if sb.DesiredState == "started" && time.Now().Before(sb.ExpiresAt) && o.binding.OrganizationScoped() {
		eligible, eligibilityErr := sandboxEligible(ctx, conn, id)
		if eligibilityErr != nil {
			return RuntimeAuthorization{}, eligibilityErr
		}
		if !eligible {
			// Withdrawal owns a short transaction. Release this connection first so
			// a one-connection pool can make progress; no stale worker grant issues.
			release()
			release = nil
			if _, err := o.store.WithdrawIneligible(ctx, id); err != nil {
				return RuntimeAuthorization{}, err
			}
			return RuntimeAuthorization{}, ErrConflict
		}
	}
	if sb.DesiredState != "started" || !time.Now().Before(sb.ExpiresAt) {
		sb, err = beginCleanup(ctx, conn, id)
		if err != nil {
			return RuntimeAuthorization{}, err
		}
		a.Generation, a.Desired = sb.Revision, sb.DesiredState
	} else if err = o.store.reservationAdmission(ctx, conn, sb.Identity.OrgID); err != nil {
		return RuntimeAuthorization{}, err
	}
	if !a.valid(o.binding) {
		return RuntimeAuthorization{}, ErrForbidden
	}
	return a, w.AuthorizeRuntime(ctx, a)
}
