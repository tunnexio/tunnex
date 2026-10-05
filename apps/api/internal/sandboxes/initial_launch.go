package sandboxes

import (
	"context"
	"errors"
	"os"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/sandboxruntime"
	"golang.org/x/crypto/ssh"
)

// InitialLaunchCoordinator composes the existing fenced steps for an initial
// launch. It is deliberately not an availability flag or a resume coordinator.
// A ready connection requires every independent policy/network/SSH gate.
type LaunchStageError struct {
	Stage string
	Cause error
}

func (e *LaunchStageError) Error() string { return "sandbox launch pending: " + e.Stage }
func (e *LaunchStageError) Unwrap() error { return e.Cause }

type InitialLaunchCoordinator struct {
	Store         *Store
	Provider      sandboxruntime.Provider
	AssetsRoot    *os.Root
	Materializer  CreationAssetMaterializer
	Assets        sandboxruntime.AssetResolver
	Files         LaunchControlTransport
	Network       PrivateNetworkControl
	Probe         TargetSSHProber
	ProbeIdentity ssh.Signer
	Policies      canonicalPolicyReader
	Sealer        handoffSealer
	GatewayID     uuid.UUID
}

func (c *InitialLaunchCoordinator) Reconcile(ctx context.Context, id uuid.UUID) (failure error) {
	stage := "configuration"
	defer func() {
		var staged *LaunchStageError
		if failure != nil && stage != "configuration" && !errors.As(failure, &staged) {
			failure = &LaunchStageError{stage, failure}
		}
	}()
	if c == nil || c.Store == nil || c.Provider == nil || (c.AssetsRoot == nil && c.Materializer == nil) || c.Assets == nil || c.Files == nil || c.Network == nil || c.Probe == nil || c.ProbeIdentity == nil || c.Policies == nil || c.Sealer == nil || c.GatewayID == uuid.Nil {
		return ErrDisabled
	}
	// Materialized SSH/skills are immutable before container creation; no package
	// installation or enrollment credential reaches the workload.
	stage = "assets"
	if _, err := c.Assets.ResolveAssets(ctx, id); err != nil {
		if c.Materializer != nil {
			_, _, err = c.Store.PrepareCreationAssetsWithTransport(ctx, id, string(ssh.MarshalAuthorizedKey(c.ProbeIdentity.PublicKey())), c.Materializer)
			if err != nil {
				return err
			}
		} else {
			owned, err := privateControlChild(c.AssetsRoot, id.String())
			if err != nil {
				return err
			}
			defer owned.Close()
			if _, _, err := c.Store.PrepareCreationAssets(ctx, id, owned, string(ssh.MarshalAuthorizedKey(c.ProbeIdentity.PublicKey()))); err != nil {
				return err
			}
		}
	}
	stage = "provider-create"
	if err := c.Store.ReconcileQuarantinedStart(ctx, id, c.Provider); err != nil {
		return err
	}
	stage = "launch-prepare"
	handoff, err := c.Store.PrepareLaunch(ctx, id, c.GatewayID, c.Sealer)
	if errors.Is(err, ErrConflict) {
		// Recovery never generates another token. The enrollment method below checks
		// consumed state and refuses unconfirmed recovery without a usable token.
		handoff, err = c.Store.ExistingLaunchOperation(ctx, id)
	}
	if err != nil {
		return err
	}
	if handoff.GatewayID != c.GatewayID {
		return ErrConflict
	}
	stage = "enrollment"
	if err = c.Store.EnrollPreparedLaunch(ctx, handoff, c.Files); err != nil {
		return err
	}
	stage = "provider-start"
	if err = c.Store.StartBoundRuntime(ctx, id, c.Provider); err != nil {
		return err
	}
	stage = "network-activate"
	if err = c.Store.ActivatePrivateNetwork(ctx, id, c.Network, c.Files); err != nil {
		return err
	}
	stage = "readiness"
	return c.Store.VerifyPrivateReadinessWithTransport(ctx, id, c.Provider, c.Policies, c.Network, c.Assets, c.ProbeIdentity, c.Probe)
}
