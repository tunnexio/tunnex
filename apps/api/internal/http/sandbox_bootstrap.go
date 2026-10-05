package http

import (
	"context"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/devices"
	"github.com/tunnexio/tunnex/apps/api/internal/sandboxes"
)

func (s apiServer) BootstrapSandbox(ctx context.Context, req api.BootstrapSandboxRequestObject) (api.BootstrapSandboxResponseObject, error) {
	if s.sandboxProvisioningReady == nil || !s.sandboxProvisioningReady() || s.devices == nil {
		return nil, sandboxUnavailable()
	}
	runtime, ok := s.sandboxes.(interface {
		AuthenticateRuntime(context.Context, string) (sandboxes.RuntimeIdentity, error)
	})
	if !ok {
		return nil, sandboxUnavailable()
	}
	if req.Body == nil || len(req.Body.BootstrapToken) != 65 || len(req.Body.PublicKey) != 44 {
		return nil, apierr.BadRequest("invalid_sandbox_bootstrap", "invalid sandbox bootstrap request")
	}
	result, err := s.devices.Create(ctx, devices.CreateInput{SandboxBootstrapToken: req.Body.BootstrapToken, PublicKey: req.Body.PublicKey})
	if err != nil {
		return nil, err
	}
	identity, err := runtime.AuthenticateRuntime(ctx, result.RuntimeCredential)
	if err != nil || identity.SandboxID == uuid.Nil || identity.PeerID != result.Device.ID {
		// A withdrawal racing redemption must not return a usable handoff. Durable
		// peer binding remains for operation recovery; never retry minting blindly.
		return nil, apierr.New(401, "invalid_sandbox_bootstrap", "sandbox bootstrap unavailable")
	}
	return api.BootstrapSandbox200JSONResponse{Body: api.SandboxBootstrapResponse{SandboxId: identity.SandboxID, PeerId: identity.PeerID, Generation: identity.Generation, Config: result.Config, RuntimeCredential: result.RuntimeCredential}, Headers: api.BootstrapSandbox200ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}
