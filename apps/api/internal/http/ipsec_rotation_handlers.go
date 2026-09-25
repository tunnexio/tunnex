package http

import (
	"context"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/crypto"
	"github.com/tunnexio/tunnex/apps/api/internal/ipsec"
)

type ipsecRotationRepository interface {
	RotatePSKs(context.Context, uuid.UUID, uuid.UUID, uuid.UUID, int64, []ipsec.RotatePSK, *crypto.Sealer) (ipsec.Connection, error)
}

func (s apiServer) RotateIPsecPSKs(ctx context.Context, req api.RotateIPsecPSKsRequestObject) (api.RotateIPsecPSKsResponseObject, error) {
	ctx, err := authorizeIPsecConfigurationCheck(ctx, req.OrgId)
	if err != nil {
		return nil, err
	}
	if req.Body == nil || req.Body.ExpectedDesiredRevision <= 0 || len(req.Body.Tunnels) < 1 || len(req.Body.Tunnels) > 2 {
		return nil, ipsecProviderError(ipsec.ErrConnectionInvalid)
	}
	replacements := make([]ipsec.RotatePSK, len(req.Body.Tunnels))
	seen := map[uuid.UUID]bool{}
	for i, t := range req.Body.Tunnels {
		if t.TunnelId == uuid.Nil || seen[t.TunnelId] || t.Psk == nil || len(*t.Psk) == 0 || len(*t.Psk) > 4096 {
			return nil, ipsecProviderError(ipsec.ErrConnectionInvalid)
		}
		seen[t.TunnelId] = true
		replacements[i] = ipsec.RotatePSK{TunnelID: t.TunnelId, PSK: *t.Psk}
	}
	// Drop references promptly; Go cannot guarantee erasure of JSON string copies.
	defer func() {
		for i := range replacements {
			replacements[i].PSK = ""
		}
		for i := range req.Body.Tunnels {
			req.Body.Tunnels[i].Psk = nil
		}
	}()
	store, ok := s.ipsecProviders.(ipsecRotationRepository)
	if !ok || s.ipsecSealer == nil {
		return nil, ipsecProviderError(ipsec.ErrConnectionUnavailable)
	}
	principal, _ := authctx.PrincipalFrom(ctx)
	record, err := store.RotatePSKs(ctx, req.OrgId, principal.UserID, req.ConnectionId, req.Body.ExpectedDesiredRevision, replacements, s.ipsecSealer)
	if err != nil {
		return nil, ipsecProviderError(err)
	}
	return api.RotateIPsecPSKs200JSONResponse{Body: publicIPsecConnection(record), Headers: api.RotateIPsecPSKs200ResponseHeaders{CacheControl: "no-store", ETag: connectionETag(record.DesiredRevision), XRequestId: reqID(ctx)}}, nil
}
