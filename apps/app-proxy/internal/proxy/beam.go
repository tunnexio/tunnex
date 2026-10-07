package proxy

import (
	"context"
	"github.com/tunnexio/tunnex/packages/apptransport"
	"github.com/tunnexio/tunnex/packages/apptransport/authoritywire"
	"github.com/tunnexio/tunnex/packages/apptransport/beam"
	"net/http"
	"time"
)

func NewBeamGateway(authority Authority) (*apptransport.Broker, http.Handler, error) {
	if authority == nil {
		return nil, nil, ErrDenied
	}
	return beam.NewRegistryGateway(func(ctx context.Context, b apptransport.Binding, serial string) (time.Time, error) {
		binding := Binding{OrgID: b.OrgID, AppID: b.AppID, GatewayID: b.GatewayID, Generation: b.Generation, Digest: b.Digest, Purpose: authoritywire.AppProxyRouteBindingPurpose(beam.Purpose), Revision: b.Revision, AuthorityVersion: b.AuthorityVersion, Hostname: b.Hostname}
		return authority.Channel(ctx, binding, serial)
	})
}
