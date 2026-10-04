package proxy

import (
	"context"
	"github.com/tunnexio/tunnex/packages/apptransport/authoritywire"
	"time"
)

type terminationAuthority interface {
	Terminated(context.Context, authoritywire.AppProxyStreamTerminatedInput) error
}

// Called only after the local HTTP/upgrade forwarding has ended. Delivery is
// best effort; independent lease expiry never depends on this notification.
func (h *Handler) notifyTerminated(binding Binding, id string, expired bool) {
	authority, ok := h.Authority.(terminationAuthority)
	if !ok {
		return
	}
	select {
	case h.terminationCallbacks <- struct{}{}:
	default:
		h.metrics.terminationDropped.Add(1)
		return
	}
	reason := authoritywire.AppProxyConnectionClosed
	if expired {
		reason = authoritywire.AppProxyLeaseExpired
	}
	go func() {
		defer func() { <-h.terminationCallbacks }()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		err := authority.Terminated(ctx, authoritywire.AppProxyStreamTerminatedInput{Binding: authoritywire.AppProxyRouteBinding(binding), StreamID: id, Reason: reason})
		if err != nil || ctx.Err() != nil {
			h.metrics.terminationFailed.Add(1)
		} else {
			h.metrics.terminationAccepted.Add(1)
		}
	}()
}
