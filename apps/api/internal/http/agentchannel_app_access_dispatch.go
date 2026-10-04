package http

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/appaccess"
	"github.com/tunnexio/tunnex/packages/apptransport"
	"github.com/tunnexio/tunnex/packages/apptransport/originpolicy"
)

type appAccessDispatchState struct {
	mu       sync.Mutex
	active   map[uuid.UUID]context.CancelFunc
	gateways map[uuid.UUID]int
	closed   bool
}

func (a *AgentChannel) dispatchAppAccessChecks(node sqlc.Node, checks []appaccess.Check) {
	state := a.appAccessDispatch
	if state == nil || a.appAccessBroker == nil {
		return
	}
	for _, check := range checks {
		if check.Status != "running" || check.Purpose != "origin_check" || !check.Deadline.After(time.Now()) || check.OrgID != node.OrgID || check.GatewayID != node.ID {
			continue
		}
		state.mu.Lock()
		_, exists := state.active[check.ID]
		if state.closed || exists || len(state.active) >= 128 || state.gateways[node.ID] >= 8 {
			state.mu.Unlock()
			continue
		}
		ctx, cancel := context.WithDeadline(context.Background(), check.Deadline)
		state.active[check.ID] = cancel
		state.gateways[node.ID]++
		state.mu.Unlock()
		go func(check appaccess.Check) {
			defer func() {
				cancel()
				state.mu.Lock()
				delete(state.active, check.ID)
				state.gateways[node.ID]--
				if state.gateways[node.ID] == 0 {
					delete(state.gateways, node.ID)
				}
				state.mu.Unlock()
			}()
			binding := apptransport.Binding{OrgID: node.OrgID.String(), GatewayID: node.ID.String(), AppID: check.AppID.String(), Generation: check.Generation.String(), Revision: check.Revision, Digest: check.Digest, Purpose: check.Purpose}
			diagnostic, serial, err := a.appAccessBroker.Probe(ctx, binding, check.ID.String())
			// No authenticated channel means there is no connector evidence to invent.
			// The durable original deadline expires this check, and later polls recover
			// any still-pending work after a control-plane restart.
			if serial == "" || ctx.Err() != nil {
				return
			}
			result := appAccessProbeResult(check, diagnostic)
			if err != nil {
				result.DNSStatus = "pending"
				result.ConnectStatus = "pending"
				result.TLSStatus = "pending"
				result.ErrorCode = "connector_failed"
			}
			_, _ = a.appAccess.CompleteCheck(ctx, appaccess.AuthenticatedGateway{OrgID: node.OrgID, GatewayID: node.ID, CertSerial: serial}, result, a.appAccessHasEntitlement())
		}(check)
	}
}
func appAccessProbeResult(check appaccess.Check, diagnostic originpolicy.Result) appaccess.Result {
	stage := func(value string) string {
		switch value {
		case "ready":
			return "passed"
		case "failed", "refused":
			return "failed"
		default:
			return "pending"
		}
	}
	out := appaccess.Result{RequestID: check.ID, Generation: check.Generation, AppID: check.AppID, Revision: check.Revision, Digest: check.Digest, Purpose: check.Purpose, DNSStatus: stage(diagnostic.DNS), ConnectStatus: stage(diagnostic.Connect), TLSStatus: stage(diagnostic.TLS)}
	if diagnostic.TLS == "not_required" {
		out.TLSStatus = "skipped"
	}
	switch diagnostic.Status {
	case "ready":
		out.ErrorCode = ""
	case "dns_refused":
		out.ErrorCode = "dns_failed"
		if diagnostic.DNS == "refused" {
			out.ErrorCode = "target_refused"
		}
	case "origin_refused":
		out.ErrorCode = "target_refused"
	case "tls_refused":
		out.ErrorCode = "tls_failed"
	case "http_failed":
		out.ErrorCode = "http_failed"
	case "unreachable":
		out.ErrorCode = "connect_failed"
	case "timeout":
		out.ErrorCode = "deadline_exceeded"
	case "cancelled":
		out.ErrorCode = "assignment_changed"
	default:
		out.ErrorCode = "connector_failed"
	}
	return out
}
