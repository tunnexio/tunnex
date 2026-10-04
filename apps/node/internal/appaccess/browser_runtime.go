package appaccess

import (
	"context"
	"github.com/tunnexio/tunnex/apps/node/internal/control"
	"github.com/tunnexio/tunnex/packages/apptransport"
	"github.com/tunnexio/tunnex/packages/apptransport/originpolicy"
	"log/slog"
	"time"
)

func ObserveBrowser(ctx context.Context, client *control.AppAccessClient, pool *BrowserPool, logger *slog.Logger) {
	defer pool.Close()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		// Refresh independently on every poll: capability is certificate-specific and
		// expires. Rotation never inherits a previous credential's browser report.
		err := client.BrowserCapability(ctx)
		var assignments []BrowserAssignment
		if err == nil {
			desired, e := client.BrowserDesired(ctx)
			err = e
			if e == nil && !desired.Withdrawn {
				for _, wire := range desired.Assignments {
					policy, e := originpolicy.Normalize(wire.AllowedDestinationCIDRs, wire.OriginCAPEM)
					if e != nil || policy.OriginCADigest != wire.OriginCADigest || (wire.Stage != "active" && wire.Stage != "pending") {
						err = apptransport.ErrUnavailable
						break
					}
					b := wire.Binding
					assignment := BrowserAssignment{Binding: apptransport.Binding{OrgID: b.OrgID, GatewayID: b.GatewayID, AppID: b.AppID, Generation: b.Generation, Digest: b.Digest, Revision: b.Revision, Purpose: string(b.Purpose), Hostname: b.Hostname, AuthorityVersion: b.AuthorityVersion}, OriginURL: wire.OriginURL, Policy: policy, Stage: string(wire.Stage)}
					if wire.Stage == "pending" {
						if wire.OperationID == nil || wire.ReadinessRequestID == nil || wire.Deadline == nil {
							err = apptransport.ErrUnavailable
							break
						}
						assignment.OperationID = *wire.OperationID
						assignment.ReadinessRequestID = *wire.ReadinessRequestID
						assignment.Deadline = *wire.Deadline
					}
					if wire.Stage == "active" && (wire.OperationID != nil || wire.ReadinessRequestID != nil || wire.Deadline != nil) {
						err = apptransport.ErrUnavailable
						break
					}
					assignments = append(assignments, assignment)
				}
			}
		}
		if err != nil {
			assignments = nil
			if ctx.Err() == nil {
				logger.Debug("app_browser_desired_refused")
			}
		}
		pool.Sync(ctx, assignments)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
