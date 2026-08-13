package http

import (
	"context"
	"log/slog"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/internal/crypto"
	"github.com/tunnexio/tunnex/apps/api/internal/devices"
	"github.com/tunnexio/tunnex/apps/api/internal/idpsync"
	"github.com/tunnexio/tunnex/apps/api/internal/licence"
	"github.com/tunnexio/tunnex/apps/api/internal/tenancy"
)

// syncDeprovisioner adapts tenancy's full deactivate sweep to the reconciler's Deprovisioner seam,
// stamping the CAUSE. It lives here (not in idpsync) so the enterprise idpsync package stays free of
// a tenancy import — the Deprovisioner interface is the whole decoupling point (S7.5.2 slice 3).
type syncDeprovisioner struct{ members *tenancy.MembershipService }

func (d syncDeprovisioner) DeactivateForSync(ctx context.Context, orgID, userID uuid.UUID, _ string) (bool, error) {
	return d.members.DeactivateMemberBySync(ctx, orgID, userID, "disabled_in_directory")
}

func (d syncDeprovisioner) RevokeOrgAccess(ctx context.Context, orgID, userID uuid.UUID, cause string) (bool, error) {
	return d.members.RevokeOrgAccessBySync(ctx, orgID, userID, cause)
}

// NewIdpSyncPort builds the enterprise IdP-sync service: sqlc + AES-GCM sealer + the device pusher
// (the same org-wide recompile the tenancy sweep uses) + the deactivate sweep behind Deprovisioner.
func NewIdpSyncPort(pool *pgxpool.Pool, sealer *crypto.Sealer, members *tenancy.MembershipService, pusher *devices.Service, lic *licence.Manager, logger *slog.Logger) idpSyncPort {
	// ⛔ THE LICENCE REACHES THE RECONCILER THROUGH HERE, AND NOWHERE ELSE. It narrows provisioning only;
	// the deprovision sweep above is untouched by any licence state, by construction.
	svc := idpsync.NewService(pool, sealer, pusher, syncDeprovisioner{members: members}, logger).WithLicence(lic)
	// Box-walk / e2e harness: a file-backed FAKE directory replaces live Graph so directory state
	// can be mutated between sync legs by editing JSON. Gated behind an env var + a loud warning;
	// never active in a normal deploy. (S7.5.2 slice 5.)
	if path := os.Getenv("TUNNEX_IDPSYNC_FAKE_DIR"); path != "" {
		svc.SetProviderFactory(idpsync.FileProviderFactory(path))
		logger.Warn("idp_sync_FAKE_DIRECTORY_ACTIVE",
			slog.String("path", path),
			slog.String("warning", "file-backed fake directory is serving group membership — NOT FOR PRODUCTION"))
	}
	return svc
}

// StartIdpSyncPoller runs the background directory poll every 10 minutes (D2), jittered so many
// orgs don't stampede Graph on the same tick. First run is one interval out (boot isn't a sync
// trigger). Stops when ctx is cancelled.
// mayTick gates this poller on scheduler leadership (S13.1 review #10). It writes directory-group membership, so N
// replicas polling means N concurrent reconciles of the same groups. nil = ungated (open build / tests).
func StartIdpSyncPoller(ctx context.Context, port idpSyncPort, logger *slog.Logger, mayTick func() bool) {
	if port == nil {
		return
	}
	const base = 10 * time.Minute
	go func() {
		// A fixed per-process phase offset (0..119s) spreads load without per-tick randomness.
		jitter := time.Duration(uuid.New().ID()%120) * time.Second
		t := time.NewTimer(base + jitter)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if mayTick != nil && !mayTick() {
					t.Reset(base + jitter)
					continue // followers serve requests but never tick
				}
				port.PollAll(ctx)
				t.Reset(base + jitter)
			}
		}
	}()
	logger.Info("idp_sync_poller_started", slog.Duration("interval", base))
}
