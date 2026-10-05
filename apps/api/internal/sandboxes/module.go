package sandboxes

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrModuleRetirementPending = errors.New("sandbox module retirement pending; retain cleanup runtime configuration")

// CheckModuleRetired never modifies resources or saved public keys. Historical
// records are retained; confirmed runtime retirement is required before off.
func CheckModuleRetired(ctx context.Context, pool *pgxpool.Pool) error {
	var pending bool
	err := pool.QueryRow(ctx, `SELECT
 EXISTS(SELECT 1 FROM organizations WHERE sandboxes_enabled)
 OR EXISTS(SELECT 1 FROM sandboxes WHERE desired_state<>'deleted' OR observed_state<>'deleted')
 OR EXISTS(SELECT 1 FROM sandbox_runtime_bindings WHERE worker_retired_at IS NULL)
 OR EXISTS(SELECT 1 FROM devices WHERE kind='sandbox' AND status='active' AND deleted_at IS NULL)
 OR EXISTS(SELECT 1 FROM sandbox_runtime_credentials WHERE revoked_at IS NULL)`).Scan(&pending)
	if err != nil {
		return err
	}
	if pending {
		return ErrModuleRetirementPending
	}
	return nil
}
