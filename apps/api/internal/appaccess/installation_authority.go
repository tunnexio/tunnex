package appaccess

import (
	"context"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
)

// Every decision reads durable installation authority. Redis records from an
// earlier installation generation are never upgraded to the current one.
func (s *Service) installationGeneration(ctx context.Context) (uuid.UUID, error) {
	authority, err := sqlc.New(s.pool).GetAppAccessInstallationAuthority(ctx)
	if err != nil {
		return uuid.Nil, appInfrastructureUnavailable()
	}
	if authority.Generation == uuid.Nil || !authority.RecoveryCompletedAt.Valid {
		return uuid.Nil, appAuthorityUnavailable()
	}
	return authority.Generation, nil
}

func (s *Service) validateInstallation(ctx context.Context, generation uuid.UUID) error {
	current, err := s.installationGeneration(ctx)
	if err != nil {
		return err
	}
	if generation == uuid.Nil || current != generation {
		return appAuthorityUnavailable()
	}
	return nil
}
