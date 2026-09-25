package ipsec

import (
	"context"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/crypto"
)

// Test-only seam fails the second seal without replacing process-global entropy.
func RotatePSKsSecondSealFailureForTest(s *ConnectionStore, ctx context.Context, org, actor, id uuid.UUID, revision int64, replacements []RotatePSK, sealer *crypto.Sealer) (Connection, error) {
	calls := 0
	return s.rotatePSKs(ctx, org, actor, id, revision, replacements, sealer, func(s *crypto.Sealer, b PSKBinding, value string) (string, error) {
		calls++
		if calls == 2 {
			return "", ErrPSKEnvelope
		}
		return SealPSK(s, b, value)
	})
}
