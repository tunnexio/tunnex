package beam

import (
	"context"
	"github.com/tunnexio/tunnex/apps/api/internal/beamreadiness"
	"time"
)

// ReadinessConfig contains installation inputs, never user supplied probe targets.
// ConnectorCA is used internally for server verification and is never serialized.
func (s *Service) ReadinessConfig() beamreadiness.Config {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	r, e := s.installation(ctx, s.pool)
	if e != nil {
		return beamreadiness.Config{}
	}
	return s.probeConfig(r)
}
