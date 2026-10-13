package fqdnresolver

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5/pgconn"
)

// Retry only a PostgreSQL-confirmed serialization abort, never an unknown commit.
// Each unit must finish rollback before returning. Three total attempts, no sleep,
// new request ID, renewed deadline, DNS observation or TTL recomputation.
func retryFQDNSerialization(ctx context.Context, beforeRetry func() error, unit func() error) error {
	for attempt := 0; attempt < 3; attempt++ {
		err := unit()
		if err == nil {
			return nil
		}
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "40001" || attempt == 2 {
			return err
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if beforeRetry != nil {
			if gateErr := beforeRetry(); gateErr != nil {
				return gateErr
			}
		}
	}
	panic("unreachable serialization attempts")
}
