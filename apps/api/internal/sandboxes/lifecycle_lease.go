package sandboxes

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Every start, recovery and cleanup reconciler must share this session lease.
// External work holds no database transaction; unlock failure discards the
// session rather than returning a locked connection to the pool.
func (s *Store) acquireLifecycle(ctx context.Context, id uuid.UUID) (*pgxpool.Conn, func(), error) {
	if id == uuid.Nil {
		return nil, nil, ErrInvalid
	}
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return nil, nil, err
	}
	hash := sha256.Sum256(append([]byte("sandbox-lifecycle:"), id[:]...))
	key := int64(binary.BigEndian.Uint64(hash[:8]))
	var locked bool
	if err = conn.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, key).Scan(&locked); err != nil || !locked {
		conn.Release()
		if err == nil {
			err = ErrConflict
		}
		return nil, nil, err
	}
	release := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		var unlocked bool
		if err := conn.QueryRow(ctx, `SELECT pg_advisory_unlock($1)`, key).Scan(&unlocked); err != nil || !unlocked {
			_ = conn.Conn().Close(ctx)
		}
		conn.Release()
	}
	return conn, release, nil
}
