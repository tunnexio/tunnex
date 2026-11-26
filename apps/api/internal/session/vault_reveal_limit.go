package session

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// Vault reveal budget (VAULT-UX-1 V4). Every reveal or copy, personal or shared, is charged to the person in
// that organization. 30 per minute is far above human use and far below a scripted bulk export.
const (
	VaultRevealLimit  = 30
	VaultRevealWindow = time.Minute
)

// VaultRevealAllowed charges one reveal and reports whether it is within the budget. The window starts at the
// first reveal (fixed window).
func (s *Store) VaultRevealAllowed(ctx context.Context, org, user uuid.UUID) (bool, error) {
	if org == uuid.Nil || user == uuid.Nil {
		return false, ErrNotFound
	}
	n, err := s.rdb.Eval(ctx, `local v = redis.call('INCR', KEYS[1])
if v == 1 then redis.call('PEXPIRE', KEYS[1], ARGV[1]) end
return v`, []string{"vault:reveal:" + org.String() + ":" + user.String()}, VaultRevealWindow.Milliseconds()).Int()
	if err != nil {
		return false, err
	}
	return n <= VaultRevealLimit, nil
}
