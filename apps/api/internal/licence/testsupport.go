package licence

import "time"

// NewTestManager builds a Manager holding claims directly, bypassing signature verification.
//
// ⚠ EXPORTED ON PURPOSE, AND THE REASON IS THE POINT. The grace gates live in `nodes` and `devices`, not
// here, and a gate nothing outside this package can construct an expired licence for is a gate that gets
// unit-tested only where it was written — never where it fires. The alternative was to prove those gates
// by reading the source for a call, which is the shape-not-capability trap (docs/laws.md).
//
// ⛔ It mints no signature and verifies none, so it can never widen production: an unsigned Manager is
// only reachable by a caller that already had the claims. Install remains the only path from a wire key.
func NewTestManager(tier string, expires time.Time) *Manager {
	m := &Manager{}
	m.claims = &Claims{Version: 1, Tier: tier, Band: tier, ExpiresAt: expires.Unix()}
	return m
}
