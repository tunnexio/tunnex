package licence

import (
	"context"
	"crypto/ed25519"
	"log/slog"
	"time"
)

// SettingKey is where the wire key lives in system_settings.
const SettingKey = "license_key"

// Store is the licence's durable home. ⚠ Deliberately tiny and free of sqlc, so `licence` stays importable
// from anywhere and the package's no-network guarantee is unchanged — a database read is not a network
// call to a licensing service, which is the property S12.2 promised.
type Store interface {
	// Get returns the stored wire key, or "" when none is installed.
	// ⛔ "" AND AN ERROR ARE DIFFERENT ANSWERS AND MUST NEVER BE CONFLATED: "" means the customer has no
	// licence, err means we could not find out. One is a product state, the other is an outage.
	Get(ctx context.Context) (string, error)
	Put(ctx context.Context, wire string) error
}

// MinRefreshInterval is the floor under the read-through TTL.
//
// ⛔ A TTL OF ZERO ON THIS PATH IS A DATABASE QUERY PER REQUEST. `Evaluate` is called by every org-scoped
// handler, every enrolment, and `/meta`. A misconfigured `0` — or an unset field, which is the same value —
// would turn the entitlement read into the busiest query in the deployment, and it would look like a
// database problem rather than a configuration one.
//
// ⚠ THE GUARD IS TAKEN AT THE SEAM, NOT AT THE CALLER, because the zero value is what an unconfigured
// struct literal produces. `&Manager{}` must be safe, and it is only safe if the floor is here.
const MinRefreshInterval = 5 * time.Second

// DefaultRefreshInterval is the staleness a replica may carry.
//
// ⚠ THIS IS THE MULTI-REPLICA WINDOW, AND NAMING IT IS THE POINT. N replicas each hold their own verdict;
// this is how long one may disagree with another after a licence is installed. The alternative — reading
// per request — was rejected as a hot-path query. Bounded disagreement, measured in seconds, is the trade.
const DefaultRefreshInterval = 30 * time.Second

// WithStore wires durable storage and the refresh interval. A ttl <= 0 takes MinRefreshInterval.
func (m *Manager) WithStore(s Store, ttl time.Duration, logger *slog.Logger) *Manager {
	if ttl < MinRefreshInterval {
		ttl = MinRefreshInterval
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.store, m.ttl, m.logger = s, ttl, logger
	return m
}

// Persist verifies a key, stores it, and adopts it — the write half of the read-through.
//
// ⛔ THE STORE WRITE COMES FIRST, AND THE IN-MEMORY ADOPTION SECOND. If the write fails the deployment must
// NOT start behaving as licensed: it would work until the next restart and then silently stop, which is the
// exact defect this file exists to remove, reproduced with a smaller fuse.
//
// ⭐ AND IT RETURNS THE TIER IT REPLACED, WHICH IS A DESIGN DECISION ABOUT AN AUDIT ROW.
//
// The caller writes a before/after audit entry, and that entry is only true if the "before" was read while
// it was still true. A handler that persists first and then reads both sides records `from: growth,
// to: growth` — present, well-formed, and saying nothing. That is a defect no test at the call site
// catches, because the row still exists and still parses.
//
// ⚠ SO THE ORDER IS NOT LEFT TO THE CALLER TO GET RIGHT. The only place that can observe the previous
// tier is inside the write, so the previous tier is returned BY the write. A future reorder cannot
// reintroduce the bug, because there is no longer an ordering to reorder.
func (m *Manager) Persist(ctx context.Context, keys map[string]ed25519.PublicKey, wire string) (res Result, previous Tier, err error) {
	res, err = Verify(keys, wire)
	if err != nil || !res.OK {
		return res, m.Evaluate(time.Now()).Tier, err
	}
	if m.store != nil {
		if e := m.store.Put(ctx, wire); e != nil {
			return Result{}, m.Evaluate(time.Now()).Tier, e
		}
	}
	previous = m.Evaluate(time.Now()).Tier // ⛔ read INSIDE the write, before the swap below

	m.mu.Lock()
	defer m.mu.Unlock()
	c := res.Claims
	m.claims = &c
	m.lastLoad = time.Now()
	m.storeErr = nil
	return res, previous, nil
}

// refresh re-reads the store when the cached verdict is older than ttl.
//
// ⛔ ON A STORE FAILURE THE LAST GOOD VERDICT IS KEPT. A transient database blip must never downgrade a
// paying deployment: falling to Community would refuse gateway enrolments, stop IdP provisioning and flip
// the whole UI to upsell cards, all because one query timed out. The licence is not a permission check —
// it is a statement about what the customer bought, and that fact does not become false when a query fails.
//
// ⚠ BUT IT IS RECORDED, NOT SWALLOWED. `storeErr` is what the licence screen renders, and it is a THIRD
// state — distinct from "no licence installed", which is a legitimate product state that must never be
// dressed up as an error, and distinct from "licensed", which this deployment can no longer confirm.
func (m *Manager) refresh(now time.Time) {
	m.mu.RLock()
	store, ttl, last := m.store, m.ttl, m.lastLoad
	m.mu.RUnlock()
	if store == nil || now.Sub(last) < ttl {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	wire, err := store.Get(ctx)

	m.mu.Lock()
	defer m.mu.Unlock()
	m.lastLoad = now // ⚠ stamped even on failure, so a down database is retried at the TTL, not per request
	if err != nil {
		m.storeErr = err
		m.logf("licence_store_unreadable", "err", err.Error(),
			"effect", "keeping the last known verdict; a read failure never downgrades a deployment")
		return
	}
	m.storeErr = nil
	if wire == "" {
		m.claims = nil // genuinely no licence — Community, and not an error
		return
	}
	res, vErr := Verify(TrustedKeys, wire)
	if vErr != nil || !res.OK {
		// ⛔ A STORED KEY THAT WILL NOT VERIFY: LOG LOUDLY, FALL BACK TO COMMUNITY, NEVER REFUSE TO START.
		//
		// Expired, malformed, or signed by a kid no longer in the shipped set — the last is the sharp one,
		// because S12.2 ruled an unknown kid is a refusal, and at boot that means a key rotation downgrades
		// every existing customer on their next restart. That is correct by the letter of the rule and
		// catastrophic in practice, so it is REPORTED here and the operator is told which it was.
		//
		// ⚠ Refusing to start would be worse than any of it: a deployment that will not boot because its
		// licence expired is the total inversion of "a running VPN never stops".
		m.claims = nil
		m.rejected = string(res.Reason)
		if m.rejected == "" && vErr != nil {
			m.rejected = "malformed"
		}
		m.logf("licence_stored_key_rejected", "reason", m.rejected,
			"effect", "serving Community; install a current key to restore entitlements")
		return
	}
	m.rejected = ""
	c := res.Claims
	m.claims = &c
}

func (m *Manager) logf(msg string, kv ...any) {
	if m.logger == nil {
		return
	}
	args := make([]any, 0, len(kv))
	for i := 0; i+1 < len(kv); i += 2 {
		args = append(args, slog.String(kv[i].(string), kv[i+1].(string)))
	}
	m.logger.Warn(msg, args...)
}

// Health is what the licence screen renders about the STORE, as opposed to the entitlement.
//
// ⭐ THREE STATES THAT LOOK ALIKE FROM A DISTANCE AND MUST NOT BE COLLAPSED:
//
//	StoreOK       — the verdict is current. "No licence installed" is a perfectly healthy StoreOK.
//	StoreStale    — the store is unreachable; the deployment is serving its LAST KNOWN verdict.
//	StoreRejected — a key IS stored and it does not verify. Community is being served on purpose.
//
// ⛔ `self_verify_failed` is why this is a typed state with a reason rather than a boolean. An opaque
// refusal cost a live session to diagnose; a refusal that names itself costs a glance.
type StoreHealth struct {
	Stale    bool
	Rejected string // "" unless a stored key failed verification: expired | malformed | unknown_kid | bad_signature
	Detail   string
}

func (m *Manager) StoreStatus() StoreHealth {
	if m == nil {
		return StoreHealth{}
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	h := StoreHealth{Rejected: m.rejected}
	if m.storeErr != nil {
		h.Stale = true
		h.Detail = "The licence store is unreachable. This deployment is serving its last known " +
			"entitlements — nothing has been downgraded. It will recover on its own once the database " +
			"is reachable."
	}
	if h.Rejected != "" {
		h.Detail = "A licence key is stored but was rejected (" + h.Rejected + "). This deployment is " +
			"serving Community entitlements. Installing a current key restores them immediately."
	}
	return h
}
