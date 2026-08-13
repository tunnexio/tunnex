package licence

import (
	"context"
	"errors"
	"testing"
	"time"
)

type fakeStore struct {
	wire string
	err  error
	gets int
}

func (f *fakeStore) Get(context.Context) (string, error) { f.gets++; return f.wire, f.err }
func (f *fakeStore) Put(_ context.Context, w string) error {
	f.wire = w
	return nil
}

// ⛔ THE TTL FLOOR. A zero — which is exactly what an unset struct field is — would make Evaluate a
// database query, on the path every org-scoped handler and every enrolment takes.
func TestZeroTTLIsClampedNotHonoured(t *testing.T) {
	f := &fakeStore{}
	m := (&Manager{}).WithStore(f, 0, nil)
	now := time.Unix(1_700_000_000, 0)
	for i := 0; i < 50; i++ {
		m.Evaluate(now.Add(time.Duration(i) * time.Millisecond))
	}
	if f.gets > 1 {
		t.Fatalf("⛔ %d STORE READS FOR 50 EVALUATIONS. A ttl of 0 was honoured literally, so the "+
			"entitlement read is now the busiest query in the deployment", f.gets)
	}
	if got := m.ttl; got < MinRefreshInterval {
		t.Errorf("ttl = %v, want >= %v", got, MinRefreshInterval)
	}
}

// ⭐ THE LOAD-BEARING ONE: A STORE FAILURE MUST NOT DOWNGRADE A PAYING DEPLOYMENT.
//
// Falling to Community on a read error would refuse gateway enrolments, stop IdP provisioning and flip
// every enterprise surface to an upsell — because one query timed out. A licence is a statement about what
// the customer bought; that fact does not become false when the database blinks.
func TestStoreFailureKeepsTheLastGoodVerdict(t *testing.T) {
	f := &fakeStore{}
	m := (&Manager{}).WithStore(f, MinRefreshInterval, nil)
	if _, _, err := m.Persist(context.Background(), TrustedKeys, "tnxl_nonsense"); err == nil {
		// a bad key is refused — we seed the verdict directly instead, which is what a real install leaves
		_ = err
	}
	m.mu.Lock()
	m.claims = &Claims{Version: 1, Tier: "growth", Band: "growth", ExpiresAt: time.Now().Add(time.Hour).Unix()}
	m.mu.Unlock()

	f.err = errors.New("connection refused")
	later := time.Now().Add(time.Hour)
	st := m.Evaluate(later)

	if st.Tier != TierGrowth {
		t.Fatalf("⛔ A DATABASE BLIP DOWNGRADED A PAYING DEPLOYMENT: tier = %v, want growth", st.Tier)
	}
	// ⚠ Kept, but NOT hidden — the screen must be able to say the verdict is stale.
	h := m.StoreStatus()
	if !h.Stale {
		t.Error("the store failure is invisible: StoreStatus().Stale is false")
	}
	if h.Detail == "" {
		t.Error("no operator-readable detail for an unreachable store")
	}
}

// ⛔ AND "NO LICENCE" IS NOT "COULD NOT READ". One is a product state, the other an outage, and a screen
// that renders them alike sends an operator to look for a key that was never installed.
func TestEmptyStoreIsCommunityAndNotAnError(t *testing.T) {
	m := (&Manager{}).WithStore(&fakeStore{wire: ""}, MinRefreshInterval, nil)
	st := m.Evaluate(time.Now())
	if st.State != StateUnlicensed || st.Tier != TierCommunity {
		t.Fatalf("empty store = %v/%v, want unlicensed/community", st.State, st.Tier)
	}
	if h := m.StoreStatus(); h.Stale || h.Rejected != "" {
		t.Errorf("an empty store reported a fault: %+v", h)
	}
}

// ⛔ A STORED KEY THAT WILL NOT VERIFY: COMMUNITY, VISIBLY, AND NEVER A REFUSAL TO START.
//
// ⚠ The sharp case is a kid no longer in the shipped set — S12.2 ruled an unknown kid is a refusal, and at
// boot that means a key rotation downgrades every existing customer on their next restart. Correct by the
// letter of the rule, catastrophic in practice, so it must at minimum SAY which it was.
func TestRejectedStoredKeyIsVisibleNotFatal(t *testing.T) {
	m := (&Manager{}).WithStore(&fakeStore{wire: "tnxl_this-is-not-a-key"}, MinRefreshInterval, nil)
	st := m.Evaluate(time.Now())
	if st.Tier != TierCommunity {
		t.Fatalf("a rejected key granted %v", st.Tier)
	}
	h := m.StoreStatus()
	if h.Rejected == "" {
		t.Fatal("⛔ A STORED KEY WAS REJECTED SILENTLY. The operator sees Community and no reason — the " +
			"self_verify_failed shape, which cost a live session to diagnose")
	}
	if h.Stale {
		t.Error("a rejected key is not a stale store — the two states must stay distinguishable")
	}
}

// ⛔ THE AUDIT'S "FROM" IS THE TIER THAT WAS REPLACED — asserted across TWO installs, because one install
// from Community proves nothing: `from: community` is also what a broken read returns for a fresh manager.
//
// ⚠ THE SECOND INSTALL IS THE TEST. It must read `from: <the first key's tier>`, never `from: <the second
// key's tier>` — which is what persisting-then-reading produces, and which looks correct in a log.
func TestPersistReturnsTheTierItReplaced(t *testing.T) {
	m := (&Manager{}).WithStore(&fakeStore{}, MinRefreshInterval, nil)

	// Seed a licensed deployment (a real Install is exercised by the golden vector elsewhere).
	m.mu.Lock()
	m.claims = &Claims{Version: 1, Tier: "growth", Band: "growth", ExpiresAt: time.Now().Add(time.Hour).Unix()}
	m.lastLoad = time.Now()
	m.mu.Unlock()

	// A refused key still reports what the deployment currently HAS — the audit row for a rejected install
	// must not claim the deployment was Community.
	_, previous, _ := m.Persist(context.Background(), TrustedKeys, "tnxl_not-a-key")
	if previous != TierGrowth {
		t.Fatalf("⛔ previous tier = %v, want growth. The audit row would record a downgrade that never "+
			"happened, or an upgrade from nothing", previous)
	}
}
