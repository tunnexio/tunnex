package licence

import (
	"crypto/ed25519"
	"log/slog"
	"sync"
	"time"
)

// Manager answers "what is this deployment entitled to" — offline, from a signed key, or from nothing.
//
// ⛔ AN ABSENT LICENCE IS COMMUNITY, NOT A REFUSAL (founder-ruled). A deployment that upgrades into this
// code must not lose anything it can keep under Community: one gateway, one org, the complete Zero Trust
// engine. What it loses is SSO, IdP sync, and the ability to enrol a SECOND gateway or org — and it must
// SAY so rather than fail silently.
//
// ⭐ THE ZERO VALUE IS USABLE AND MEANS COMMUNITY. That is the fail-open default, and it exists in the same
// commit as the reader on purpose: the moment a capability starts asking a real question there must never
// be a window where nothing answers.
type Manager struct {
	mu sync.RWMutex
	// ⚠ THE PARSE IS CACHED. THE VERDICT IS NOT. Settings change on write; a licence expires on TIME, so a
	// verdict computed at load is wrong from the first second after expiry. Every read re-evaluates the
	// clock against the cached claims.
	//
	// Cost on the hot path: two int64 comparisons and an RLock. The signature check — the expensive part —
	// happens once, in Install.
	claims *Claims
	clock  Clock

	// ── the durable half (S12.1 follow-up) ────────────────────────────────────────────────────────────
	// ⛔ THE MANAGER WAS MEMORY-ONLY AND THAT WAS A LIVE DEFECT: an installed licence evaporated on the
	// next restart, and the first symptom a customer saw was a gateway refusing to enrol.
	store    Store
	ttl      time.Duration
	lastLoad time.Time
	storeErr error  // the store could not be read — the last good verdict is being served
	rejected string // a key IS stored and does not verify — Community is being served on purpose
	logger   *slog.Logger
}

// State is where a deployment sits on the degradation ladder.
type State int

const (
	// StateUnlicensed — no key. Community. Not an error and not a failure.
	StateUnlicensed State = iota
	// StateValid — a key, not expired.
	StateValid
	// StateExpired — past expiry, inside grace. ⛔ NOTHING STOPS. A warning is shown.
	StateExpired
	// StateLapsed — past expiry + grace. Gated capabilities stop; the VPN does not.
	StateLapsed
)

// GracePeriod is the 90 days after expiry during which everything keeps working.
const GracePeriod = 90 * 24 * time.Hour

// Install verifies a wire key and caches its claims. An error leaves the previous state untouched — a bad
// paste must never downgrade a working deployment.
func (m *Manager) Install(keys map[string]ed25519.PublicKey, wire string) (Result, error) {
	res, err := Verify(keys, wire)
	if err != nil || !res.OK {
		return res, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	c := res.Claims
	m.claims = &c
	return res, nil
}

// Status is the whole answer, evaluated against `now`.
type Status struct {
	State State
	Tier  Tier
	// ExpiresAt is zero when unlicensed.
	ExpiresAt time.Time
	// GraceEndsAt is when gated capabilities stop. Zero unless expired.
	GraceEndsAt time.Time
	// ClockWentBackwards is honest instrumentation, never a refusal.
	ClockWentBackwards bool
}

// Evaluate answers for a given instant. ⚠ PER READ — see the note on Manager.claims.
func (m *Manager) Evaluate(now time.Time) Status {
	// ⛔ A NIL MANAGER IS COMMUNITY, NOT A PANIC — and this is a safety property, not a convenience.
	//
	// Every consumer in this story already treats a nil manager as "no licence, Community entitlements",
	// which is the correct fail-open: an unlicensed deployment must keep the free product. Making the
	// RECEIVER honour that too means the fail-open cannot be lost by one construction site forgetting the
	// guard. Without it, a single unguarded field turns "this deployment has no licence" — the most common
	// state there is — into a 500 on the first request that asks.
	if m == nil {
		return Status{State: StateUnlicensed, Tier: TierCommunity}
	}
	// ⚠ READ-THROUGH, TTL-BOUNDED — AND IT RUNS AFTER THE NIL GUARD, WHICH IS NOT A DETAIL. It was written
	// above it and panicked every caller holding a nil manager: the refresh dereferences the receiver, so a
	// safety guard placed after the thing it guards is not a guard at all.
	//
	// Every replica re-reads the store rather than caching at boot: without this, persistence would only
	// convert "the licence dies on restart" into "the licence exists on some pods and not others", and a
	// gateway enrolment refused by one replica would succeed on the next.
	m.refresh(now)
	obs := m.clock.Observe(now)

	m.mu.RLock()
	c := m.claims
	m.mu.RUnlock()

	if c == nil {
		return Status{State: StateUnlicensed, Tier: TierCommunity, ClockWentBackwards: obs.BackwardJump}
	}

	// ⚠ A TIER THIS BUILD DOES NOT KNOW IS COMMUNITY, not everything. A licence naming an unknown tier is
	// one this build cannot honour, and the safe reading is the free tier.
	tier := Tier(c.Tier)
	if !KnownTier(tier) {
		tier = TierCommunity
	}

	exp := time.Unix(c.ExpiresAt, 0)
	st := Status{Tier: tier, ExpiresAt: exp, ClockWentBackwards: obs.BackwardJump}
	switch {
	case now.Before(exp):
		st.State = StateValid
	case now.Before(exp.Add(GracePeriod)):
		// ⛔ EXPIRED IS NOT LAPSED. Nothing stops here — the entitlement is unchanged and a warning is the
		// only difference. That is the ruling: a running VPN never stops, and no human is ever blocked.
		st.State = StateExpired
		st.GraceEndsAt = exp.Add(GracePeriod)
	default:
		st.State = StateLapsed
		st.GraceEndsAt = exp.Add(GracePeriod)
		// ⛔ AFTER GRACE THE GATED CAPABILITIES STOP, which is expressed by falling back to Community —
		// NOT by refusing. Existing gateways and orgs keep running; only enrolment is affected.
		st.Tier = TierCommunity
	}
	return st
}

// Has is the entitlement question every gated capability asks.
//
// ⚠ NEVER `if edition == "enterprise"`. This reads the ONE map, so moving a feature between tiers stays a
// one-line change.
func (m *Manager) Has(f Feature, now time.Time) bool {
	return Has(m.Evaluate(now).Tier, f)
}

// GatewayCeilingNow is the number of gateways this deployment may ENROL. nil means unlimited.
//
// ⛔ AT ENROLMENT ONLY. Running gateways are never stopped, and an UPGRADE IS NOT AN ENROLMENT: a
// deployment already running three gateways keeps all three and cannot add a fourth.
// ⛔ RULED: `gw` IS AUTHORITATIVE WHEN THE KEY CARRIES IT. The tier map is the DEFAULT, not the answer.
//
// The alternative was to delete `gw` from the wire. Rejected, and the reason is commercial rather than
// technical: `gw` is resolved AT MINT precisely so a later band-table change cannot re-price a key already
// in a customer's hands. Deleting it would mean a customer's ceiling silently follows whatever the CURRENT
// build's map says — so shipping a release that lowers Growth from 20 to 15 would quietly take five
// gateways off every existing Growth customer, mid-term, without anyone deciding to.
//
// > ## ⭐ **A SIGNED KEY IS A CONTRACT. THE MAP IS THE PRICE LIST. WHEN THEY DISAGREE, THE CONTRACT WINS.**
//
// ⚠ AND THIS ENDS THE RENDER-FLOOR VIOLATION RATHER THAN LIVING WITH IT. Until now the key ASSERTED a
// ceiling — signed, attested, unrecallable — and the product ignored it. A claim that is cryptographically
// attested and operationally inert is worse than no claim: `gw: 20` shipped on a trial key and was true of
// nothing.
//
// ⚠ THE TWO CANNOT DRIFT GOING FORWARD, which is what makes trusting the key safe: the issuer computes
// `gw` from `BANDS[band].gateways` at mint, `BANDS` is the single source in that repo, and
// `band_agreement_test.go` pins it against the Go map by hand in both repos.
//
// ⛔ A KEY WITH NO `gw` FALLS BACK TO THE MAP. Keys minted before S12.1 carry neither `tier` nor `gw`; they
// read as Community, which is exactly what they could do when they were signed.
func (m *Manager) GatewayCeilingNow(now time.Time) *int {
	m.mu.RLock()
	c := m.claims
	m.mu.RUnlock()
	st := m.Evaluate(now)
	// ⚠ ONLY WHILE THE LICENCE STILL GRANTS ITS TIER. Once lapsed, Evaluate falls to Community and the
	// signed ceiling goes with it — a contract that has expired is not a contract.
	if c != nil && c.Gateways != nil && st.Tier != TierCommunity {
		return c.Gateways
	}
	ceil, _ := GatewayCeilingFor(st.Tier)
	return ceil
}

// OrgCeilingNow is the number of organizations this deployment may CREATE. nil means unlimited.
func (m *Manager) OrgCeilingNow(now time.Time) *int {
	c, _ := OrgCeilingFor(m.Evaluate(now).Tier)
	return c
}

// AllowsNewPrincipals reports whether a new principal — a device, an agent, a gateway — may be enrolled.
//
// ⛔ THIS IS THE GRACE LADDER'S TEETH, AND IT IS THE ONLY THING GRACE CHANGES.
//
//	valid    → yes
//	expired  → NO. Everything already enrolled keeps working; nothing stops. What stops is GROWTH.
//	lapsed   → NO.
//
// ⚠ THAT IS THE WHOLE DISTINCTION THE MODEL RESTS ON: a limit that blocks a new principal blocks GROWTH,
// and a limit that stops a running one blocks WORK. Grace refuses the first and never the second — a
// running VPN never stops, and no human already connected is ever disconnected by a licence state.
func (m *Manager) AllowsNewPrincipals(now time.Time) bool {
	switch m.Evaluate(now).State {
	case StateExpired, StateLapsed:
		return false
	default:
		return true
	}
}

// NewPrincipalRefusal is what an operator reads when grace has begun.
//
// ⭐ It says what still works before it says what does not, because the first thing an operator needs is
// to know their fleet is fine.
func (m *Manager) NewPrincipalRefusal(now time.Time) string {
	st := m.Evaluate(now)
	when := ""
	if !st.ExpiresAt.IsZero() {
		when = " on " + st.ExpiresAt.Format("2 January 2006")
	}
	return "This licence expired" + when + ". Everything already enrolled keeps working and nothing has " +
		"stopped — but new devices, agents and gateways cannot be enrolled until it is renewed."
}
