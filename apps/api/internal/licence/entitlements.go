package licence

// ⭐ ONE MAP. TIER → FEATURE SET. AS DATA.
//
// ⛔ NEVER `if edition == "enterprise"`. The boundary between tiers is DATA so that moving a feature is one
// line here — and that property is the whole reason for the shape. The licensing model says the tier table
// may be revised in either direction as the market answers; a boundary encoded as control flow can only be
// rewritten, never revised. The build-tag split this replaces was exactly that: 25 tagged files and 40 web
// call sites, none of them movable without a refactor.

// Feature is a named capability. ⛔ NAMED PER CAPABILITY, NEVER REUSED — the same rule RBAC permissions
// follow, and for the same reason: a shared name makes two capabilities impossible to separate later.
type Feature string

const (
	// FeatMultiGateway — more than one gateway. ⚠ The COUNT is a band property, not a boolean; this only
	// says whether the tier may exceed the free ceiling at all.
	FeatMultiGateway Feature = "multi_gateway"
	// FeatMultiOrg — more than one organization.
	FeatMultiOrg Feature = "multi_org"
	// FeatSSO — SSO/OIDC login (Google, Microsoft Entra).
	FeatSSO Feature = "sso"
	// FeatIdpSync — IdP directory sync. ⚠ Its DEPROVISION half is not gated: a licence may stop granting
	// access, it must never stop removing it.
	FeatIdpSync Feature = "idp_sync"
)

// Tier is what a licence grants. ⚠ Community is the no-key tier: holding no licence IS being Community.
type Tier string

const (
	TierCommunity Tier = "community"
	TierTrial     Tier = "trial"
	TierStarter   Tier = "starter"
	TierGrowth    Tier = "growth"
	TierScale     Tier = "scale"
)

// GatewayCeiling is the number of gateways a tier may ENROL. nil means unlimited.
//
// ⛔ CHECKED AT ENROLMENT ONLY. A running gateway is never stopped — which is why the trial ceiling is 2 and
// not 20: a temporary grant of a create-time limit is a permanent grant of everything created under it
// (docs/laws.md). Two is what shows site-to-site and failover, and a ceiling we are content to leave
// running forever.
// ⛔ THE CEILINGS ARE UNEXPORTED AND REACHED ONLY THROUGH THE ACCESSORS BELOW.
//
// ⚠ AND THAT IS A NARROWER PROTECTION THAN IT LOOKS — said plainly rather than implied. Unexporting stops
// arbitrary code INDEXING the map with an arbitrary tier and acting on the number; it does NOT stop someone
// editing `TierTrial: ptr(2)` to `ptr(20)` because it looks inconsistent beside Growth. No API shape
// prevents a literal being changed.
//
// ⭐ WHAT ACTUALLY GUARDS THE NUMBER IS THE TEST THAT PINS IT WITH ITS REASON
// (nodes.TestTheBandsAreTheFoundersNumbers): a temporary grant of a create-time limit is a permanent grant
// of everything created under it, so 2 is what shows site-to-site and failover AND a ceiling we are content
// to leave running forever. Both halves must hold, and only 2 satisfies both.
var gatewayCeiling = map[Tier]*int{
	TierCommunity: ptr(1),
	TierTrial:     ptr(2),
	TierStarter:   ptr(5),
	TierGrowth:    ptr(20),
	TierScale:     nil,
}

// OrgCeiling is the number of organizations a tier may CREATE. nil means unlimited.
var orgCeiling = map[Tier]*int{
	TierCommunity: ptr(1),
	TierTrial:     ptr(1),
	TierStarter:   nil,
	TierGrowth:    nil,
	TierScale:     nil,
}

// ⭐ THE MAP. Moving a feature between tiers is one line.
//
// ⚠ COMMUNITY IS DELIBERATELY GENEROUS AND THAT IS THE STRATEGY, NOT AN OVERSIGHT: the complete Zero Trust
// engine, AI agents, Kubernetes, OpenVPN, posture, approval, MFA enforcement, Access Events and the
// full-retention audit log are all free. The moat is Community's generosity, not Enterprise's length —
// a thinner Community loses to NetBird, whose self-hosted edition is free with unlimited users.
var tierFeatures = map[Tier]map[Feature]bool{
	TierCommunity: {},
	// ⛔ THE TRIAL CARRIES SSO AND DIRECTORY SYNC (founder-ruled). A trial exists to answer "does this
	// work for us", and for an enterprise buyer that question IS SSO. Without it the trial could not
	// configure Google or Entra at all, so the one capability most likely to decide the purchase was the
	// one thing the evaluation could not test.
	//
	// ⚠ AND IT IS BOUNDED, BECAUSE THIS IS A CREATE-TIME GRANT. SSO LOGIN is deliberately never gated (a
	// licence state must never lock a human out — see requireSSOAdmin), so handing the trial SSO would
	// otherwise buy PERMANENT free SSO for anyone who takes one: the trial-band law, exactly. What stops
	// at lapse is everything that ONBOARDS SOMEBODY NEW — JIT provisioning and domain-capture auto-join —
	// so the free-forever surface is capped at the humans who already existed during the trial.
	TierTrial:   {FeatMultiGateway: true, FeatSSO: true, FeatIdpSync: true},
	TierStarter: {FeatMultiGateway: true, FeatMultiOrg: true, FeatSSO: true, FeatIdpSync: true},
	TierGrowth:  {FeatMultiGateway: true, FeatMultiOrg: true, FeatSSO: true, FeatIdpSync: true},
	TierScale:   {FeatMultiGateway: true, FeatMultiOrg: true, FeatSSO: true, FeatIdpSync: true},
}

// GatewayCeilingFor is the number of gateways a tier may ENROL. nil means unlimited.
//
// ⚠ AN UNKNOWN TIER GETS COMMUNITY'S CEILING, NOT UNLIMITED — and closing that is most of why the accessor
// exists. `gatewayCeiling[unknownTier]` returns a nil *int, which this package reads as UNLIMITED: the most
// permissive possible answer for a tier this build cannot honour. A missing entry and "unlimited" are the
// same zero value, and only a function can tell them apart.
func GatewayCeilingFor(t Tier) (ceiling *int, known bool) {
	c, ok := gatewayCeiling[t]
	if !ok {
		return gatewayCeiling[TierCommunity], false
	}
	return c, true
}

// OrgCeilingFor is the number of organizations a tier may CREATE. nil means unlimited. Same unknown-tier
// rule as GatewayCeilingFor.
func OrgCeilingFor(t Tier) (ceiling *int, known bool) {
	c, ok := orgCeiling[t]
	if !ok {
		return orgCeiling[TierCommunity], false
	}
	return c, true
}

// KnownTier reports whether this build understands a tier name.
func KnownTier(t Tier) bool { _, ok := gatewayCeiling[t]; return ok }

// AllFeatures is every feature, for censuses and for the admin surface. Derived from the map so a new
// feature cannot be invisible to either.
func AllFeatures() []Feature {
	seen := map[Feature]bool{}
	for _, fs := range tierFeatures {
		for f := range fs {
			seen[f] = true
		}
	}
	out := make([]Feature, 0, len(seen))
	for f := range seen {
		out = append(out, f)
	}
	return out
}

// Has reports whether a tier includes a feature.
//
// ⚠ AN UNKNOWN TIER HAS NOTHING. A licence naming a tier this build does not know is not a licence for
// everything — it is a licence this build cannot honour, and the safe reading is the free tier.
func Has(t Tier, f Feature) bool { return tierFeatures[t][f] }

func ptr(i int) *int { return &i }
