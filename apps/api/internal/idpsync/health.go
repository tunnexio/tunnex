package idpsync

import "time"

// SyncTier is the legible two-tier sync-health state (D2), DERIVED at read time from the stored
// idp_sync_configs row — never a dead-green field. Mirrors the S7.4b freshness-clock pattern:
// the boolean says "degraded now", the clock says "how long / how bad".
type SyncTier int

const (
	TierOK        SyncTier = iota // last poll succeeded
	TierDegraded                  // immediate tier: a poll is currently failing, within the ceiling
	TierEscalated                 // escalated tier: still failing past 3× the poll interval (30 min)
)

func (t SyncTier) String() string {
	switch t {
	case TierOK:
		return "ok"
	case TierDegraded:
		return "degraded"
	case TierEscalated:
		return "escalated"
	default:
		return "unknown"
	}
}

// EscalationCeiling is 3× the 10-minute poll interval (D2): a sync failing longer than this has
// been broken across three whole cycles and escalates.
const EscalationCeiling = 30 * time.Minute

// ClassifySyncHealth projects the two-tier state.
//   - lastSyncOk true                        → TierOK
//   - lastSyncOk false, last GOOD sync fresh → TierDegraded (immediate tier; a transient blip, or a
//     stable known-bad mapping like a gone group whose fetch still advanced the clock)
//   - lastSyncOk false, last GOOD sync stale → TierEscalated (the clock froze at the last success
//     and now exceeds the ceiling: a sustained outage)
//
// The escalation anchor is the last SUCCESSFUL sync; if a config never synced, it is the creation
// time, so a config that fails from birth still escalates a ceiling after it was created.
func ClassifySyncHealth(lastSyncOk bool, lastSyncAt *time.Time, createdAt, now time.Time, ceiling time.Duration) SyncTier {
	if lastSyncOk {
		return TierOK
	}
	anchor := createdAt
	if lastSyncAt != nil {
		anchor = *lastSyncAt
	}
	if now.Sub(anchor) > ceiling {
		return TierEscalated
	}
	return TierDegraded
}

// ── D1: the partially-licensed state ────────────────────────────────────────────────────────────────

// ⛔ THIS IS NOT A FOURTH SyncTier, AND THAT IS THE WHOLE POINT.
//
// TierDegraded and TierEscalated mean BROKEN — a poll is failing. A lapsed licence is not a failure: the
// sync is running and doing exactly the right thing. Folding it into the tier would render a correct
// deployment as a red one.
//
// ⛔ AND THE CONSEQUENCE OF GETTING THAT WRONG IS THE FAIL-OPEN WE JUST CLOSED. An operator who reads
// "IdP sync: ERROR" does the obvious thing — disconnects or re-enters the credential — and the
// deprovision half stops with it. **Copy that reads as a fault CAUSES the leak the ruling prevents.**
//
// So it rides ALONGSIDE the tier: the tier still says ok, and this says what is and is not happening.
type ProvisioningState int

const (
	// ProvisioningActive — licensed. Joiners are provisioned, leavers are removed.
	ProvisioningActive ProvisioningState = iota
	// ProvisioningPaused — the licence has lapsed. New members are no longer provisioned; removals and
	// deprovisions are STILL APPLIED (D1).
	ProvisioningPaused
)

// The operator-facing copy, as constants rather than strings assembled at a call site, so the wording is
// one truth and is testable. The customer is entitled to know their deployment is still talking to their
// IdP on a lapsed licence — §2 of docs/S12.1-D1-idpsync-release.md accepts that it keeps calling, on the
// condition that it is VISIBLE rather than silent.
const (
	ProvisioningPausedTitle = "Directory sync is partially licensed"
	ProvisioningPausedBody  = "Your licence has lapsed, so new members are no longer being added from your " +
		"directory. Removals are still being applied: someone removed or disabled in your directory still " +
		"loses access here. Renew to resume adding members."
)

// DescribeProvisioning returns the operator-facing title and body for a provisioning state, or empty
// strings when nothing needs saying. ⚠ Empty on Active by design — a permanent "provisioning is working"
// banner trains the reader to stop seeing the line that matters when it changes.
func DescribeProvisioning(p ProvisioningState) (title, body string) {
	if p == ProvisioningPaused {
		return ProvisioningPausedTitle, ProvisioningPausedBody
	}
	return "", ""
}
