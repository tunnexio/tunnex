package http

import (
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
)

// TestAgentGatewayReportingWatchesTheStatusChannel — S15.3.
//
// ⛔ THE GATEWAY RUNS TWO LOOPS AND ONLY ONE OF THEM CARRIES HANDSHAKES. `/agent/report` bumps
// `nodes.last_seen_at`; `/agent/status` upserts `device_status` (stamping `updated_at`) and is the sole
// carrier of peer handshake data. They run at the same 30s cadence in the same process, which is exactly why
// watching the wrong one looks correct in every normal condition and fails only when it matters.
//
// > **A FRESHNESS CLOCK MUST BE STAMPED BY THE CHANNEL IT VOUCHES FOR.** Otherwise "the reporter is alive"
// > is a claim about a different reporter.
func TestAgentGatewayReportingWatchesTheStatusChannel(t *testing.T) {
	ts := func(d time.Duration) pgtype.Timestamptz {
		return pgtype.Timestamptz{Time: time.Now().Add(-d), Valid: true}
	}
	var absent pgtype.Timestamptz

	// ── ⭐ THE CASE THE FIELD EXISTS FOR: the status push has died, the report loop has not.
	//    Reading last_seen_at here returns true — the gateway looks healthy — while no handshake data is
	//    arriving at all, so every agent on it would render a confident "never connected".
	if agentGatewayReporting(ts(30*time.Minute), ts(5*time.Second)) {
		t.Fatal("a STALE status channel must read as not-reporting even while the report loop is fresh — " +
			"that is the whole failure this field was added to prevent")
	}

	// ── AND THE SECOND HALF, without which the first would pass on `return false`.
	if !agentGatewayReporting(ts(5*time.Second), ts(30*time.Minute)) {
		t.Fatal("a FRESH status channel must read as reporting; a function that refused everything would " +
			"turn every agent's liveness into permanent unknown, which is not caution, it is blindness")
	}

	// ── THE FALLBACK, AND ITS EXACT SCOPE. No device_status row at all means no push has yet mentioned
	//    this agent — true for the first ~30s of its life. Treating that as a dead reporter would bury the
	//    ACTIONABLE "never connected" (run the command) under an unknown that blames the gateway.
	if !agentGatewayReporting(absent, ts(5*time.Second)) {
		t.Fatal("with no status row yet, a live gateway must still count as reporting")
	}
	if agentGatewayReporting(absent, ts(30*time.Minute)) {
		t.Fatal("with no status row AND a stale gateway, nothing is reporting")
	}
	// ⚠ Neither clock present is the honest zero: we have heard nothing from anywhere.
	if agentGatewayReporting(absent, absent) {
		t.Fatal("with no clock at all, the reporter cannot be claimed alive")
	}

	// ⛔ AND IT SHARES THE DEVICE WINDOW RATHER THAN CHOOSING ITS OWN. If this drifted from
	//    `deviceOnline`, the Agents screen and the Devices screen would disagree about the same gateway
	//    and neither would be wrong on its own terms.
	justInside := onlineThreshold - time.Second
	justOutside := onlineThreshold + time.Second
	if !agentGatewayReporting(ts(justInside), absent) {
		t.Fatalf("inside the shared window (%s) must report", onlineThreshold)
	}
	if agentGatewayReporting(ts(justOutside), absent) {
		t.Fatalf("outside the shared window (%s) must not report", onlineThreshold)
	}
}
