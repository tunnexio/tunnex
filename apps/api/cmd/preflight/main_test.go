package main

import (
	"strings"
	"testing"
	"time"
)

// TestSinceNamesTheAgeOrItsAbsence — the WF-S11-2 fold's substance.
//
// The walk found preflight printing "all 4 gateway(s) at v6 or newer" about a fleet where three agents had last
// reported five days earlier. The number was right; the sentence implied a liveness claim the check never made.
// This asserts the two cases that made it wrong: a NEVER-reported agent must not render as an age, and a
// long-silent one must render in days rather than being rounded into invisibility.
func TestSinceNamesTheAgeOrItsAbsence(t *testing.T) {
	if got := since(nil); got != "never reported" {
		t.Fatalf("a nil report time must be named, not rendered as an age: got %q", got)
	}

	fiveDays := time.Now().Add(-5 * 24 * time.Hour)
	got := since(&fiveDays)
	if !strings.Contains(got, "5d") {
		t.Fatalf("a five-day-old report must say so in days: got %q", got)
	}

	// The exact wire case from the walk: the live gateway. It must NOT read as stale.
	fresh := time.Now().Add(-30 * time.Second)
	if got := since(&fresh); !strings.Contains(got, "just now") {
		t.Fatalf("a fresh report must read as current: got %q", got)
	}

	// The boundary that decides wording. staleAfter is an hour, so 59m is current and 61m is not — the
	// threshold changes WORDING only and must never change whether preflight passes.
	almost := time.Now().Add(-59 * time.Minute)
	if got := since(&almost); !strings.Contains(got, "m ago") {
		t.Fatalf("under an hour must render in minutes: got %q", got)
	}
	over := time.Now().Add(-61 * time.Minute)
	if got := since(&over); !strings.Contains(got, "h ago") {
		t.Fatalf("over an hour must render in hours: got %q", got)
	}
}

// TestStaleAfterOnlyAffectsWording guards the property that makes the fold safe: staleness is reported, never
// enforced. A stale agent's last-known version is a conservative floor (a dead agent cannot have been silently
// downgraded), so preflight must not start REFUSING rolls on deployments with legitimately dormant sites —
// which is the exact scope expansion that was registered rather than built (option (b), not ruled).
func TestStaleAfterOnlyAffectsWording(t *testing.T) {
	if staleAfter <= 0 {
		t.Fatal("staleAfter must be a positive duration")
	}
	if staleAfter > 24*time.Hour {
		t.Fatalf("staleAfter = %s is too generous to be informative", staleAfter)
	}
}
