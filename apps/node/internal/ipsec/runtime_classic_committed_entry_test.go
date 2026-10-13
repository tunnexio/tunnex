package ipsec

import "testing"

func TestClassicCommittedEntryRejectsHistoryDrift(t *testing.T) {
	m := classicMaterialFixture()
	entry, _, err := runtimeMaterialEntry(m, m.Manifest.OrgID, m.Manifest.NodeID, "net:[4026531992]")
	if err != nil {
		t.Fatal(err)
	}
	boot := "9617762e-19db-4a21-bdee-909dfb31e501"
	saved := entry
	saved.Phase = RuntimeApplied
	saved.Restoration = &RuntimeRestoration{BootID: boot}
	if !classicCommittedEntryMatches(entry, saved, boot) {
		t.Fatal("initial exact commit refused")
	}
	if classicCommittedEntryMatches(saved, saved, "foreign") || classicCommittedEntryMatches(entry, saved, "") {
		t.Fatal("fresh boot change accepted")
	}
	for _, kind := range []string{"boot", "epoch", "history", "observed", "phase"} {
		changed := saved
		stamp := *saved.Restoration
		changed.Restoration = &stamp
		switch kind {
		case "boot":
			stamp.BootID = "foreign"
		case "epoch":
			stamp.Epoch = 1
		case "history":
			stamp.Retired = []RuntimeRetiredEpoch{{EvidenceDigest: "foreign"}}
		case "observed":
			changed.Observed[0].InterfaceIndex = 999
		case "phase":
			changed.Phase = RuntimeCleanupPending
		}
		if classicCommittedEntryMatches(entry, changed, boot) {
			t.Fatal("initial foreign commit accepted", kind)
		}
		prior := saved
		if classicCommittedEntryMatches(prior, changed, boot) {
			t.Fatal("existing restoration changed", kind)
		}
	}
}
