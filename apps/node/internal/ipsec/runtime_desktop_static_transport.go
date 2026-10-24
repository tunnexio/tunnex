package ipsec

// The immutable delivery marker selects route-based CHILD_SAs. Grants may change
// every lease without changing their selectors; exact finite guard permits remain
// the only application authority. A missing marker preserves legacy LAN ownership.
func validDesktopStaticManifest(m RuntimeManifest) bool {
	if m.DesktopStaticVersion == nil {
		return true
	}
	return *m.DesktopStaticVersion == 1 && m.ProfileID == "aws-static-ipv4-v1" &&
		m.BGP == nil && m.BGPVersion == nil && m.RecoveryVersion != nil && *m.RecoveryVersion == 1 &&
		m.TransportVersion == nil && m.TunnelCount == nil
}

func hasDesktopStaticTransport(e RuntimeJournalEntry) bool {
	return e.Engines[0].DesktopStaticVersion != 0 || e.Engines[1].DesktopStaticVersion != 0
}

func validDesktopStaticJournal(e RuntimeJournalEntry) bool {
	if !hasDesktopStaticTransport(e) {
		return true
	}
	return e.Engines[0].DesktopStaticVersion == 1 && e.Engines[1].DesktopStaticVersion == 1 &&
		e.Allocation.ProfileID == "" && !e.Allocation.BGP && e.BGP == nil && e.ContractVersion == 2 &&
		e.Engines[0].ProfileID == "" && e.Engines[1].ProfileID == "" && !e.Engines[0].BGP && !e.Engines[1].BGP &&
		validJournalRecovery(e)
}
