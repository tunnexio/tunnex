package ipsec

import "net/netip"

// runtimeBGPContract identifies bounded intent, never runtime qualification.
func runtimeBGPContract(m RuntimeManifest) (bool, error) {
	if m.ProfileID != "aws-bgp-ipv4-v1" && m.ProfileID != GCPHABGPProfile && !IsAzureBGPProfile(m.ProfileID) {
		if m.BGP != nil || m.BGPVersion != nil {
			return false, ErrRuntimeController
		}
		return false, nil
	}
	version := 1
	if m.ProfileID == GCPHABGPProfile {
		version = 2
	}
	if IsAzureBGPProfile(m.ProfileID) {
		version = 3
	}
	if m.BGPVersion == nil || *m.BGPVersion != version || m.BGP == nil || m.RecoveryVersion != nil || !validProfileBGPConfig(m.ProfileID, *m.BGP) {
		return false, ErrRuntimeController
	}
	if m.ProfileID == GCPHABGPProfile && !validGCPBGPConfig(*m.BGP) {
		return false, ErrRuntimeController
	}
	if IsAzureBGPProfile(m.ProfileID) && !validAzureBGPConfig(*m.BGP) {
		return false, ErrRuntimeController
	}
	return true, nil
}
func validBGPConfig(b BGPConfig) bool {
	private := func(a uint32) bool { return a >= 64512 && a <= 65534 || a >= 4200000000 && a <= 4294967294 }
	id, e := netip.ParseAddr(b.RouterID)
	return private(b.LocalASN) && (private(b.RemoteASN) || b.RemoteASN == 7224) && b.LocalASN != b.RemoteASN && b.MaximumPrefixes >= 1 && b.MaximumPrefixes <= 64 && e == nil && id.Is4() && id.String() == b.RouterID && id.As4()[0] != 0 && !id.IsLoopback() && !id.IsLinkLocalUnicast() && id.As4()[0] < 224
}
func validJournalBGP(r RuntimeJournalEntry) bool {
	if r.ContractVersion != 3 {
		if r.BGP != nil || r.Allocation.BGP || r.Engines[0].BGP || r.Engines[1].BGP {
			return false
		}
		return true
	}
	if r.BGP == nil || !validProfileBGPConfig(r.Allocation.ProfileID, *r.BGP) || (r.Allocation.ProfileID == GCPHABGPProfile && !validGCPBGPConfig(*r.BGP)) || (IsAzureBGPProfile(r.Allocation.ProfileID) && !validAzureBGPConfig(*r.BGP)) || !r.Allocation.BGP || r.Recovery != nil {
		return false
	}
	for i, e := range r.Engines[:r.Allocation.activeTunnelCount()] {
		if !e.BGP || e.ProfileID != r.Allocation.ProfileID || r.Allocation.Tunnels[i].BGP == nil {
			return false
		}
	}
	return true
}

// bgpRefusalPeers persists transport denial independently of application prefix
// boundaries and live namespace/interface ownership. It never carries permits.
func bgpRefusalPeers(e RuntimeJournalEntry) []GuardBGPPeer {
	if e.ContractVersion != 3 || !validJournalBGP(e) {
		return nil
	}
	peers := make([]GuardBGPPeer, 0, 2)
	for _, t := range e.Allocation.Tunnels[:e.Allocation.activeTunnelCount()] {
		profile := ""
		if IsAzureBGPProfile(e.Allocation.ProfileID) {
			profile = "azure-apipa-v1"
		}
		peers = append(peers, GuardBGPPeer{TransportProfile: profile, Local: t.InsideAddress.Addr(), Remote: t.BGP.Peer})
	}
	return peers
}
