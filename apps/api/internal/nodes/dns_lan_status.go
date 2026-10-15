package nodes

import (
	"github.com/google/uuid"
	"net/netip"
	"strings"
	"unicode"
)

// DNSLANListenerState is a bounded authenticated observation, not a grant.
// Freshness comes from the control-plane policy_reported_at receipt timestamp.
type DNSLANListenerState struct {
	Address    string   `json:"address"`
	Interface  string   `json:"interface"`
	Ready      bool     `json:"ready"`
	Error      string   `json:"error"`
	ProfileIDs []string `json:"profile_ids"`
}

func boundedDNSLANListenerStates(in []DNSLANListenerState) []DNSLANListenerState {
	out := []DNSLANListenerState{}
	if len(in) > 16 {
		return out
	}
	for _, state := range in {
		addr, err := netip.ParseAddr(state.Address)
		if err != nil || !addr.Is4() || !addr.IsPrivate() || state.Interface == "" || len(state.Interface) > 15 || len(state.ProfileIDs) > 16 {
			continue
		}
		valid := true
		for _, c := range state.Interface {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("_.-", c)) {
				valid = false
			}
		}
		for _, id := range state.ProfileIDs {
			if _, err := uuid.Parse(id); err != nil {
				valid = false
			}
		}
		if !valid {
			continue
		}
		state.Address = addr.String()
		state.Error = strings.Map(func(r rune) rune {
			if unicode.IsControl(r) {
				return -1
			}
			return r
		}, state.Error)
		if len(state.Error) > 256 {
			state.Error = state.Error[:256]
		}
		if state.Error != "" {
			state.Ready = false
		}
		out = append(out, state)
	}
	return out
}
