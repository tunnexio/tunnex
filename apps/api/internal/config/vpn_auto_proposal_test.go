package config

import "testing"

func TestProposalVPNAutoRequiresDeploymentOptIn(t *testing.T) {
	t.Setenv("TUNNEX_AI_VPN_AUTO", "")
	if Load().AIVPNAuto {
		t.Fatal("default enabled")
	}
	t.Setenv("TUNNEX_AI_VPN_AUTO", "true")
	if !Load().AIVPNAuto {
		t.Fatal("explicit opt-in missing")
	}
}
