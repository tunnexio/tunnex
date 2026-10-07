package config

import "testing"

func TestBeamConfigDefaultOffAndRestoreFence(t *testing.T) {
	t.Setenv("TUNNEX_BEAM_BASE_DOMAIN", "")
	t.Setenv("TUNNEX_BEAM_PROXY_URL", "")
	t.Setenv("TUNNEX_BEAM_DOMAIN_READY", "")
	c := Load()
	if c.BeamBaseDomain != "" || c.BeamProxyURL != "" || c.BeamDomainReady {
		t.Fatal("Beam mustdefaultoff")
	}
	for _, c := range []Config{{BeamBaseDomain: "beam.example.net"}, {BeamProxyURL: "https://connector.example.net"}} {
		if c.ValidateAppAccessRestoreMarker() == nil {
			t.Fatal("Beam enabledwithoutrestorefence")
		}
		c.AppAccessRestoreMarker = "/private/restore/pending.json"
		if c.ValidateAppAccessRestoreMarker() != nil {
			t.Fatal("absolutefencerefused")
		}
	}
	t.Setenv("TUNNEX_BEAM_BASE_DOMAIN", "beam.example.net")
	t.Setenv("TUNNEX_BEAM_PROXY_URL", "https://connector.example.net")
	t.Setenv("TUNNEX_BEAM_DOMAIN_READY", "true")
	c = Load()
	if c.BeamBaseDomain != "beam.example.net" || c.BeamProxyURL != "https://connector.example.net" || !c.BeamDomainReady {
		t.Fatal("operatorconfigurationignored")
	}
}
