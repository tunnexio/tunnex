package ipsec

import (
	"encoding/json"
	"testing"
)

func TestDesktopStaticTransportManifestContract(t *testing.T) {
	var base RuntimeManifest
	if err := json.Unmarshal([]byte(recoveryManifestLegacyGolden), &base); err != nil {
		t.Fatal(err)
	}
	one := 1
	base.RecoveryVersion = &one
	base.DesktopStaticVersion = &one
	if !runtimeDesktopStaticCompatible(base, true) {
		t.Fatal("qualified contract refused")
	}
	for name, mutate := range map[string]func(*RuntimeManifest){
		"future":            func(m *RuntimeManifest) { v := 2; m.DesktopStaticVersion = &v },
		"transport version": func(m *RuntimeManifest) { m.TransportVersion = &one },
		"tunnel count":      func(m *RuntimeManifest) { m.TunnelCount = &one },
		"missing recovery":  func(m *RuntimeManifest) { m.RecoveryVersion = nil },
		"future recovery":   func(m *RuntimeManifest) { v := 2; m.RecoveryVersion = &v },
		"BGP":               func(m *RuntimeManifest) { m.BGP = &BGPConfig{} },
		"BGP version":       func(m *RuntimeManifest) { m.BGPVersion = &one },
		"other provider":    func(m *RuntimeManifest) { m.ProfileID = GCPClassicProfile },
	} {
		t.Run(name, func(t *testing.T) {
			m := base
			mutate(&m)
			if runtimeDesktopStaticCompatible(m, true) {
				t.Fatal("invalid transport contract accepted")
			}
		})
	}
	if runtimeDesktopStaticCompatible(base, false) {
		t.Fatal("old gateway received static transport marker")
	}
	_, marked := runtimeHash(base)
	base.DesktopStaticVersion = nil
	_, legacy := runtimeHash(base)
	if marked == legacy || !runtimeDesktopStaticCompatible(base, false) {
		t.Fatal("legacy digest or admission changed")
	}
}
