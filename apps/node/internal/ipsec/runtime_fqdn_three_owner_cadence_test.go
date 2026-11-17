package ipsec

import (
	"testing"
	"time"
)

// The three-short case retains the original 13-second starting window. The
// live-shaped case has four descriptors per owner (two devices and two ALB
// answers), with 60-second BGP DNS metadata and 30-second static metadata.
// Neither case changes the original finite native deadline during refresh.
func TestFQDNThreeOwnerCadence(t *testing.T) {
	for _, variant := range []string{"three-short", "live"} {
		t.Run(variant, func(t *testing.T) {
			for seconds := 0; seconds < 15; seconds++ {
				phase := time.Duration(seconds) * time.Second
				t.Run(phase.String(), func(t *testing.T) { testFQDNMultiOwnerCadence(t, phase, variant) })
			}
		})
	}
}
