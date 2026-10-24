package nodes

import (
	"encoding/json"
	"testing"
)

func TestDesktopStaticCapabilityExplicitRecoveryQualification(t *testing.T) {
	for _, c := range []struct{ transit, recovery, reported, want int }{{1, 1, 1, 1}, {0, 1, 1, 0}, {1, 0, 1, 0}, {1, 1, 0, 0}, {1, 1, 2, 0}, {1, 1, -1, 0}, {2, 1, 1, 0}} {
		if got := ipsecDesktopStaticCapability(c.transit, c.recovery, c.reported); got != c.want {
			t.Fatalf("%+v got%d", c, got)
		}
	}
	for _, raw := range []string{`{"ipsec_desktop_static_version":"1"}`, `{"ipsec_desktop_static_version":true}`} {
		var p AppliedPolicy
		if json.Unmarshal([]byte(raw), &p) == nil {
			t.Fatal("untyped static capability accepted")
		}
	}
	var caps NodeCapabilities
	if e := json.Unmarshal([]byte(`{"ipsec_desktop_static_version":1}`), &caps); e != nil || caps.IPsecDesktopStaticVersion != 1 {
		t.Fatal("static report lost", e)
	}
}
