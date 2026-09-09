package icewire

import (
	"testing"

	"github.com/pion/ice/v4"
)

func TestCandidatePath(t *testing.T) {
	types := []ice.CandidateType{ice.CandidateType(0), ice.CandidateTypeHost, ice.CandidateTypeServerReflexive, ice.CandidateTypePeerReflexive, ice.CandidateTypeRelay}
	// Cover both perspectives: a relay on either side is relay; an unknown
	// or peer-reflexive side must not be advertised as direct.
	want := [][]string{
		{"unknown", "unknown", "unknown", "unknown", "relay"},
		{"unknown", "direct", "direct", "unknown", "relay"},
		{"unknown", "direct", "direct", "unknown", "relay"},
		{"unknown", "unknown", "unknown", "unknown", "relay"},
		{"relay", "relay", "relay", "relay", "relay"},
	}
	for i, local := range types {
		for j, remote := range types {
			if got := candidatePath(local, remote); got != want[i][j] {
				t.Errorf("%v/%v: got %s, want %s", local, remote, got, want[i][j])
			}
		}
	}
}
