package policyspec

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ⛔ S15.3's BINDING CONSTRAINT, MADE EXECUTABLE: NOTHING THE AGENT SURFACE ADDS MAY REACH THE COMPILED
// ARTIFACT.
//
// `hashAllow` is {SrcIP, DstCIDR, Protocol, PortLow, PortHigh}, and `dst_kind` never reaches the agent. That
// measured fact is why the destination half already shipped — and it is also why a descriptive marker is
// invisible to enforcement **by construction rather than by discipline**.
//
// > **THE CHEAPEST PLACE TO BE WRONG IS OUTSIDE THE THING THAT MUST BE RIGHT.** A field the compiler cannot
// > read cannot desync an artifact, cannot bump RequiredVersion, and cannot brick a gateway that has not
// > been updated.
//
// ⚠ This test is a GATE, not a note. The rule "if a design requires touching policyspec, it is the wrong
// design" is only enforceable if something fails when it is broken.
func TestS153MarkersNeverReachTheArtifact(t *testing.T) {
	// The enforcement projection is the whole subject: whatever CanonicalHash hashes IS what the agent
	// enforces on. If a marker appears here, it has reached the artifact.
	b, err := os.ReadFile("hash.go")
	if err != nil {
		t.Fatalf("read hash.go: %v", err)
	}
	hash := string(b)
	for _, forbidden := range []string{"Label", "label", "Kind", "kind"} {
		if strings.Contains(hash, forbidden) {
			t.Fatalf("S15.3: %q appears in the enforcement projection (hash.go) — a descriptive marker has "+
				"reached the compiled artifact. It must be invisible to enforcement BY CONSTRUCTION.", forbidden)
		}
	}

	// ⛔ AND THE COMPILER'S INPUT TYPE STAYS PURE. `ResourceInput` is the compiler's own payload; a
	// descriptive field there would say "this is policy input" to every reader, and only a trip through
	// hash.go would reveal otherwise. The label is passed OUT OF BAND for exactly this reason.
	b, err = os.ReadFile("policyspec.go")
	if err != nil {
		t.Fatalf("read policyspec.go: %v", err)
	}
	spec := string(b)
	start := strings.Index(spec, "type ResourceInput struct")
	if start < 0 {
		t.Fatal("VACUOUS: ResourceInput not found — this gate is measuring nothing")
	}
	end := strings.Index(spec[start:], "}")
	if end < 0 {
		t.Fatal("VACUOUS: could not bound ResourceInput")
	}
	if body := spec[start : start+end]; strings.Contains(body, "Label") {
		t.Fatal("S15.3: ResourceInput carries a Label — the compiler's input type must stay pure; " +
			"pass descriptive values out of band")
	}

	// Vacuity floor: the file we are asserting about must actually contain the thing we claim it bounds.
	if !strings.Contains(hash, "hashAllow") {
		t.Fatal("VACUOUS: hash.go does not contain hashAllow — the walk or the file moved, and this gate " +
			"would pass forever while proving nothing")
	}
	_ = filepath.Base("")
}
