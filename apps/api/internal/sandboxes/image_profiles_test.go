package sandboxes

import (
	"strings"
	"testing"
)

func TestCandidateImageProfilesHaveBoundedHonestEvidence(t *testing.T) {
	profiles := CandidateImageProfiles()
	if len(profiles) != 6 {
		t.Fatal("expected three profiles on both architectures")
	}
	seen := map[string]bool{}
	for _, p := range profiles {
		key := p.Name + p.Architecture
		if seen[key] {
			t.Fatal("duplicate profile", key)
		}
		seen[key] = true
		if p.Qualification != "candidate" || len(p.ImageDigest) != 71 || p.ConfigDigest == "" || p.Distro == "" || p.EvidenceContext == "" || p.MeasuredAt == "" {
			t.Fatal("unqualified or missing evidence", key)
		}
		if p.CompressedImageBytes <= 0 || p.UnpackedImageBytes <= p.CompressedImageBytes || p.IdleMemoryBytes <= 0 || p.IdleMemoryBytes >= p.MeasurementMemoryCapBytes {
			t.Fatal("invalid measurements", key)
		}
		if p.Emulated != (p.Architecture == "amd64") || !strings.Contains(p.Compatibility, "musl") {
			t.Fatal("compatibility evidence lost", key)
		}
		if ImageProfileForDigest(p.ImageDigest) == nil || ImageProfileForDigest(p.ConfigDigest) == nil {
			t.Fatal("digest metadata mismatch")
		}
	}
	if ImageProfileForDigest("ubuntu") != nil || ImageProfileForDigest("sha256:"+strings.Repeat("f", 64)) != nil {
		t.Fatal("invented unknown image metadata")
	}
	profiles[0].IncludedTools[0] = "mutated"
	if CandidateImageProfiles()[0].IncludedTools[0] == "mutated" {
		t.Fatal("catalog mutable across callers")
	}
}
