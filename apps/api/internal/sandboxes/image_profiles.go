package sandboxes

import (
	_ "embed"
	"encoding/json"
)

// ImageProfile describes a measured image. It is deliberately not a Template:
// it has no ID, scope or configured resource limits and cannot be launched.
// Measurement limits belong only to the evidence context, not the provider.
type ImageProfile struct {
	Name                         string   `json:"name"`
	Distro                       string   `json:"distro"`
	Architecture                 string   `json:"architecture"`
	ImageDigest                  string   `json:"image_digest"`
	ConfigDigest                 string   `json:"config_digest"`
	CompressedImageBytes         int64    `json:"compressed_image_bytes"`
	UnpackedImageBytes           int64    `json:"unpacked_image_bytes"`
	IdleMemoryBytes              int64    `json:"idle_memory_bytes"`
	EvidenceContext              string   `json:"evidence_context"`
	MeasuredAt                   string   `json:"measured_at"`
	IncludedTools                []string `json:"included_tools"`
	ExcludedTools                []string `json:"excluded_tools"`
	Compatibility                string   `json:"compatibility"`
	Qualification                string   `json:"qualification"`
	Emulated                     bool     `json:"emulated"`
	MeasurementMemoryCapBytes    int64    `json:"measurement_memory_cap_bytes"`
	MeasurementWorkspaceCapBytes int64    `json:"measurement_workspace_cap_bytes"`
}

//go:embed image_profiles.json
var imageProfileJSON []byte

// CandidateImageProfiles returns fresh data so callers cannot mutate the catalog.
// Metadata publication alone never registers a template or changes its gate.
func CandidateImageProfiles() []ImageProfile {
	var profiles []ImageProfile
	if err := json.Unmarshal(imageProfileJSON, &profiles); err != nil {
		panic("invalid compiled sandbox image metadata")
	}
	return profiles
}

// ImageProfileForDigest supplies metadata only for an exact measured immutable
// image. Unknown Ubuntu/native images must remain unspecified, never inferred
// from a template's display name or distro.
func ImageProfileForDigest(digest string) *ImageProfile {
	for _, profile := range CandidateImageProfiles() {
		if profile.ImageDigest == digest || profile.ConfigDigest == digest {
			return &profile
		}
	}
	return nil
}
