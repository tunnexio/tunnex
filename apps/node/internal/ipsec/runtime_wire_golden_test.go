package ipsec

import (
	"bytes"
	"encoding/json"
	"github.com/google/uuid"
	"os"
	"testing"
)

// The input bytes/digests are emitted independently by the API's actual typed
// manifest. Hashing a node-generated fixture would miss field-order drift.
func TestRuntimeManifestAPIGoldenWire(t *testing.T) {
	raw, err := os.ReadFile("testdata/api_runtime_manifest_golden.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		Name     string          `json:"name"`
		Manifest json.RawMessage `json:"manifest"`
		SHA256   string          `json:"sha256"`
	}
	if json.Unmarshal(raw, &cases) != nil || len(cases) != 3 {
		t.Fatal("invalid independent API fixture")
	}
	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			var m RuntimeManifest
			if json.Unmarshal(tc.Manifest, &m) != nil {
				t.Fatal("decode API manifest")
			}
			encoded, err := json.Marshal(m)
			var canonical bytes.Buffer
			if err != nil || json.Compact(&canonical, tc.Manifest) != nil || !bytes.Equal(encoded, canonical.Bytes()) {
				t.Fatal("node reserialized bytes differ from API manifest")
			}
			d := RuntimeDelivery{ID: uuid.MustParse("eeeeeeee-0000-0000-0000-000000000001"), DesiredRevision: m.DesiredRevision, Kind: "apply", OwnershipDigest: tc.SHA256, Manifest: m}
			if !runtimeDeliveryValid(d, m.OrgID, m.NodeID, "apply") {
				t.Fatal("API-produced delivery digest refused")
			}
			d.Manifest.DesiredRevision++
			if runtimeDeliveryValid(d, m.OrgID, m.NodeID, "apply") {
				t.Fatal("changed intent admitted with old digest")
			}
		})
	}
}
