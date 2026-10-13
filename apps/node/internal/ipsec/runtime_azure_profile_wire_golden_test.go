package ipsec

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"testing"
)

// These fixed bytes/hashes are produced by the independent API wire fixture,
// not generated from the consumer's RuntimeManifest. They prove serialization
// compatibility only, never journal lineage or native readiness.
func TestAzureProfileRecreationConsumesIndependentAPIGolden(t *testing.T) {
	raw, err := os.ReadFile("testdata/api_azure_profile_recreation_manifest_golden.json")
	if err != nil {
		t.Fatal(err)
	}
	var rows []struct {
		Name     string          `json:"name"`
		Manifest json.RawMessage `json:"manifest"`
		SHA256   string          `json:"sha256"`
	}
	if json.Unmarshal(raw, &rows) != nil || len(rows) != 4 {
		t.Fatal("producer fixture shape")
	}
	seen := map[string]bool{}
	for _, r := range rows {
		t.Run(r.Name, func(t *testing.T) {
			var m RuntimeManifest
			dec := json.NewDecoder(bytes.NewReader(r.Manifest))
			dec.DisallowUnknownFields()
			if dec.Decode(&m) != nil || dec.Decode(new(any)) != io.EOF || m.ProfileID != r.Name || seen[r.Name] || !validAzureRecreationManifest(m) {
				t.Fatal("literal producer manifest refused")
			}
			seen[r.Name] = true
			encoded, err := json.Marshal(m)
			if err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256(encoded)
			if hex.EncodeToString(sum[:]) != r.SHA256 {
				t.Fatal("producer ownership digest differs")
			}
			var compact bytes.Buffer
			if json.Compact(&compact, r.Manifest) != nil || !bytes.Equal(encoded, compact.Bytes()) {
				t.Fatal("producer canonical bytes differ")
			}
			if m.AzureProfileRecreationVersion == nil || *m.AzureProfileRecreationVersion != 1 || m.AzureBGPRecreationVersion != nil {
				t.Fatal("cross-profile opt-in inferred")
			}
			m.AzureProfileRecreationVersion = nil
			legacy, err := json.Marshal(m)
			if err != nil || bytes.Contains(legacy, []byte("azure_profile_recreation_version")) {
				t.Fatal("omitted legacy field serialized")
			}
		})
	}
}
