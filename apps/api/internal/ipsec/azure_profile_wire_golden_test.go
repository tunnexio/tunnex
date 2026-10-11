package ipsec

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
)

// These frozen literal bytes extend the independently assembled four-profile
// schema fixtures. RuntimeHash and node constructors never generate expectations.
func TestAPIAzureProfileRecreationWireGolden(t *testing.T) {
	raw, e := os.ReadFile("testdata/api_azure_profile_recreation_manifest_golden.json")
	if e != nil {
		t.Fatal(e)
	}
	var rows []struct {
		Name     string          `json:"name"`
		Manifest json.RawMessage `json:"manifest"`
		SHA256   string          `json:"sha256"`
	}
	if json.Unmarshal(raw, &rows) != nil || len(rows) != 4 {
		t.Fatal("fixture shape")
	}
	for _, row := range rows {
		t.Run(row.Name, func(t *testing.T) {
			var m RuntimeManifest
			if json.Unmarshal(row.Manifest, &m) != nil || m.AzureProfileRecreationVersion == nil || *m.AzureProfileRecreationVersion != 1 || m.AzureBGPRecreationVersion != nil || len(m.RetainedGuardPredecessors) != 1 {
				t.Fatal("fixture contract")
			}
			var expected bytes.Buffer
			if e = json.Compact(&expected, row.Manifest); e != nil {
				t.Fatal(e)
			}
			actual, digest := runtimeHash(m)
			if !bytes.Equal(actual, expected.Bytes()) || digest != row.SHA256 {
				t.Fatal("profile recreation canonical wire changed")
			}
		})
	}
}
