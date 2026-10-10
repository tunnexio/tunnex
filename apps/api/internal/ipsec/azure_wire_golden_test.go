package ipsec

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
)

// Frozen literal fixtures were independently assembled from the documented wire
// schema, not node constructors or runtimeHash. Tests never rewrite fixtures.
func TestAPIAzureRuntimeManifestWireGolden(t *testing.T) {
	raw, err := os.ReadFile("testdata/api_azure_runtime_manifest_golden.json")
	if err != nil {
		t.Fatal(err)
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
			var reference RuntimeManifest
			if json.Unmarshal(row.Manifest, &reference) != nil {
				t.Fatal("reference decode")
			}
			c := Connection{OrgID: reference.OrgID, ID: reference.ConnectionID, HistoricalGatewayNodeID: reference.NodeID, HistoricalSiteID: reference.SiteID, DesiredRevision: reference.DesiredRevision}
			cfg := StaticConfig{ProfileID: row.Name, CustomerOutsideAddress: reference.CustomerOutsideAddress, LocalPrefixes: reference.LocalPrefixes, RemotePrefixes: reference.RemotePrefixes, BGP: reference.BGP}
			actual := runtimeManifest(c, cfg, reference.Tunnels)
			canonical, digest := runtimeHash(actual)
			var expected []byte
			buffer := new(bytes.Buffer)
			if err := json.Compact(buffer, row.Manifest); err != nil {
				t.Fatal(err)
			}
			expected = buffer.Bytes()
			if string(canonical) != string(expected) || digest != row.SHA256 {
				t.Fatalf("%s producer canonical wire changed", row.Name)
			}
		})
	}
}
