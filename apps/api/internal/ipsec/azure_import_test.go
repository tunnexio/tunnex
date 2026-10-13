package ipsec

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestAzureImportAndPerPeerSettingsNeverExportSecrets(t *testing.T) {
	c := azureFixture(AzureActiveActiveBGPProfile)
	raw, _ := json.Marshal(c)
	var v map[string]any
	json.Unmarshal(raw, &v)
	for i, entry := range v["tunnels"].([]any) {
		entry.(map[string]any)["psk"] = c.Tunnels[i].PSK
	}
	raw, _ = json.Marshal(v)
	got, err := ImportAzureConfiguration(raw)
	if err != nil {
		t.Fatal(err)
	}
	settings, err := GenerateAzurePeerSettings(got)
	if err != nil || len(settings) != 2 || settings[0].AzureBGPAddress == settings[1].AzureBGPAddress {
		t.Fatal("per peer settings mismatch", err)
	}
	projection, _ := json.Marshal(settings)
	if strings.Contains(string(projection), "psk") || strings.Contains(string(projection), c.Tunnels[0].PSK) {
		t.Fatal("secret export")
	}
	if _, err = ImportAzureConfiguration([]byte(`{"profile_id":"azure-active-active-bgp-ipv4-v1","profile_id":"azure-policy-based"}`)); err == nil {
		t.Fatal("duplicate key accepted")
	}
	v["unknown"] = true
	raw, _ = json.Marshal(v)
	if _, err = ImportAzureConfiguration(raw); err == nil {
		t.Fatal("unknown field accepted")
	}
	if _, err = ImportAzureConfiguration([]byte(`{"profile_id":"azure-policy-based"}`)); err == nil {
		t.Fatal("unsupported import accepted")
	}
}
