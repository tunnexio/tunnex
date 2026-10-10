package ipsec

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
)

// Preparation only, no networking. Writes fresh disposable credentials to a new
// private directory, never stdout; the caller supplies the owned native peers.
func TestDNSOwnerViewGCPComponentPrepare(t *testing.T) {
	directory := os.Getenv("TUNNEX_GCP_DNS_OWNER_PREPARE_DIR")
	if directory == "" {
		t.Skip("explicit private fixture preparation only")
	}
	if !filepath.IsAbs(directory) {
		t.Fatal("absolute new private directory required")
	}
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal("new private directory required", err)
	}
	for _, profile := range []string{GCPClassicStaticProfile, GCPHABGPProfile} {
		m := classicMaterialFixture()
		if profile == GCPHABGPProfile {
			m = gcpMaterialFixture()
		}
		count, err := runtimeMaterialTransportContract(m)
		if err != nil {
			t.Fatal(err)
		}
		m.Manifest.CustomerOutsideAddress = "198.18.222.10"
		for i := 0; i < count; i++ {
			m.Manifest.Tunnels[i].OutsideAddress = []string{"198.18.222.20", "198.18.222.21"}[i]
			secret := make([]byte, 16)
			if _, err = rand.Read(secret); err != nil {
				t.Fatal("disposable entropy unavailable")
			}
			m.Secrets[i].PSK = "0-" + hex.EncodeToString(secret)
		}
		m.Policy.Grants = nil
		m.Policy.DNSResolverGrants = []RuntimeDNSResolverGrant{{ContextConfigID: uuid.New(), ContextConfigVersion: 1, ProfileID: uuid.New(), ConnectionID: m.Manifest.ConnectionID, ConfigurationRevision: m.Manifest.ConfigurationRevision, SourceAddress: "10.10.0.1", ResolverAddress: "10.20.0.53"}}
		runtimeReseal(&m)
		if _, _, err = runtimeMaterialEntry(m, m.Manifest.OrgID, m.Manifest.NodeID, "net:[4026531992]"); err != nil {
			t.Fatal("generated component material invalid", err)
		}
		raw, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(directory, profile+".json"), append(raw, '\n'), 0600); err != nil {
			t.Fatal("private material write refused", err)
		}
	}
}
