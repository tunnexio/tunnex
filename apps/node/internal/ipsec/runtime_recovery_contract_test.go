package ipsec

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
)

// Fixed pre-recovery wire shape: this fixture deliberately pins legacy field
// order and bytes, independently of the current Go type's marshal behavior.
const legacyRecoveryManifestGolden = `{"org_id":"00000000-0000-0000-0000-000000000001","node_id":"00000000-0000-0000-0000-000000000002","site_id":"00000000-0000-0000-0000-000000000003","connection_id":"00000000-0000-0000-0000-000000000004","desired_revision":1,"configuration_revision":1,"profile_id":"aws-static-ipv4-v1","customer_outside_address":"192.0.2.1","local_prefixes":["10.10.0.0/24"],"remote_prefixes":["10.20.0.0/24"],"tunnels":[{"id":"00000000-0000-0000-0000-000000000005","slot":1,"secret_revision":1,"link_name":"tunnel1","xfrm_id":101,"reqid":101,"outside_address":"198.51.100.1","inside_cidr":"169.254.20.0/30","customer_inside_address":"169.254.20.1","cloud_inside_address":"169.254.20.2","route_table":254,"route_protocol":242,"route_metric":50001,"selected":true},{"id":"00000000-0000-0000-0000-000000000006","slot":2,"secret_revision":1,"link_name":"tunnel2","xfrm_id":102,"reqid":102,"outside_address":"198.51.100.2","inside_cidr":"169.254.20.4/30","customer_inside_address":"169.254.20.5","cloud_inside_address":"169.254.20.6","route_table":254,"route_protocol":242,"route_metric":50002,"selected":false}]}`
const legacyRecoveryManifestSHA256 = "6b58b1044ed54edf76631157e96174a6b1a9fd5fa74f7532a3de3b9bc320cb40"

func TestRuntimeRecoveryContract(t *testing.T) {
	if enabled, err := runtimeRecoveryContract(RuntimeManifest{}); enabled || err != nil {
		t.Fatal("absent contract must remain legacy", enabled, err)
	}
	for _, v := range []int{-1, 0, 1, 2, 99} {
		enabled, err := runtimeRecoveryContract(RuntimeManifest{RecoveryVersion: &v})
		if v == 1 {
			if !enabled || err != nil {
				t.Fatal("known contract not recognized", enabled, err)
			}
		} else if enabled || err == nil {
			t.Fatalf("unsupported contract %d accepted", v)
		}
	}
}

func TestRuntimeRecoveryLegacyCanonicalDigest(t *testing.T) {
	var m RuntimeManifest
	if err := json.Unmarshal([]byte(legacyRecoveryManifestGolden), &m); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(m)
	if err != nil || string(raw) != legacyRecoveryManifestGolden {
		t.Fatal("legacy canonical bytes changed", err)
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != legacyRecoveryManifestSHA256 {
		t.Fatal("legacy digest changed")
	}
	one := 1
	m.RecoveryVersion = &one
	raw, err = json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	want := legacyRecoveryManifestGolden[:len(legacyRecoveryManifestGolden)-1] + `,"recovery_version":1}`
	if string(raw) != want {
		t.Fatal("recovery contract not appended canonically")
	}
	withRecovery := sha256.Sum256(raw)
	if sum == withRecovery {
		t.Fatal("recovery authorization not bound into digest")
	}
	two := 2
	m.RecoveryVersion = &two
	changed, _ := json.Marshal(m)
	if sha256.Sum256(changed) == withRecovery {
		t.Fatal("version change left digest unchanged")
	}
	m.RecoveryVersion = nil
	restored, _ := json.Marshal(m)
	if !bytes.Equal(restored, []byte(legacyRecoveryManifestGolden)) {
		t.Fatal("legacy bytes not restored")
	}
}

func TestRuntimeRecoveryOldStrictDecoderRefusesAuthorization(t *testing.T) {
	// Model the old decoder's exact manifest vocabulary, not the extended type.
	var old struct {
		OrgID                  json.RawMessage `json:"org_id"`
		NodeID                 json.RawMessage `json:"node_id"`
		SiteID                 json.RawMessage `json:"site_id"`
		ConnectionID           json.RawMessage `json:"connection_id"`
		DesiredRevision        json.RawMessage `json:"desired_revision"`
		ConfigurationRevision  json.RawMessage `json:"configuration_revision"`
		ProfileID              json.RawMessage `json:"profile_id"`
		CustomerOutsideAddress json.RawMessage `json:"customer_outside_address"`
		LocalPrefixes          json.RawMessage `json:"local_prefixes"`
		RemotePrefixes         json.RawMessage `json:"remote_prefixes"`
		Tunnels                json.RawMessage `json:"tunnels"`
	}
	legacy := json.NewDecoder(bytes.NewBufferString(legacyRecoveryManifestGolden))
	legacy.DisallowUnknownFields()
	if err := legacy.Decode(&old); err != nil {
		t.Fatal("legacy fixture not accepted", err)
	}
	extended := legacyRecoveryManifestGolden[:len(legacyRecoveryManifestGolden)-1] + `,"recovery_version":1}`
	decoder := json.NewDecoder(bytes.NewBufferString(extended))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&old); err == nil {
		t.Fatal("old decoder accepted recovery intent")
	}
}

func TestRuntimeRecoveryNullDoesNotGrantAuthority(t *testing.T) {
	raw := legacyRecoveryManifestGolden[:len(legacyRecoveryManifestGolden)-1] + `,"recovery_version":null}`
	var m RuntimeManifest
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		t.Fatal(err)
	}
	if enabled, err := runtimeRecoveryContract(m); enabled || err != nil {
		t.Fatal("null granted recovery", enabled, err)
	}
}
