package ipsec

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
)

// This fixed wire fixture is shared with the node compatibility regression.
const recoveryManifestLegacyGolden = `{"org_id":"00000000-0000-0000-0000-000000000001","node_id":"00000000-0000-0000-0000-000000000002","site_id":"00000000-0000-0000-0000-000000000003","connection_id":"00000000-0000-0000-0000-000000000004","desired_revision":1,"configuration_revision":1,"profile_id":"aws-static-ipv4-v1","customer_outside_address":"192.0.2.1","local_prefixes":["10.10.0.0/24"],"remote_prefixes":["10.20.0.0/24"],"tunnels":[{"id":"00000000-0000-0000-0000-000000000005","slot":1,"secret_revision":1,"link_name":"tunnel1","xfrm_id":101,"reqid":101,"outside_address":"198.51.100.1","inside_cidr":"169.254.20.0/30","customer_inside_address":"169.254.20.1","cloud_inside_address":"169.254.20.2","route_table":254,"route_protocol":242,"route_metric":50001,"selected":true},{"id":"00000000-0000-0000-0000-000000000006","slot":2,"secret_revision":1,"link_name":"tunnel2","xfrm_id":102,"reqid":102,"outside_address":"198.51.100.2","inside_cidr":"169.254.20.4/30","customer_inside_address":"169.254.20.5","cloud_inside_address":"169.254.20.6","route_table":254,"route_protocol":242,"route_metric":50002,"selected":false}]}`

func TestRecoveryManifestCanonicalCompatibility(t *testing.T) {
	var m RuntimeManifest
	if err := json.Unmarshal([]byte(recoveryManifestLegacyGolden), &m); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(m)
	if err != nil || string(raw) != recoveryManifestLegacyGolden {
		t.Fatal("legacy CP bytes changed", err)
	}
	digest := sha256.Sum256(raw)
	if hex.EncodeToString(digest[:]) != "6b58b1044ed54edf76631157e96174a6b1a9fd5fa74f7532a3de3b9bc320cb40" {
		t.Fatal("legacy CP digest differs from node")
	}
	version := 1
	m.RecoveryVersion = &version
	raw, err = json.Marshal(m)
	want := recoveryManifestLegacyGolden[:len(recoveryManifestLegacyGolden)-1] + `,"recovery_version":1}`
	if err != nil || string(raw) != want {
		t.Fatal("CP recovery shape differs from node", err)
	}
}
