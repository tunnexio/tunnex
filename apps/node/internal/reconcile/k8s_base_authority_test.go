package reconcile

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestKubernetesOwnershipBaseAuthorityStrictDecode(t *testing.T) {
	valid := `{"wire_version":1,"authority_revision":7,"node_id":"99999999-9999-9999-9999-999999999999","org_id":"11111111-1111-1111-1111-111111111111","site_id":"22222222-2222-2222-2222-222222222222","base_version":17,"base_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","classifications":[{"scope":{"org_id":"11111111-1111-1111-1111-111111111111","site_id":"22222222-2222-2222-2222-222222222222","cluster_id":"33333333-3333-3333-3333-333333333333","pool_id":"44444444-4444-4444-4444-444444444444"},"disposition":"arm_fence","fields":{"routes":["10.44.0.0/16"],"wg_peers":[],"vip_mappings":[],"dns_zones":[]}}],"unfenced_pools":[]}`
	var got KubernetesOwnershipBaseAuthority
	if err := json.Unmarshal([]byte(valid), &got); err != nil {
		t.Fatal(err)
	}
	if got.AuthorityRevision != 7 || len(got.Classifications) != 1 {
		t.Fatalf("decoded authority=%+v", got)
	}

	tests := []struct {
		name string
		raw  string
		want string
	}{
		{name: "unknown top-level", raw: strings.Replace(valid, `"unfenced_pools":[]`, `"unfenced_pools":[],"future":true`, 1), want: "unknown field"},
		{name: "unknown nested", raw: strings.Replace(valid, `"disposition":"arm_fence"`, `"disposition":"arm_fence","future":true`, 1), want: "unknown field"},
		{name: "duplicate top-level", raw: strings.Replace(valid, `"wire_version":1`, `"wire_version":1,"wire_version":1`, 1), want: "duplicate"},
		{name: "duplicate nested", raw: strings.Replace(valid, `"pool_id":"44444444-4444-4444-4444-444444444444"`, `"pool_id":"44444444-4444-4444-4444-444444444444","pool_id":"44444444-4444-4444-4444-444444444444"`, 1), want: "duplicate"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var decoded KubernetesOwnershipBaseAuthority
			err := json.Unmarshal([]byte(test.raw), &decoded)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("err=%v want substring %q", err, test.want)
			}
		})
	}
}

func TestDesiredStateAuthorityIsOptional(t *testing.T) {
	var desired DesiredState
	if err := json.Unmarshal([]byte(`{"protocol_version":1,"node_id":"99999999-9999-9999-9999-999999999999","version":1}`), &desired); err != nil {
		t.Fatal(err)
	}
	if desired.KubernetesOwnershipBaseAuthority != nil {
		t.Fatalf("legacy desired state unexpectedly gained authority: %+v", desired.KubernetesOwnershipBaseAuthority)
	}
}
