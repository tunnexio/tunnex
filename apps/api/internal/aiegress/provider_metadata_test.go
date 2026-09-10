package aiegress

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEndpointProviderMetadata(t *testing.T) {
	for _, kind := range []string{"", "custom", "sagemaker", "openai"} {
		p := filepath.Join(t.TempDir(), "policy.json")
		data := `{"endpoints":[{"name":"Endpoint","provider":"` + kind + `","url":"http://endpoint.example","allowed_cidrs":["10.0.0.0/8"]}],"protected_hosts":["control.invalid"]}`
		if err := os.WriteFile(p, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		policy, err := LoadPolicy(p)
		if kind == "openai" {
			if err == nil {
				t.Fatal("unsupported endpoint type")
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		want := kind
		if want == "" {
			want = "custom"
		}
		if policy.Endpoints[0].Provider != want {
			t.Fatal("wrong default")
		}
	}
}
