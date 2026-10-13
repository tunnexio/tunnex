package control

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/node/internal/ipsec"
)

// The bounded strict HTTP decoder recognizes the optional field. Runtime
// admission still independently checks version, profile and retained history.
func TestAzureProfileRecreationMaterialWireOptionalAndStrict(t *testing.T) {
	for _, explicit := range []bool{false, true} {
		t.Run(map[bool]string{false: "legacy_omitted", true: "explicit_one"}[explicit], func(t *testing.T) {
			m := ipsec.RuntimeMaterial{}
			if explicit {
				one := 1
				m.Manifest.AzureProfileRecreationVersion = &one
			}
			raw, err := json.Marshal(m)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(raw), `"azure_profile_recreation_version"`) != explicit {
				t.Fatal("optional wire changed")
			}
			c := &Client{base: "https://cp.test", http: &http.Client{Transport: ipsecRoundTrip(func(r *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(string(raw)))}, nil
			})}}
			got, err := c.IPsecMaterial(context.Background(), uuid.New(), 1)
			if err != nil {
				t.Fatal(err)
			}
			if explicit && (got.Manifest.AzureProfileRecreationVersion == nil || *got.Manifest.AzureProfileRecreationVersion != 1) {
				t.Fatal("explicit version lost")
			}
			if !explicit && got.Manifest.AzureProfileRecreationVersion != nil {
				t.Fatal("legacy opted in")
			}
			round, err := json.Marshal(got)
			if err != nil || string(round) != string(raw) {
				t.Fatal("wire not preserved")
			}
		})
	}
	for _, raw := range []string{`{"manifest":{"azure_profile_recreation_capability":1}}`, `{"manifest":{"azure_profile_recreation_version":"1"}}`, `{"manifest":{"azure_profile_recreation_version":1}} {}`} {
		c := &Client{base: "https://cp.test", http: &http.Client{Transport: ipsecRoundTrip(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(raw))}, nil
		})}}
		if _, err := c.IPsecMaterial(context.Background(), uuid.New(), 1); err == nil {
			t.Fatal("alias, malformed or trailing payload accepted")
		}
	}
}
