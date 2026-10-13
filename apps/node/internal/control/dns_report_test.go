package control

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestReportSeparatelyGatesIPsecResolverTransport(t *testing.T) {
	var got map[string]json.RawMessage
	c := &Client{base: "https://control.test", http: &http.Client{Transport: ipsecReportTransport(func(r *http.Request) (*http.Response, error) {
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		return &http.Response{StatusCode: 204, Body: io.NopCloser(strings.NewReader(""))}, nil
	})}}
	for _, ipsecVersion := range []int{0, 1} {
		if err := c.ReportInfo(context.Background(), "key", "", false, false, PolicyStatus{DNSResolveRPCVersion: 2, DNSIPsecResolveVersion: ipsecVersion}); err != nil {
			t.Fatal(err)
		}
		if string(got["dns_resolve_rpc_version"]) != "2" || string(got["dns_ipsec_resolve_version"]) != string(rune('0'+ipsecVersion)) {
			t.Fatal("IPsec transport collapsed into legacy RPC compatibility", got)
		}
	}
}
