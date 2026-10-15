package control

import (
	"context"
	"encoding/json"
	"github.com/tunnexio/tunnex/apps/node/internal/dnsforward"
	"github.com/tunnexio/tunnex/apps/node/internal/fqdnrpc"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestReportIncludesActualLANListenerFailureAndClearsRetiredState(t *testing.T) {
	var got map[string]json.RawMessage
	c := &Client{base: "https://control.test", http: &http.Client{Transport: ipsecReportTransport(func(r *http.Request) (*http.Response, error) {
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		return &http.Response{StatusCode: 204, Body: io.NopCloser(strings.NewReader(""))}, nil
	})}}
	f := dnsforward.New(nil, nil)
	c.SetDNSForwarder(f)
	f.SetResolverProfiles([]dnsforward.ResolverProfile{{Config: fqdnrpc.ResolverConfig{ID: "11111111-1111-4111-8111-111111111111", Version: 1, ProfileID: "22222222-2222-4222-8222-222222222222"}, ZoneSuffixes: []string{"office.test"}, StaticRecords: []dnsforward.StaticRecord{{Name: "app.office.test", Type: "A", Value: "10.0.0.1", TTL: 300}}, LANListener: &dnsforward.LANListener{Address: "192.168.1.39", Interface: "tnx-missing", AllowedSources: []string{"192.168.1.0/24"}}}})
	f.ReconcileK8sBinds(context.Background(), "tnx-wg-missing")
	defer f.CloseK8sBinds()
	if err := c.ReportInfo(context.Background(), "key", "", false, false, PolicyStatus{}); err != nil {
		t.Fatal(err)
	}
	var states []dnsforward.LANListenerState
	if err := json.Unmarshal(got["dns_lan_listeners"], &states); err != nil {
		t.Fatal(err)
	}
	if len(states) != 1 || states[0].Ready || states[0].Error == "" || len(states[0].ProfileIDs) != 1 {
		t.Fatal("configured listener falsely reported ready", states)
	}
	f.SetResolverProfiles(nil)
	f.ReconcileK8sBinds(context.Background(), "tnx-wg-missing")
	if err := c.ReportInfo(context.Background(), "key", "", false, false, PolicyStatus{}); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(got["dns_lan_listeners"], &states); err != nil || len(states) != 0 {
		t.Fatal("retired listener remained in report", states, err)
	}
}
