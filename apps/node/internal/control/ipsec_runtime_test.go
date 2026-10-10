package control

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/node/internal/ipsec"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

type ipsecRoundTrip func(*http.Request) (*http.Response, error)

func (f ipsecRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestIPsecRuntimeTransportBoundedRedacted(t *testing.T) {
	for _, test := range []struct {
		name, body string
		status     int
	}{{"error", "private-secret-marker", 500}, {"unknown", `{"items":[],"secret":"private-secret-marker"}`, 200}, {"trailing", `{"items":[]} {}`, 200}, {"oversize", strings.Repeat("x", (1<<20)+1), 200}} {
		t.Run(test.name, func(t *testing.T) {
			c := &Client{base: "https://cp.test", http: &http.Client{Transport: ipsecRoundTrip(func(r *http.Request) (*http.Response, error) {
				if _, ok := r.Context().Deadline(); !ok {
					t.Error("unbounded request")
				}
				return &http.Response{StatusCode: test.status, Body: io.NopCloser(strings.NewReader(test.body)), Header: http.Header{}}, nil
			})}}
			_, err := c.IPsecPending(context.Background(), nil, 50)
			if err == nil || strings.Contains(err.Error(), "private-secret-marker") {
				t.Fatal("invalid response accepted/reflected")
			}
		})
	}
}
func TestIPsecRuntimeTransportPathAndCancellation(t *testing.T) {
	id := uuid.New()
	calls := 0
	c := &Client{base: "https://cp.test", http: &http.Client{Transport: ipsecRoundTrip(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.Path != "/agent/ipsec/connections/"+id.String()+"/material" || r.Method != "POST" {
			t.Error("wrong path")
		}
		b, _ := io.ReadAll(r.Body)
		if string(b) != `{"desired_revision":7}` {
			t.Error("wrong body")
		}
		return nil, errors.New("private-secret-marker")
	})}}
	_, err := c.IPsecMaterial(context.Background(), id, 7)
	if err == nil || strings.Contains(err.Error(), "private-secret-marker") || calls != 1 {
		t.Fatal("transport error reflected")
	}
	_, err = c.IPsecMaterial(context.Background(), uuid.Nil, 7)
	if err == nil || calls != 1 {
		t.Fatal("invalid identity sent")
	}
}
func TestIPsecRuntimeTransportAcknowledgement204(t *testing.T) {
	c := &Client{base: "https://cp.test", http: &http.Client{Transport: ipsecRoundTrip(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 204, Body: io.NopCloser(strings.NewReader("")), Header: http.Header{}}, nil
	})}}
	if e := c.IPsecAcknowledge(context.Background(), uuid.New(), ipsec.RuntimeAcknowledgement{}); e != nil {
		t.Fatal(e)
	}
}
func TestIPsecRuntimeTransportNeverFollowsRedirect(t *testing.T) {
	calls := 0
	c := &Client{base: "https://cp.test", http: &http.Client{Transport: ipsecRoundTrip(func(r *http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: 307, Body: io.NopCloser(strings.NewReader("")), Header: http.Header{"Location": []string{"https://other.test/private"}}}, nil
	})}}
	if _, e := c.IPsecMaterial(context.Background(), uuid.New(), 1); e == nil || calls != 1 {
		t.Fatal("followed redirect")
	}
}
func TestIPsecRuntimeTransportRejectsPlaintext(t *testing.T) {
	calls := 0
	c := &Client{base: "http://cp.test", http: &http.Client{Transport: ipsecRoundTrip(func(r *http.Request) (*http.Response, error) { calls++; return nil, errors.New("unexpected") })}}
	if _, e := c.IPsecMaterial(context.Background(), uuid.New(), 1); e == nil || calls != 0 {
		t.Fatal("secret endpoint allowed plaintext")
	}
}

func TestIPsecRuntimeStatusTransportExactBody(t *testing.T) {
	id := uuid.New()
	report := ipsec.RuntimeStatusReport{DeliveryID: uuid.New(), DesiredRevision: 7, ConfigurationRevision: 1, Tunnels: [2]ipsec.RuntimeTunnelStatus{{ID: uuid.New(), Slot: 1, Status: "up", Selected: true}, {ID: uuid.New(), Slot: 2, Status: "unknown"}}}
	calls := 0
	c := &Client{base: "https://cp.test", http: &http.Client{Transport: ipsecRoundTrip(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method != "POST" || r.URL.Path != "/agent/ipsec/connections/"+id.String()+"/status" {
			t.Fatal("wrong status endpoint")
		}
		var got ipsec.RuntimeStatusReport
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if decoder.Decode(&got) != nil || got != report {
			t.Fatal("wrong report body")
		}
		return &http.Response{StatusCode: 204, Body: io.NopCloser(strings.NewReader("")), Header: http.Header{}}, nil
	})}}
	if e := c.IPsecReportStatus(context.Background(), id, report); e != nil || calls != 1 {
		t.Fatal("status transport failed", e)
	}
	report.Tunnels[1].Status = "applied"
	if c.IPsecReportStatus(context.Background(), id, report) == nil || calls != 1 {
		t.Fatal("unsupported status sent")
	}
}

func bgpTransportReport() ipsec.RuntimeStatusReport {
	return ipsec.RuntimeStatusReport{DeliveryID: uuid.New(), DesiredRevision: 2, ConfigurationRevision: 1, Tunnels: [2]ipsec.RuntimeTunnelStatus{{ID: uuid.New(), Slot: 1, Status: "up"}, {ID: uuid.New(), Slot: 2, Status: "up"}}, BGP: &ipsec.RuntimeBGPStatus{Version: 1, Sequence: 5, Peers: [2]ipsec.RuntimeBGPPeerStatus{{Slot: 1, State: "established", AcceptedPrefixes: 1, InstalledPrefixes: 1}, {Slot: 2, State: "established", AcceptedPrefixes: 1, InstalledPrefixes: 1}}, Routes: []ipsec.RuntimeBGPRoute{{Prefix: "10.20.0.0/24", Slot: 1}, {Prefix: "10.30.0.0/24", Slot: 2}}}}
}
func TestIPsecBGPStatusTransportExactBody(t *testing.T) {
	report := bgpTransportReport()
	calls := 0
	id := uuid.New()
	c := &Client{base: "https://cp.test", http: &http.Client{Transport: ipsecRoundTrip(func(r *http.Request) (*http.Response, error) {
		calls++
		var got ipsec.RuntimeStatusReport
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if decoder.Decode(&got) != nil || !reflect.DeepEqual(got, report) {
			t.Fatal("BGP exact typed status changed")
		}
		return &http.Response{StatusCode: 204, Body: io.NopCloser(strings.NewReader(""))}, nil
	})}}
	if err := c.IPsecReportStatus(context.Background(), id, report); err != nil || calls != 1 {
		t.Fatal("both-unselected BGP report not sent", err)
	}
	report.BGP = nil
	if err := c.IPsecReportStatus(context.Background(), id, report); err != nil || calls != 2 {
		t.Fatal("honest missing BGP measurements refused", err)
	}
}
func TestIPsecBGPStatusTransportRefusesMalformed(t *testing.T) {
	for name, mutate := range map[string]func(*ipsec.RuntimeStatusReport){
		"static preference":     func(r *ipsec.RuntimeStatusReport) { r.Tunnels[0].Selected = true },
		"mixed recovery":        func(r *ipsec.RuntimeStatusReport) { v := 1; r.RecoveryVersion = &v },
		"global path":           func(r *ipsec.RuntimeStatusReport) { v := 1; r.ActiveSlot = &v },
		"unknown version":       func(r *ipsec.RuntimeStatusReport) { r.BGP.Version = 2 },
		"unsafe sequence":       func(r *ipsec.RuntimeStatusReport) { r.BGP.Sequence = 9007199254740992 },
		"null routes":           func(r *ipsec.RuntimeStatusReport) { r.BGP.Routes = nil },
		"noncanonical prefix":   func(r *ipsec.RuntimeStatusReport) { r.BGP.Routes[0].Prefix = "10.20.0.1/24" },
		"duplicate prefix":      func(r *ipsec.RuntimeStatusReport) { r.BGP.Routes[1] = r.BGP.Routes[0] },
		"invalid slot":          func(r *ipsec.RuntimeStatusReport) { r.BGP.Routes[0].Slot = 3 },
		"invalid FSM":           func(r *ipsec.RuntimeStatusReport) { r.BGP.Peers[0].State = "Established" },
		"tally mismatch":        func(r *ipsec.RuntimeStatusReport) { r.BGP.Peers[0].InstalledPrefixes = 0 },
		"oversized accepted":    func(r *ipsec.RuntimeStatusReport) { r.BGP.Peers[0].AcceptedPrefixes = 65 },
		"idle installed":        func(r *ipsec.RuntimeStatusReport) { r.BGP.Peers[0].State = "idle" },
		"established IPsecdown": func(r *ipsec.RuntimeStatusReport) { r.Tunnels[0].Status = "down" },
		"negative rejected":     func(r *ipsec.RuntimeStatusReport) { n := -1; r.BGP.Peers[0].RejectedPrefixes = &n },
	} {
		t.Run(name, func(t *testing.T) {
			r := bgpTransportReport()
			mutate(&r)
			if validIPsecStatusReport(r) {
				t.Fatal("malformed BGP report accepted")
			}
		})
	}
}
