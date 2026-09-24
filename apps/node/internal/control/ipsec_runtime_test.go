package control

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/node/internal/ipsec"
	"io"
	"net/http"
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
