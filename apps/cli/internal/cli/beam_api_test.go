package cli

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/cli/internal/beamapi"
)

type beamRoundTrip func(*http.Request) (*http.Response, error)

func (f beamRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func beamResponse(code int, body string) *http.Response {
	return &http.Response{StatusCode: code, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}
}
func beamTestHTTP(t *testing.T, f beamRoundTrip) *beamHTTPAPI {
	t.Helper()
	api, e := newBeamHTTPAPI(Credential{Server: "https://cp.example.net", Token: "PRIVATE-CURRENT-TOKEN"})
	if e != nil {
		t.Fatal(e)
	}
	a := api.(*beamHTTPAPI)
	a.client.Transport = f
	return a
}
func TestBeamTypedWireRequestsUseCurrentCredentialAndCorrectBodies(t *testing.T) {
	generation := uuid.NewString()
	key := uuid.NewString()
	requests := 0
	a := beamTestHTTP(t, func(r *http.Request) (*http.Response, error) {
		requests++
		if r.Header.Get("Authorization") != "Bearer PRIVATE-CURRENT-TOKEN" || r.Header.Get("Accept") != "application/json" {
			t.Fatal("native request not bound to existing login")
		}
		if r.URL.Host != "cp.example.net" || !strings.HasPrefix(r.URL.Path, beamPath(beamTestOrg)) {
			t.Fatal("wrong control-plane origin or tenant")
		}
		switch {
		case r.URL.Path == beamPath(beamTestOrg)+"/shares" && r.Method == "POST":
			var v beamapi.BeamCreateInput
			if e := json.NewDecoder(r.Body).Decode(&v); e != nil {
				t.Fatal(e)
			}
			if v.IdempotencyKey.String() != key || v.DurationSeconds != 3600 || len(v.Grants) != 1 || v.Grants[0].SubjectId.String() != beamTestReviewer || v.Target.Port != 5173 || v.Target.CaPem != nil {
				t.Fatalf("unexpected create contract: %+v", v)
			}
		case strings.HasSuffix(r.URL.Path, "/connector"):
			var v beamapi.BeamConnectorInput
			if e := json.NewDecoder(r.Body).Decode(&v); e != nil {
				t.Fatal(e)
			}
			if v.ExpectedVersion != 3 || v.CsrPem != "SIGNED-CSR" {
				t.Fatal("connector issuance contract changed")
			}
		case strings.HasSuffix(r.URL.Path, "/heartbeat"):
			var v beamapi.BeamHeartbeatInput
			if e := json.NewDecoder(r.Body).Decode(&v); e != nil {
				t.Fatal(e)
			}
			if v.Generation.String() != generation || !v.OriginReady {
				t.Fatal("heartbeat not bound to issued generation")
			}
		case strings.HasSuffix(r.URL.Path, "/actions"):
			var v beamapi.BeamActionInput
			if e := json.NewDecoder(r.Body).Decode(&v); e != nil {
				t.Fatal(e)
			}
			if v.ExpectedVersion != 4 || v.Action != beamapi.Pause {
				t.Fatal("expected-version action contract changed")
			}
		case strings.HasSuffix(r.URL.Path, "/shares") && r.Method == "GET":
			if r.URL.Query().Get("limit") != "20" || r.URL.Query().Get("offset") != "40" {
				t.Fatal("list is not server paginated")
			}
		}
		return beamResponse(200, "{}"), nil
	})
	ctx := context.Background()
	if _, e := a.Create(ctx, beamTestOrg, beamCreate{Name: "App", Target: beamTarget{Protocol: "http", Address: "127.0.0.1", Port: 5173}, Duration: 3600, Grants: []beamGrant{{"user", beamTestReviewer}}, IdempotencyKey: key}); e != nil {
		t.Fatal(e)
	}
	if _, e := a.Issue(ctx, beamTestOrg, beamTestShare, 3, "SIGNED-CSR"); e != nil {
		t.Fatal(e)
	}
	if _, e := a.Heartbeat(ctx, beamTestOrg, beamTestShare, generation, true); e != nil {
		t.Fatal(e)
	}
	if _, e := a.Action(ctx, beamTestOrg, beamTestShare, beamAction{Action: "pause", ExpectedVersion: 4}); e != nil {
		t.Fatal(e)
	}
	if _, e := a.List(ctx, beamTestOrg, 40); e != nil {
		t.Fatal(e)
	}
	if requests != 5 {
		t.Fatal("unexpected native request count")
	}
}
func TestBeamRedirectNeverForwardsCredentialAndErrorsNeverReflectUpstream(t *testing.T) {
	count := 0
	a := beamTestHTTP(t, func(r *http.Request) (*http.Response, error) {
		count++
		res := beamResponse(302, `{"error":{"code":"PRIVATE-TOKEN","message":"PRIVATE-TOKEN PRIVATE-UPSTREAM"}}`)
		res.Header.Set("Location", "https://attacker.invalid/collect")
		return res, nil
	})
	_, e := a.Policy(context.Background(), beamTestOrg)
	if e == nil || count != 1 || strings.Contains(e.Error(), "PRIVATE") || strings.Contains(e.Error(), "attacker") {
		t.Fatalf("redirect/error leak: %v requests %d", e, count)
	}
	a.client.Transport = beamRoundTrip(func(*http.Request) (*http.Response, error) {
		return beamResponse(403, `{"error":{"message":"PRIVATE-TOKEN target=http://localhost:5173?secret=1","code":"PRIVATE-CODE"}}`), nil
	})
	_, e = a.Policy(context.Background(), beamTestOrg)
	if e == nil || strings.Contains(e.Error(), "PRIVATE") || strings.Contains(e.Error(), "localhost") {
		t.Fatalf("reflected raw error: %v", e)
	}
}
func TestBeamRequestBudgetRefusesOversizedCSRBeforeNetwork(t *testing.T) {
	called := false
	a := beamTestHTTP(t, func(*http.Request) (*http.Response, error) { called = true; return beamResponse(200, "{}"), nil })
	_, e := a.Issue(context.Background(), beamTestOrg, beamTestShare, 2, strings.Repeat("A", 33<<10))
	if e == nil || called {
		t.Fatal("oversized native payload reached network")
	}
}
func TestBeamAPIResponseBudgetAndCancellation(t *testing.T) {
	a := beamTestHTTP(t, func(*http.Request) (*http.Response, error) {
		return beamResponse(200, strings.Repeat(" ", (2<<20)+1)), nil
	})
	if _, e := a.Policy(context.Background(), beamTestOrg); e == nil || !strings.Contains(e.Error(), "size limit") {
		t.Fatalf("oversized response accepted: %v", e)
	}
	a.client.Transport = beamRoundTrip(func(r *http.Request) (*http.Response, error) { <-r.Context().Done(); return nil, r.Context().Err() })
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, e := a.Policy(ctx, beamTestOrg)
	if !errors.Is(e, errBeamNetwork) || time.Since(start) > 300*time.Millisecond {
		t.Fatalf("unbounded/cause leaking cancellation: %v", e)
	}
}
func TestBeamRejectsUntrustedStoredServerAndCanonicalOutput(t *testing.T) {
	for _, server := range []string{"http://remote.example.net", "https://user:password@cp.example.net", "https://cp.example.net?secret=1", "https://cp.example.net#token", "file:///tmp/session"} {
		if _, e := newBeamHTTPAPI(Credential{Server: server, Token: "PRIVATE"}); e == nil {
			t.Fatalf("unsafe stored server accepted: %s", server)
		}
	}
	s := beamShare{Hostname: "p-123.example.net", URL: "https://p-123.example.net/?token=PRIVATE"}
	if _, e := beamCanonicalURL(s); e == nil {
		t.Fatal("raw query leaked in canonical publication URL")
	}
	s.URL = "https://evil.example.net/"
	if _, e := beamCanonicalURL(s); e == nil {
		t.Fatal("wrong hostname accepted")
	}
}

func TestBeamRealTLSHTTPRedirectBudgetAndDeadline(t *testing.T) {
	var forwarded atomic.Int32
	destination := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { forwarded.Add(1); w.WriteHeader(200) }))
	defer destination.Close()
	source := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer PRIVATE-CURRENT-TOKEN" {
			t.Error("request lost existing credential")
		}
		switch r.URL.Query().Get("mode") {
		case "budget":
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, strings.Repeat(" ", (2<<20)+1))
		case "cancel":
			<-r.Context().Done()
		default:
			http.Redirect(w, r, destination.URL, http.StatusTemporaryRedirect)
		}
	}))
	defer source.Close()
	api, e := newBeamHTTPAPI(Credential{Server: source.URL, Token: "PRIVATE-CURRENT-TOKEN"})
	if e != nil {
		t.Fatal(e)
	}
	a := api.(*beamHTTPAPI)
	a.client.Transport = source.Client().Transport
	_, e = a.Policy(context.Background(), beamTestOrg)
	if e == nil || forwarded.Load() != 0 {
		t.Fatalf("real redirect forwarded native authority: %v count%d", e, forwarded.Load())
	}
	var value beamPolicy
	if e = a.request(context.Background(), "GET", beamPath(beamTestOrg)+"/policy?mode=budget", nil, &value); e == nil || !strings.Contains(e.Error(), "size limit") {
		t.Fatalf("real response budget not enforced: %v", e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	start := time.Now()
	e = a.request(ctx, "GET", beamPath(beamTestOrg)+"/policy?mode=cancel", nil, &value)
	if !errors.Is(e, errBeamNetwork) || time.Since(start) > 300*time.Millisecond {
		t.Fatalf("real request exceeded deadline: %v", e)
	}
}
