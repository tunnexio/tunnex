package beam

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tunnexio/tunnex/packages/apptransport"
)

func testBinding() apptransport.Binding {
	return apptransport.Binding{OrgID: "10000000-0000-4000-8000-000000000001", GatewayID: "20000000-0000-4000-8000-000000000002", AppID: "30000000-0000-4000-8000-000000000003", Generation: "40000000-0000-4000-8000-000000000004", Revision: 1, AuthorityVersion: 1, Hostname: "p-example.beam.example", Digest: strings.Repeat("a", 64), Purpose: Purpose}
}

func TestRegistryRejectsAliasesAndDuplicateAuthorityFieldsBeforeLookup(t *testing.T) {
	called := 0
	broker, handler, err := NewRegistryGateway(func(context.Context, apptransport.Binding, string) (time.Time, error) {
		called++
		return time.Now().Add(time.Second), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer broker.Close()
	for _, mutate := range []func(*http.Request){
		func(r *http.Request) { r.Header.Set("X-App-Purpose", "browser_proxy") },
		func(r *http.Request) { r.Header.Add("X-App-Org-ID", testBinding().OrgID) },
		func(r *http.Request) { r.Header.Set("X-App-Org-ID", "10000000-0000-4000-8000-00000000ABCD") },
		func(r *http.Request) { r.Header.Set("X-App-Digest", strings.Repeat("A", 64)) },
		func(r *http.Request) { r.Header.Set("X-App-Hostname", "P-EXAMPLE.beam.example") },
		func(r *http.Request) { r.URL.RawQuery = "target=remote" },
		func(r *http.Request) { r.TLS.VerifiedChains = nil },
		func(r *http.Request) { r.TLS.Version = tls.VersionTLS12 },
	} {
		r := httptest.NewRequest(http.MethodConnect, ChannelPath, nil)
		cert := &x509.Certificate{SerialNumber: big.NewInt(1), NotAfter: time.Now().Add(time.Hour)}
		r.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, PeerCertificates: []*x509.Certificate{cert}, VerifiedChains: [][]*x509.Certificate{{cert}}}
		apptransport.BindingHeaders(r.Header, testBinding())
		mutate(r)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != http.StatusForbidden {
			t.Fatal("malformed authority reached broker", w.Code)
		}
	}
	if called != 0 {
		t.Fatal("untrusted binding reached current authority", called)
	}
}

func TestGatewayRejectsInvalidAndForeignAssignments(t *testing.T) {
	for _, change := range []func(*apptransport.Binding){
		func(b *apptransport.Binding) { b.Purpose = "browser_proxy" },
		func(b *apptransport.Binding) { b.OrgID = "00000000-0000-0000-0000-000000000000" },
		func(b *apptransport.Binding) { b.GatewayID = "not-an-identity" },
		func(b *apptransport.Binding) { b.Revision = 0 },
		func(b *apptransport.Binding) { b.AuthorityVersion = 0 },
		func(b *apptransport.Binding) { b.Hostname = "127.0.0.1" },
		func(b *apptransport.Binding) { b.Digest = "bad" },
	} {
		b := testBinding()
		change(&b)
		if _, _, err := NewGateway(b, func(context.Context, apptransport.Binding, string) (time.Time, error) { return time.Now(), nil }); err == nil {
			t.Fatal("invalid binding accepted", b)
		}
	}
}

func TestGatewayRequiresVerifiedTLSBeforeAuthority(t *testing.T) {
	called := false
	b := testBinding()
	broker, handler, err := NewGateway(b, func(context.Context, apptransport.Binding, string) (time.Time, error) {
		called = true
		return time.Now().Add(time.Second), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer broker.Close()
	r := httptest.NewRequest(http.MethodConnect, ChannelPath, nil)
	apptransport.BindingHeaders(r.Header, b)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden || called {
		t.Fatal("unverified TLS reached authority")
	}
}

func TestBeamBrokerRejectsAppAccessAudienceAndRoute(t *testing.T) {
	called := false
	broker := apptransport.NewBeamBroker(func(context.Context, apptransport.Binding, string) (time.Time, error) {
		called = true
		return time.Now().Add(time.Second), nil
	})
	defer broker.Close()
	for _, purpose := range []string{"origin_check", "browser_proxy"} {
		b := testBinding()
		b.Purpose = purpose
		w := httptest.NewRecorder()
		_ = broker.Accept(w, httptest.NewRequest(http.MethodConnect, ChannelPath, nil), b, "fixture")
		if w.Code != http.StatusForbidden {
			t.Fatal("foreign audience admitted", purpose)
		}
	}
	w := httptest.NewRecorder()
	_ = broker.Accept(w, httptest.NewRequest(http.MethodConnect, "/app-access/channel", nil), testBinding(), "fixture")
	if w.Code != http.StatusForbidden || called {
		t.Fatal("App Access route reached Beam authority")
	}
}
