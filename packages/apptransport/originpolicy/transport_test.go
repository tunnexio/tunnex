package originpolicy

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"sync/atomic"
	"testing"
)

func TestStreamingTransportTLSAndLiteralOrigin(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "example.com" || r.TLS.ServerName != "example.com" || r.URL.Path != "/form" {
			t.Errorf("origin identity: %s %s %s", r.Host, r.TLS.ServerName, r.URL.Path)
		}
		io.Copy(w, r.Body)
	}))
	defer server.Close()
	cert, e := x509.ParseCertificate(server.TLS.Certificates[0].Certificate[0])
	if e != nil {
		t.Fatal(e)
	}
	policy, e := Normalize([]string{"10.1.2.3/32"}, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})))
	if e != nil {
		t.Fatal(e)
	}
	checker := Checker{Lookup: func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("10.1.2.3")}, nil
	}, Dial: func(ctx context.Context, n, address string) (net.Conn, error) {
		if address != "10.1.2.3:443" {
			t.Errorf("nonliteral dial: %s", address)
		}
		return (&net.Dialer{}).DialContext(ctx, n, server.Listener.Addr().String())
	}}
	for _, tc := range []struct {
		origin string
		policy Policy
		ok     bool
	}{{"https://example.com", policy, true}, {"https://wrong.example", policy, false}, {"https://example.com", func() Policy { p, _ := Normalize(policy.AllowedDestinationCIDRs, ""); return p }(), false}} {
		tr := &Transport{Origin: tc.origin, Policy: tc.policy, Checker: checker}
		request, _ := http.NewRequest("POST", "http://untrusted-browser-target/form", io.NopCloser(&testBody{}))
		response, e := tr.RoundTrip(request)
		if (e == nil) != tc.ok {
			t.Fatal(tc.origin, e)
		}
		if e == nil {
			body, _ := io.ReadAll(response.Body)
			response.Body.Close()
			if string(body) != "streamed" {
				t.Fatal(string(body))
			}
		}
	}
}

type testBody struct{ sent bool }

func (b *testBody) Read(p []byte) (int, error) {
	if b.sent {
		return 0, io.EOF
	}
	b.sent = true
	return copy(p, "streamed"), nil
}
func TestStreamingTransportRefreshesAllDNSAndControlAliases(t *testing.T) {
	policy, _ := Normalize([]string{"10.1.0.0/16"}, "")
	var mode atomic.Int32
	var calls atomic.Int32
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1); w.WriteHeader(http.StatusNoContent) }))
	defer server.Close()
	checker := Checker{ControlHosts: []string{"control.example"}, Lookup: func(_ context.Context, host string) ([]netip.Addr, error) {
		if host == "control.example" {
			switch mode.Load() {
			case 1:
				return []netip.Addr{netip.MustParseAddr("10.1.2.3")}, nil
			case 2:
				return nil, errors.New("DNS unavailable")
			}
			return []netip.Addr{netip.MustParseAddr("10.1.2.4")}, nil
		}
		if mode.Load() == 3 {
			return []netip.Addr{netip.MustParseAddr("10.1.2.3"), netip.MustParseAddr("::ffff:169.254.169.254")}, nil
		}
		if mode.Load() == 4 {
			return []netip.Addr{netip.MustParseAddr("10.1.3.4")}, nil
		}
		return []netip.Addr{netip.MustParseAddr("10.1.2.3")}, nil
	}, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		calls.Add(1)
		want := "10.1.2.3:80"
		if mode.Load() == 4 {
			want = "10.1.3.4:80"
		}
		if network != "tcp" || address != want {
			t.Errorf("unexpected numeric dial: %s %s", network, address)
		}
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}}
	tr := &Transport{Origin: "http://origin.example", Checker: checker, Policy: policy}
	request, _ := http.NewRequest("GET", "http://logical.invalid/asset", nil)
	// First allowed resolution reaches the literal dial; subsequent DNS changes
	// must be re-evaluated rather than inheriting a cached connection/decision.
	response, err := tr.RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if calls.Load() != 1 || hits.Load() != 1 {
		t.Fatal("initial valid destination did not dial")
	}
	for _, m := range []int32{1, 2, 3} {
		mode.Store(m)
		if _, e := tr.RoundTrip(request); e == nil {
			t.Fatal(m, "accepted")
		}
		if calls.Load() != 1 || hits.Load() != 1 {
			t.Fatal(m, "refused DNS dialed or hit origin")
		}
	}
	mode.Store(4)
	response, err = tr.RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if calls.Load() != 2 || hits.Load() != 2 {
		t.Fatal("changed allowed DNS was not freshly dialed")
	}

}

func TestStreamingTransportBrowserURLCannotChangeOrigin(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Host != "origin.example" || r.URL.Host != "" || r.URL.Scheme != "" || r.URL.Path != "/reports/detail" || r.URL.RawPath != "/reports%2Fdetail" || r.URL.RawQuery != "next=https%3A%2F%2Fevil.example%2F&x=1" {
			t.Errorf("browser URL changed registered origin or path/query: host=%q url=%v", r.Host, r.URL)
		}
		if r.Header.Get("Authorization") != "" {
			t.Error("browser URL userinfo became origin credentials")
		}
		w.Header().Set("Location", "http://169.254.169.254/latest/meta-data")
		w.WriteHeader(http.StatusFound)
	}))
	defer server.Close()
	policy, err := Normalize([]string{"10.1.2.3/32"}, "")
	if err != nil {
		t.Fatal(err)
	}
	var dials atomic.Int32
	tr := &Transport{Origin: "http://origin.example", Policy: policy, Checker: Checker{
		Lookup: func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("10.1.2.3")}, nil
		},
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			dials.Add(1)
			if network != "tcp" || address != "10.1.2.3:80" {
				t.Errorf("browser URL changed numeric dial: %q %q", network, address)
			}
			return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
		},
	}}
	request := &http.Request{Method: http.MethodGet, Header: make(http.Header), Host: "browser.example", URL: &url.URL{
		Scheme: "https", Host: "169.254.169.254:9443", User: url.UserPassword("browser", "untrusted"),
		Opaque: "//169.254.169.254/forged", OmitHost: true,
		Path: "/reports/detail", RawPath: "/reports%2Fdetail", RawQuery: "next=https%3A%2F%2Fevil.example%2F&x=1",
		Fragment: "browser-fragment", RawFragment: "browser%2Dfragment",
	}}
	response, err := tr.RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusFound || dials.Load() != 1 || hits.Load() != 1 {
		t.Fatal("transport followed redirect or did not use its single pinned origin")
	}
	if request.URL.Host != "169.254.169.254:9443" || request.URL.Opaque != "//169.254.169.254/forged" || request.Host != "browser.example" {
		t.Fatal("transport mutated caller URL")
	}
}
