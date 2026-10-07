package proxy

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/tunnexio/tunnex/packages/apptransport"
	"github.com/tunnexio/tunnex/packages/apptransport/authoritywire"
)

func TestBeamOversizeUploadRejectsBeforeReceivingBody(t *testing.T) {
	// A real TLS client declares an oversized body but sends only one byte.
	// Nil authority/broker also proves the request cannot enter serving admission.
	server := httptest.NewTLSServer(NewBeamHandler("apps.example.net", nil, nil))
	defer server.Close()
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := tls.Dial("tcp", u.Host, &tls.Config{RootCAs: pool, ServerName: "example.com", MinVersion: tls.VersionTLS13})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := fmt.Fprintf(conn, "POST /upload HTTP/1.1\r\nHost: p-fixture.apps.example.net\r\nContent-Length: %d\r\n\r\nx", (16<<20)+1); err != nil {
		t.Fatal(err)
	}
	res, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal("response waited for unfinished upload", err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil || res.StatusCode != http.StatusRequestEntityTooLarge || !res.Close || !strings.Contains(string(body), "16 MiB") {
		t.Fatalf("unexpected oversize response: status=%d close=%v error=%v", res.StatusCode, res.Close, err)
	}
}

func TestBeamLaunchUsesIsolatedPurposeAndHashOnlyConsoleHandoff(t *testing.T) {
	a := newLaunchAuthority()
	a.route.Binding.Purpose = "beam_proxy"
	h := NewBeamHandler("apps.example.net", a, nil)
	h.Console, _ = ConsoleURL("https://console.example.com", "apps.example.net")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, appRequest("GET", "/_beam/start?target=%2Fforms", ""))
	if w.Code != http.StatusSeeOther {
		t.Fatal(w.Code)
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != apptransport.AppNonceCookie || !cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].Domain != "" {
		t.Fatal("unsafe nonce cookie")
	}
	destination, err := url.Parse(w.Header().Get("Location"))
	hash := sha256.Sum256([]byte(cookies[0].Value))
	if err != nil || destination.Path != "/beam/launch" || destination.Query().Get("shareId") != a.route.Binding.AppID || destination.Query().Get("nonce_hash") != hex.EncodeToString(hash[:]) || strings.Contains(destination.String(), cookies[0].Value) {
		t.Fatal("unsafe Beam handoff")
	}
	a.route.Binding.Purpose = "browser_proxy"
	w = httptest.NewRecorder()
	h.ServeHTTP(w, appRequest("GET", "/_beam/start", ""))
	if w.Code != http.StatusForbidden || len(w.Header().Values("Set-Cookie")) != 0 {
		t.Fatal("App Access route granted Beam launch")
	}
	a.route.Binding.Purpose = "beam_proxy"
	old := launchHandler(t, a)
	w = httptest.NewRecorder()
	old.ServeHTTP(w, appRequest("GET", StartPath, ""))
	if w.Code != http.StatusForbidden {
		t.Fatal("Beam route granted App Access launch")
	}
}

func TestBeamRedeemCodesKeepAudiencePrefix(t *testing.T) {
	beam := NewBeamHandler("apps.example.net", nil, nil)
	app := NewHandler("apps.example.net", nil, nil)
	raw := newLaunchAuthority().code
	if !beam.redeemCodeValid("tnxbc_"+raw) || beam.redeemCodeValid(raw) || app.redeemCodeValid("tnxbc_"+raw) || !app.redeemCodeValid(raw) {
		t.Fatal("launch code audience changed")
	}
	for _, code := range []string{"tnxbc_", "tnxbc_bad", "tnxbs_" + raw, "tnxbc_tnxbc_" + raw} {
		if beam.redeemCodeValid(code) {
			t.Fatal("invalid Beam code accepted")
		}
	}
}

func TestBeamClientCallsOnlyBeamAuthorityNamespace(t *testing.T) {
	var paths []string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.Header.Get("Authorization") != "AppProxy tnxap_fixture" {
			t.Error("authority credential/method lost")
		}
		paths = append(paths, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/internal/beam/domains" {
			_ = json.NewEncoder(w).Encode(DomainConfig{PortalURL: "https://console.example.com", AppBaseDomain: "apps.example.net"})
			return
		}
		_, _ = w.Write([]byte("{}"))
	}))
	defer server.Close()
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	c, err := NewBeamClient(server.URL, "tnxap_fixture", &tls.Config{ServerName: "example.com", RootCAs: pool})
	if err != nil {
		t.Fatal(err)
	}
	b := launchBinding()
	b.Purpose = authoritywire.AppProxyRouteBindingPurpose("beam_proxy")
	ctx := context.Background()
	_, _ = c.Lookup(ctx, b.Hostname)
	_, _ = c.Channel(ctx, b, "1")
	_, _ = c.Authorize(ctx, b, "session", Request{Method: "GET", RelativePath: "/"})
	_, _ = c.Renew(ctx, b, "stream")
	_, _ = c.Pending(ctx, PendingInput{})
	_, _ = c.Redeem(ctx, RedeemInput{})
	_, _ = c.Domains(ctx)
	expected := []string{"resolve", "connector", "authorize", "renew", "pending", "redeem", "domains"}
	if len(paths) != len(expected) {
		t.Fatalf("requests=%v", paths)
	}
	for i, path := range expected {
		if paths[i] != "/internal/beam/"+path {
			t.Fatal(paths)
		}
	}
	if b.Valid() || !b.validPurpose("beam_proxy") {
		t.Fatal("legacy binding validator must stay App Access only")
	}
}

func TestBeamOperationalMetricsStaySeparateAndRedacted(t *testing.T) {
	b := apptransport.NewBeamBroker(nil)
	defer b.Close()
	h := NewBeamHandler("apps.example.net", nil, b)
	op := &Operational{Handler: h, CertificateExpiresAt: time.Now().Add(time.Hour), AuthorityReady: func() bool { return true }}
	w := httptest.NewRecorder()
	op.ServeHTTP(w, httptest.NewRequest("GET", "/metrics", nil))
	if w.Code != 200 || !strings.Contains(w.Body.String(), "tunnex_beam_proxy_ready 1") || strings.Contains(w.Body.String(), "tunnex_app_proxy_") {
		t.Fatal("Beam operational audience lost")
	}
	for _, secret := range []string{"apps.example.net", "org_id", "app_id", "cookie", "credential"} {
		if strings.Contains(w.Body.String(), secret) {
			t.Fatal("operational metadata leaked", secret)
		}
	}
	for _, metric := range []string{"tls_seconds_until_expiry", "authority_lease_failures_total", "authority_lease_expired_total"} {
		if !strings.Contains(w.Body.String(), "tunnex_beam_proxy_"+metric) {
			t.Fatal("missing actionable Beam metric", metric)
		}
	}
	op.Draining.Store(true)
	w = httptest.NewRecorder()
	op.ServeHTTP(w, httptest.NewRequest("GET", "/readyz", nil))
	if w.Code != 503 {
		t.Fatal("draining Beam still ready")
	}
}

func TestBeamRequestOrganizationCapacityIsIndependent(t *testing.T) {
	h := NewBeamHandler("apps.example.net", nil, nil)
	var releases []func()
	defer func() {
		for _, release := range releases {
			release()
		}
	}()
	for i := 0; i < 64; i++ {
		binding := Binding{OrgID: "org-a", AppID: fmt.Sprint(i), GatewayID: fmt.Sprint(i)}
		release := h.reserve(binding, fmt.Sprint(i))
		if release == nil {
			t.Fatal("reservation refused before organization limit")
		}
		releases = append(releases, release)
	}
	if h.reserve(Binding{OrgID: "org-a", AppID: "extra", GatewayID: "extra"}, "extra") != nil {
		t.Fatal("organization limit not enforced")
	}
	release := h.reserve(Binding{OrgID: "org-b", AppID: "other", GatewayID: "other"}, "other")
	if release == nil {
		t.Fatal("one organization consumed another's request capacity")
	}
	release()
	releases[0]()
	releases = releases[1:]
	release = h.reserve(Binding{OrgID: "org-a", AppID: "extra", GatewayID: "extra"}, "extra")
	if release == nil {
		t.Fatal("released request reservation leaked")
	}
	releases = append(releases, release)
}
