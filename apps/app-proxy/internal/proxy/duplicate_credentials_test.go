package proxy

import (
	"crypto/tls"
	"github.com/tunnexio/tunnex/packages/apptransport"
	"net/http/httptest"
	"testing"
)

func TestDuplicateAuthorizationRefusedBeforeAuthority(t *testing.T) {
	a := &deniedAuthority{}
	broker := apptransport.NewBrowserBroker(nil)
	defer broker.Close()
	handler := NewHandler("apps.example.net", a, broker)
	for _, name := range []string{"Authorization", "Proxy-Authorization"} {
		r := httptest.NewRequest("GET", "/", nil)
		r.Host = "payroll.apps.example.net"
		r.TLS = &tls.ConnectionState{Version: tls.VersionTLS13}
		r.Header[name] = []string{"Bearer application-token", "AppProxy tnxap_secret"}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != 403 {
			t.Fatal("duplicate credentials accepted")
		}
	}
	if a.calls.Load() != 0 {
		t.Fatal("duplicate credentials reached authority")
	}
}
