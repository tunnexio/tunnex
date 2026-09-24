package http

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tunnexio/tunnex/apps/api/internal/ipsec"
)

type agentIPsecSpyBody struct{ reads int }

func (b *agentIPsecSpyBody) Read([]byte) (int, error) { b.reads++; return 0, io.EOF }
func (*agentIPsecSpyBody) Close() error               { return nil }
func TestAgentIPsecAuthBeforeParsing(t *testing.T) {
	a := NewAgentChannel(nil, nil, nil, nil)
	for _, tt := range []struct{ method, path string }{{"GET", "/agent/ipsec/pending?limit=bad"}, {"POST", "/agent/ipsec/connections/bad/material"}, {"POST", "/agent/ipsec/connections/bad/status"}, {"GET", "/agent/ipsec/connections/bad/cleanup?desired_revision=bad"}, {"POST", "/agent/ipsec/connections/bad/acknowledgements"}, {"POST", "/agent/ipsec/connections/bad/permit-lease"}} {
		body := &agentIPsecSpyBody{}
		req := httptest.NewRequest(tt.method, tt.path, nil)
		req.Body = body
		w := httptest.NewRecorder()
		a.Handler().ServeHTTP(w, req)
		if w.Code != 401 || body.reads != 0 || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("unauth boundary %s: %d reads%d", tt.path, w.Code, body.reads)
		}
	}
}
func TestAgentIPsecStrictDecodeRedaction(t *testing.T) {
	for _, body := range []string{`{"desired_revision":1,"desired_revision":2}`, `{"desired_revision":1,"desired_revisio\u006e":2}`, `{"desired_revision":1,"unknown":"secret-marker"}`, `{"desired_revision":9223372036854775808}`, `{"desired_revision":"secret-marker"}`, `{"desired_revision":1}{}`, strings.Repeat("x", 128*1024+1)} {
		var target struct {
			DesiredRevision int64 `json:"desired_revision"`
		}
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/agent/ipsec/connections/x/material", strings.NewReader(body))
		if decodeAgentIPsec(w, req, &target) || w.Code != 400 || strings.Contains(w.Body.String(), "secret-marker") {
			t.Fatal("unbounded or reflected decode")
		}
	}
}
func TestAgentIPsecErrorNeverWritesMaterial(t *testing.T) {
	marker := "private-PSK-marker"
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/agent/ipsec/connections/x/material", nil).WithContext(context.Background())
	writeAgentIPsec(w, r, ipsec.RuntimeMaterial{Secrets: [2]ipsec.RuntimeSecret{{PSK: marker}, {PSK: marker}}}, ipsec.ErrConnectionConflict)
	if w.Code != 409 || strings.Contains(w.Body.String(), marker) {
		t.Fatal("failed transaction leaked material")
	}
}
