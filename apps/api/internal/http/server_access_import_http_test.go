package http

import (
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
	"github.com/tunnexio/tunnex/apps/api/internal/serveraccess"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type recordingWhitespaceReader struct{ remaining, read int64 }

func (r *recordingWhitespaceReader) Read(p []byte) (int, error) {
	if r.remaining == 0 {
		return 0, io.EOF
	}
	n := len(p)
	if int64(n) > r.remaining {
		n = int(r.remaining)
	}
	for i := 0; i < n; i++ {
		p[i] = ' '
	}
	r.remaining -= int64(n)
	r.read += int64(n)
	return n, nil
}
func TestTerminalImportStreamingBodyBoundsBeforeDecoder(t *testing.T) {
	org := uuid.New()
	p := appAccessPrincipal(org, rbac.RoleAdmin)
	p.SessionID = "synthetic-parent"
	p.AuthMethod = authctx.AuthLocalPassword
	p.EmailVerified = true
	for _, tc := range []struct {
		name, method, path, body string
		authenticated            bool
		bytes                    int64
		want                     int
	}{
		{"package chunked trailing bytes", "POST", "recording-import", `{"package":"AA=="}`, true, 48 << 20, 413},
		{"ordinary metadata retains small bound", "PUT", "recording-archive", `{"enabled":false}`, true, 128 << 10, 413},
		{"unauthenticated denied before body read", "POST", "recording-import", `{"package":"AA=="}`, false, 48 << 20, 401},
	} {
		t.Run(tc.name, func(t *testing.T) {
			router, e := NewRouter(slog.New(slog.NewTextHandler(io.Discard, nil)), Deps{AppBaseURL: "http://localhost", ServerAccess: serveraccess.New(nil, nil, nil, true), AuthFn: func(*http.Request) *authctx.Principal {
				if tc.authenticated {
					return p
				}
				return nil
			}})
			if e != nil {
				t.Fatal(e)
			}
			tail := &recordingWhitespaceReader{remaining: tc.bytes}
			req := httptest.NewRequest(tc.method, "http://localhost/api/v1/organizations/"+org.String()+"/server-access/"+tc.path, io.MultiReader(strings.NewReader(tc.body), tail))
			req.ContentLength = -1
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Origin", "http://localhost")
			req.Header.Set("X-Tunnex-CSRF", "1")
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			if w.Code != tc.want {
				t.Fatalf("status %d want %d: %s", w.Code, tc.want, w.Body.String())
			}
			if !tc.authenticated && tail.read != 0 {
				t.Fatal("unauthenticated body consumed")
			}
		})
	}
}
