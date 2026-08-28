package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/oapi-codegen/runtime/types"
)

type fqdnSettingRouteHandler struct{ Unimplemented }

func (fqdnSettingRouteHandler) SetFQDNResourceEnabled(w http.ResponseWriter, _ *http.Request, _ types.UUID) {
	w.WriteHeader(http.StatusNoContent)
}

// This exercises the generated router rather than merely inspecting the YAML:
// a PUT to the setting must reach its handler, while /impact has no PUT route.
func TestFQDNSettingPutRouteRegistration(t *testing.T) {
	r := chi.NewRouter()
	HandlerFromMux(fqdnSettingRouteHandler{}, r)
	org := "00000000-0000-0000-0000-000000000001"
	for _, tc := range []struct {
		path string
		want int
	}{
		{"/api/v1/organizations/" + org + "/fqdn-resources/setting", http.StatusNoContent},
		{"/api/v1/organizations/" + org + "/fqdn-resources/setting/impact", http.StatusMethodNotAllowed},
	} {
		req := httptest.NewRequest(http.MethodPut, tc.path, nil)
		rw := httptest.NewRecorder()
		r.ServeHTTP(rw, req)
		if rw.Code != tc.want {
			t.Errorf("PUT %s = %d, want %d", tc.path, rw.Code, tc.want)
		}
	}
}
