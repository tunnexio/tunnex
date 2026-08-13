package http

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers/gorillamux"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
)

func TestZZMaxLenProbe(t *testing.T) {
	sw, err := api.GetSwagger()
	if err != nil {
		t.Fatal(err)
	}
	sw.Servers = nil
	router, err := gorillamux.NewRouter(sw)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, fp string }{
		{"201chars", strings.Repeat("a", 201)},
		{"65chars", strings.Repeat("a", 65)},
	} {
		body := `{"key_fingerprint":"` + tc.fp + `","nonce":"","csr":"","signature":"","agent_version":"x"}`
		req := httptest.NewRequest(http.MethodPost, "http://x/api/v1/agent/rekey", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		route, pp, err := router.FindRoute(req)
		if err != nil {
			t.Fatalf("%s: route: %v", tc.name, err)
		}
		err = openapi3filter.ValidateRequest(req.Context(), &openapi3filter.RequestValidationInput{
			Request: req, PathParams: pp, Route: route,
			Options: &openapi3filter.Options{AuthenticationFunc: func(ctx context.Context, in *openapi3filter.AuthenticationInput) error { return nil }},
		})
		t.Logf("%s -> %v", tc.name, err)
	}
}
