package http

import (
	"testing"

	"github.com/tunnexio/tunnex/apps/api/internal/api"
)

// Domain Capture is retired. Keep the public contract closed so a future
// regeneration cannot accidentally re-expose the historical endpoints.
func TestDomainCaptureEndpointsAreAbsent(t *testing.T) {
	swagger, err := api.GetSwagger()
	if err != nil {
		t.Fatalf("GetSwagger: %v", err)
	}
	for _, path := range []string{
		"/api/v1/organizations/{orgId}/domains",
		"/api/v1/organizations/{orgId}/domains/verify",
	} {
		if _, ok := swagger.Paths.Map()[path]; ok {
			t.Fatalf("retired Domain Capture path is still public: %s", path)
		}
	}
}
