package http

import (
	"net/http"

	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
)

// AI-UX-1 contract stubs.
//
// The operations in the three `*_stub_handlers.go` files beside this one are in the OpenAPI contract so
// the control-plane, gateway and web work packages can build against generated types, but their behaviour
// lands with those packages. Until then each one authorizes the caller exactly as the finished handler
// will and then answers 501 `agent_ux_not_implemented`, so nothing can mistake a stub for an answer.
//
// The package that implements an operation deletes its stub; this file goes with the last one.
func agentUXNotImplemented() *apierr.Error {
	return apierr.New(http.StatusNotImplemented, "agent_ux_not_implemented", "This operation is not available yet.")
}
