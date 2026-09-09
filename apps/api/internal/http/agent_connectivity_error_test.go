package http

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/tunnexio/tunnex/apps/api/internal/connectivity"
)

func TestAgentConnectivityErrorStatus(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want int
	}{
		{connectivity.ErrDenied, http.StatusForbidden},
		{fmt.Errorf("wrapped: %w", connectivity.ErrDenied), http.StatusForbidden},
		{connectivity.ErrPayload, http.StatusBadRequest},
		{context.DeadlineExceeded, http.StatusServiceUnavailable},
		{context.Canceled, http.StatusServiceUnavailable},
		{errors.New("storage unavailable"), http.StatusServiceUnavailable},
	} {
		if got := agentConnectivityErrorStatus(tc.err); got != tc.want {
			t.Fatalf("%v: got %d, want %d", tc.err, got, tc.want)
		}
	}
}
