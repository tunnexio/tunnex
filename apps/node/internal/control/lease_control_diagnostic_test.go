package control

import (
	"context"
	"errors"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/node/internal/ipsec"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRenewLeaseClosedHTTPFailureAndSentinel(t *testing.T) {
	for _, v := range []struct {
		status   int
		category string
	}{{400, "http_400"}, {401, "http_401"}, {403, "http_403"}, {404, "http_404"}, {409, "http_409"}, {429, "http_429"}, {500, "http_5xx"}, {599, "http_5xx"}, {418, "http_other"}} {
		t.Run(v.category, func(t *testing.T) {
			calls := 0
			s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				w.WriteHeader(v.status)
				io.WriteString(w, "private-secret-marker")
			}))
			defer s.Close()
			c := &Client{base: s.URL, http: s.Client()}
			_, e := c.RenewIPsecLease(context.Background(), uuid.New(), ipsec.RuntimeLeaseRequest{Nonce: "fresh-nonce"})
			var classified interface{ IPsecLeaseFailureStage() string }
			if !errors.Is(e, ErrIPsecControl) || e.Error() != ErrIPsecControl.Error() || strings.Contains(e.Error(), "private-secret-marker") || !errors.As(e, &classified) || classified.IPsecLeaseFailureStage() != v.category || calls != 1 {
				t.Fatal("closed category/sentinel/call count failed")
			}
			// Existing non-renew callers retain exact sentinel equality.
			_, other := c.IPsecMaterial(context.Background(), uuid.New(), 1)
			if other != ErrIPsecControl {
				t.Fatal("generic caller sentinel changed")
			}
		})
	}
}
func TestRenewLeaseClosedTransportAndParse(t *testing.T) {
	for _, v := range []struct {
		category  string
		transport error
		body      string
	}{{"transport_deadline", context.DeadlineExceeded, ""}, {"transport_cancel", context.Canceled, ""}, {"transport_other", errors.New("private-secret-marker"), ""}, {"parse", nil, "not-json-private-secret-marker"}, {"parse", nil, "{} {}"}, {"parse", nil, strings.Repeat("x", (1<<20)+1)}} {
		t.Run(v.category, func(t *testing.T) {
			calls := 0
			c := &Client{base: "https://cp.test", http: &http.Client{Transport: ipsecRoundTrip(func(r *http.Request) (*http.Response, error) {
				calls++
				if _, ok := r.Context().Deadline(); !ok {
					t.Fatal("request deadline removed")
				}
				if v.transport != nil {
					return nil, v.transport
				}
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(v.body)), Header: http.Header{}}, nil
			})}}
			_, e := c.RenewIPsecLease(context.Background(), uuid.New(), ipsec.RuntimeLeaseRequest{})
			var classified interface{ IPsecLeaseFailureStage() string }
			if !errors.Is(e, ErrIPsecControl) || !errors.As(e, &classified) || classified.IPsecLeaseFailureStage() != v.category || calls != 1 || e.Error() != ErrIPsecControl.Error() {
				t.Fatal("failure classification or sentinel changed")
			}
		})
	}
}
