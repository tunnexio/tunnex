package control

import (
	"context"
	"errors"
	"fmt"
	"github.com/tunnexio/tunnex/apps/node/internal/fqdnrpc"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestDNSReportDiagnosticFixedProjection(t *testing.T) {
	for _, tc := range []struct {
		err      error
		status   int
		category string
	}{{nil, 204, "none"}, {dnsReportHTTPError{409}, 409, "http_status"}, {fmt.Errorf("private: %w", dnsReportHTTPError{400}), 400, "http_status"}, {dnsReportHTTPError{9999}, 0, "http_status"}, {fmt.Errorf("private: %w", context.Canceled), 0, "canceled"}, {context.DeadlineExceeded, 0, "deadline"}, {errors.New("secret-http-body"), 0, "transport_or_encoding"}} {
		status, category := DNSReportDiagnostic(tc.err)
		if status != tc.status || category != tc.category {
			t.Fatal("unsafe category", status, category)
		}
	}
	if (dnsReportHTTPError{409}).Error() != "dns-resolution status 409" {
		t.Fatal("existing caller error text changed")
	}
}

func TestDNSReportActualHTTPStatusProjection(t *testing.T) {
	for _, status := range []int{204, 400, 401, 403, 409, 410, 500} {
		c := &Client{base: "https://control.test", http: &http.Client{Transport: ipsecReportTransport(func(r *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader("private-body"))}, nil
		})}}
		err := c.ReportDNSResolution(context.Background(), fqdnrpc.Response{Hostname: "secret.test", RequestID: "private"})
		got, category := DNSReportDiagnostic(err)
		if got != status || (status == 204 && category != "none") || (status != 204 && category != "http_status") {
			t.Fatal("incorrect actual report status", got, category)
		}
	}
}
