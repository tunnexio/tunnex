package control

import (
	"context"
	"errors"
	"fmt"
)

// Retain the existing error text for existing callers. Diagnostics project only
// the bounded HTTP status and a fixed category, never this text or a body.
type dnsReportHTTPError struct{ status int }

func (e dnsReportHTTPError) Error() string { return fmt.Sprintf("dns-resolution status %d", e.status) }
func DNSReportDiagnostic(err error) (int, string) {
	if err == nil {
		return 204, "none"
	}
	var status dnsReportHTTPError
	if errors.As(err, &status) {
		if status.status >= 100 && status.status <= 599 {
			return status.status, "http_status"
		}
		return 0, "http_status"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return 0, "deadline"
	}
	if errors.Is(err, context.Canceled) {
		return 0, "canceled"
	}
	return 0, "transport_or_encoding"
}
