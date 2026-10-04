package apptransport

import (
	"net/http"
	"strconv"
	"time"
)

// OriginHeaderTiming is connector-controlled diagnostics, never authority.
const OriginHeaderTiming = "X-App-Origin-Response-Nanoseconds"

type originMeasuredTransport struct{ base http.RoundTripper }

func (t originMeasuredTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	start := time.Now()
	response, err := t.base.RoundTrip(r)
	if err == nil && response != nil {
		// Overwrite any origin-supplied value. Body/stream lifetime is excluded.
		response.Header.Set(OriginHeaderTiming, strconv.FormatInt(int64(time.Since(start)), 10))
	}
	return response, err
}
