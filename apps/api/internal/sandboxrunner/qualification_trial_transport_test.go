package sandboxrunner

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestQualificationTrialTransportRequiresCurrentActiveLeafAndExactBoundedRoutes(t *testing.T) {
	b, _ := NewBroker("spiffe://tunnex/runner/one")
	var cleanup atomic.Bool
	var calls atomic.Int32
	b.Authorize = func(_ context.Context, c *x509.Certificate) (bool, error) {
		if string(c.RawSubjectPublicKeyInfo) != "current" {
			return false, ErrUnavailable
		}
		return cleanup.Load(), nil
	}
	id := uuid.New()
	b.QualificationTrial = func(_ context.Context, _ *x509.Certificate, trial uuid.UUID, action string, raw json.RawMessage) (json.RawMessage, error) {
		if trial != id {
			return nil, ErrUnavailable
		}
		calls.Add(1)
		if action == "status" {
			return json.RawMessage(`{"version":1,"phase":"awaiting_expiry"}`), nil
		}
		return nil, nil
	}
	prefix := "/internal/sandbox-runners/v1/qualification-trials/" + id.String()
	expiry := time.Now().Add(time.Hour)
	if got := enrolledRequest(b, prefix+"/status", nil, "current", expiry); got.Code != 200 || !json.Valid(got.Body.Bytes()) {
		t.Fatal("public status", got.Code)
	}
	if got := enrolledRequest(b, prefix+"/witness", []byte(`{"version":1}`), "current", expiry).Code; got != 204 {
		t.Fatal("witness", got)
	}
	for _, key := range []string{"former", "unrelated"} {
		if got := enrolledRequest(b, prefix+"/status", nil, key, expiry).Code; got != 403 {
			t.Fatal("wrong current key", got)
		}
	}
	cleanup.Store(true)
	for _, action := range []string{"status", "witness"} {
		if got := enrolledRequest(b, prefix+"/"+action, nil, "current", expiry).Code; got != 403 {
			t.Fatal("cleanup trial access", got)
		}
	}
	cleanup.Store(false)
	cases := []struct{ path, body string }{{prefix + "/status", `{}`}, {prefix + "/status?secret=x", ""}, {prefix + "/start", ""}, {prefix + "/status/other", ""}, {"/internal/sandbox-runners/v1/qualification-trials/not-uuid/status", ""}, {prefix + "/witness", `{} {}`}, {prefix + "/witness", `{"large":"` + strings.Repeat("a", QualificationReportLimit) + `"}`}}
	for _, c := range cases {
		if got := enrolledRequest(b, c.path, []byte(c.body), "current", expiry).Code; got != 400 {
			t.Fatal("invalid trial request", c.path, got)
		}
	}
	if got := enrolledRequest(b, prefix+"/status", nil, "current", time.Now().Add(-time.Second)).Code; got != 403 {
		t.Fatal("expired established certificate", got)
	}
	if calls.Load() != 2 {
		t.Fatal("rejected payload reached service", calls.Load())
	}
}
