package control

import (
	"context"
	"errors"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/node/internal/ipsec"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type lease409Body struct {
	io.Reader
	reads  int
	fail   bool
	cancel context.CancelFunc
}

func (b *lease409Body) Read(p []byte) (int, error) {
	b.reads++
	if b.cancel != nil {
		b.cancel()
	}
	if b.fail {
		return 0, errors.New("private-marker")
	}
	return b.Reader.Read(p)
}
func (b *lease409Body) Close() error { return nil }
func TestRenewLeaseConflictCodeClosedAndBounded(t *testing.T) {
	for _, v := range []struct {
		name, body, want string
		fail, cancel     bool
	}{
		{"ineligible", `{"error":{"code":"ipsec_connection_ineligible","message":"private-marker","request_id":"private-marker","details":["private-marker"]}}`, "http_409_ineligible", false, false},
		{"conflict", `{"error":{"code":"ipsec_connection_conflict"}}`, "http_409_conflict", false, false},
		{"unknown", `{"error":{"code":"private-marker"}}`, "http_409", false, false},
		{"malformed", `{"error":`, "http_409", false, false},
		{"duplicate", `{"error":{"code":"ipsec_connection_ineligible","code":"ipsec_connection_conflict"}}`, "http_409", false, false},
		{"trailing", `{"error":{"code":"ipsec_connection_conflict"}} {}`, "http_409", false, false},
		{"oversize", `{"error":{"code":"ipsec_connection_conflict","message":"` + strings.Repeat("x", 4096) + `"}}`, "http_409", false, false},
		{"read_failure", "", "http_409", true, false},
		{"cancel", `{"error":{"code":"ipsec_connection_conflict"}}`, "http_409", false, true},
	} {
		t.Run(v.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			b := &lease409Body{Reader: strings.NewReader(v.body), fail: v.fail}
			if v.cancel {
				b.cancel = cancel
			}
			calls := 0
			c := &Client{base: "https://cp.test", http: &http.Client{Transport: ipsecRoundTrip(func(r *http.Request) (*http.Response, error) {
				calls++
				if _, ok := r.Context().Deadline(); !ok {
					t.Fatal("deadline absent")
				}
				return &http.Response{StatusCode: 409, Body: b, Header: http.Header{}}, nil
			})}}
			_, err := c.RenewIPsecLease(ctx, uuid.New(), ipsec.RuntimeLeaseRequest{Nonce: "same-fresh-nonce"})
			var stage interface{ IPsecLeaseFailureStage() string }
			if !errors.Is(err, ErrIPsecControl) || err.Error() != ErrIPsecControl.Error() || !errors.As(err, &stage) || stage.IPsecLeaseFailureStage() != v.want || calls != 1 {
				t.Fatalf("fixed category/sentinel/callcount: %v %v", err, stage)
			}
		})
	}
}
func TestNonRenewConflictBodyUnchanged(t *testing.T) {
	b := &lease409Body{Reader: strings.NewReader(`{"error":{"code":"ipsec_connection_conflict"}}`)}
	c := &Client{base: "https://cp.test", http: &http.Client{Transport: ipsecRoundTrip(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 409, Body: b, Header: http.Header{}}, nil
	})}}
	_, err := c.IPsecMaterial(context.Background(), uuid.New(), 1)
	if err != ErrIPsecControl || b.reads != 0 {
		t.Fatal("non-renew changed")
	}
}

type stalledLease409Body struct{ ctx context.Context }

func (b stalledLease409Body) Read([]byte) (int, error) { <-b.ctx.Done(); return 0, b.ctx.Err() }
func (b stalledLease409Body) Close() error             { return nil }
func TestRenewLeaseConflictStalledBodyBounded(t *testing.T) {
	calls := 0
	c := &Client{base: "https://cp.test", http: &http.Client{Transport: ipsecRoundTrip(func(r *http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: 409, Body: stalledLease409Body{r.Context()}, Header: http.Header{}}, nil
	})}}
	started := time.Now()
	_, err := c.RenewIPsecLease(context.Background(), uuid.New(), ipsec.RuntimeLeaseRequest{})
	elapsed := time.Since(started)
	var stage interface{ IPsecLeaseFailureStage() string }
	if !errors.Is(err, ErrIPsecControl) || !errors.As(err, &stage) || stage.IPsecLeaseFailureStage() != "http_409" || calls != 1 || elapsed > 500*time.Millisecond {
		t.Fatalf("stalled diagnostic not bounded: %v", elapsed)
	}
}
