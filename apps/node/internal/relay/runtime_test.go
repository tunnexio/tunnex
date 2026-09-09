package relay

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/tunnexio/tunnex/apps/node/internal/control"
)

type leaseControl struct {
	pageControl
	read func(context.Context, control.ConnectivitySession) (control.ConnectivitySession, error)
}

func (c *leaseControl) ConnectivityRead(ctx context.Context, s control.ConnectivitySession) (control.ConnectivitySession, error) {
	return c.read(ctx, s)
}

func TestForwardingRequiresFreshAuthorizationWithinPreviousLease(t *testing.T) {
	s := control.ConnectivitySession{DevicePublicKey: "device", GatewayPublicKey: "gateway", DeviceSequence: 1, GatewaySequence: 1}
	t.Run("expired negotiation never reads or forwards", func(t *testing.T) {
		r := &Runtime{client: &leaseControl{read: func(context.Context, control.ConnectivitySession) (control.ConnectivitySession, error) {
			t.Fatal("expired lease reached CP")
			return s, nil
		}}}
		if _, _, err := r.authorizeForwarding(context.Background(), s, time.Now().Add(-time.Second), true); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal(err)
		}
	})
	t.Run("CP loss cannot manufacture a lease after ICE", func(t *testing.T) {
		r := &Runtime{client: &leaseControl{read: func(ctx context.Context, _ control.ConnectivitySession) (control.ConnectivitySession, error) {
			<-ctx.Done()
			return s, ctx.Err()
		}}}
		until := time.Now().Add(20 * time.Millisecond)
		_, next, err := r.authorizeForwarding(context.Background(), s, until, true)
		if !errors.Is(err, context.DeadlineExceeded) || !next.Equal(until) {
			t.Fatalf("lease extended: %v %v", next, err)
		}
	})
	t.Run("response latency does not extend authority", func(t *testing.T) {
		var started time.Time
		r := &Runtime{client: &leaseControl{read: func(context.Context, control.ConnectivitySession) (control.ConnectivitySession, error) {
			started = time.Now()
			time.Sleep(20 * time.Millisecond)
			return s, nil
		}}}
		_, next, err := r.authorizeForwarding(context.Background(), s, time.Now().Add(time.Second), true)
		if err != nil || next.After(started.Add(30*time.Second)) {
			t.Fatalf("response anchored lease: %v %v", next, err)
		}
	})
	t.Run("new offer is allowed only during negotiation", func(t *testing.T) {
		r := &Runtime{client: &leaseControl{read: func(context.Context, control.ConnectivitySession) (control.ConnectivitySession, error) {
			changed := s
			changed.DeviceSequence++
			return changed, nil
		}}}
		if _, _, err := r.authorizeForwarding(context.Background(), s, time.Now().Add(time.Second), false); err != nil {
			t.Fatal(err)
		}
		if _, _, err := r.authorizeForwarding(context.Background(), s, time.Now().Add(time.Second), true); !errors.Is(err, control.ErrConnectivityDenied) {
			t.Fatal(err)
		}
	})
}

type pageControl struct{ calls chan string }

func (p *pageControl) ConnectivityPending(ctx context.Context, cursor string) (control.ConnectivityPage, error) {
	select {
	case p.calls <- cursor:
	case <-ctx.Done():
		return control.ConnectivityPage{}, ctx.Err()
	}
	next := "second-page"
	if cursor != "" {
		next = ""
	}
	return control.ConnectivityPage{NextCursor: next}, nil
}
func (*pageControl) ConnectivityRead(context.Context, control.ConnectivitySession) (control.ConnectivitySession, error) {
	panic("no session expected")
}
func (*pageControl) ConnectivityPublish(context.Context, control.ConnectivitySession, int64, string) (control.ConnectivitySession, error) {
	panic("no session expected")
}

func TestRuntimePagesAndStops(t *testing.T) {
	p := &pageControl{calls: make(chan string, 4)}
	r := &Runtime{client: p, pollInterval: time.Millisecond}
	r.SetPort(51820)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); r.Run(ctx) }()
	for _, want := range []string{"", "second-page", ""} {
		select {
		case got := <-p.calls:
			if got != want {
				t.Fatalf("cursor %q, want %q", got, want)
			}
		case <-time.After(time.Second):
			t.Fatal("pagination stalled")
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("runtime did not stop")
	}
}

func TestRuntimePortIsValidated(t *testing.T) {
	r := &Runtime{}
	for _, port := range []int{1, 51820, 65535, 0, -1, 65536} {
		r.SetPort(port)
		want := int32(port)
		if port < 1 || port > 65535 {
			want = 0
		}
		if got := r.port.Load(); got != want {
			t.Fatalf("port=%d got=%d", port, got)
		}
	}
}
