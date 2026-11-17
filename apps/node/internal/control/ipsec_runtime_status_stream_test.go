package control

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/node/internal/ipsec"
)

type streamHeartbeatPollRig struct {
	heartbeatBatchRig
	stream             func(context.Context, func(context.Context, ipsec.RuntimeRecoveryHeartbeat) error) error
	legacyCalls, posts int
	failPost           bool
}

func (f *streamHeartbeatPollRig) RefreshIPsecActiveRecovery(context.Context) ([]ipsec.RuntimeRecoveryHeartbeat, error) {
	f.legacyCalls++
	return nil, ErrIPsecControl
}
func (f *streamHeartbeatPollRig) RefreshIPsecActiveRecoveryObserved(ctx context.Context, publish func(context.Context, ipsec.RuntimeRecoveryHeartbeat) error) error {
	return f.stream(ctx, publish)
}
func (f *streamHeartbeatPollRig) IPsecReportStatus(ctx context.Context, id uuid.UUID, r ipsec.RuntimeStatusReport) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	f.posts++
	if f.failPost {
		return errors.New("status transport failed")
	}
	return f.runtimePollFake.IPsecReportStatus(ctx, id, r)
}
func streamHeartbeatFixture() ipsec.RuntimeRecoveryHeartbeat {
	one := 1
	seq := uint64(7)
	id := uuid.New()
	d := ipsec.RuntimeDelivery{ID: uuid.New(), Kind: "apply", DesiredRevision: 2, Manifest: ipsec.RuntimeManifest{ConnectionID: id, DesiredRevision: 2, ConfigurationRevision: 1, ProfileID: "aws-static-ipv4-v1", RecoveryVersion: &one, Tunnels: [2]ipsec.RuntimeTunnel{{ID: uuid.New(), Slot: 1, Selected: true}, {ID: uuid.New(), Slot: 2}}}}
	r := ipsec.RuntimeStatusReport{DeliveryID: d.ID, DesiredRevision: 2, ConfigurationRevision: 1, RecoveryVersion: &one, SelectionSequence: &seq, Tunnels: [2]ipsec.RuntimeTunnelStatus{{ID: d.Manifest.Tunnels[0].ID, Slot: 1, Status: "down", Selected: true}, {ID: d.Manifest.Tunnels[1].ID, Slot: 2, Status: "up"}}}
	return ipsec.RuntimeRecoveryHeartbeat{ConnectionID: id, Delivery: d, Report: r}
}
func TestIPsecRuntimeStatusUsesImmediateStreamingDispatch(t *testing.T) {
	f := &streamHeartbeatPollRig{}
	parent, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	f.stream = func(ctx context.Context, publish func(context.Context, ipsec.RuntimeRecoveryHeartbeat) error) error {
		if d, _ := ctx.Deadline(); time.Until(d) < 15*time.Second {
			t.Fatal("control imposed legacy shared five-second deadline")
		}
		for i := 0; i < 2; i++ {
			owner, stop := context.WithTimeout(ctx, 5*time.Second)
			err := publish(owner, streamHeartbeatFixture())
			stop()
			if err != nil {
				return err
			}
			if f.posts != i+1 {
				t.Fatal("publication was buffered behind another owner")
			}
		}
		return nil
	}
	if RefreshIPsecRuntimeStatus(parent, f, f) != nil || f.legacyCalls != 0 || f.posts != 2 {
		t.Fatal("streaming not preferred", f.legacyCalls, f.posts)
	}
}
func TestIPsecRuntimeStreamingRejectsInvalidOrFailedPublication(t *testing.T) {
	for _, kind := range []string{"duplicate", "foreign", "bad_revision", "canceled_owner", "canceled_parent", "http", "ignored_invalid", "ignored_http"} {
		t.Run(kind, func(t *testing.T) {
			f := &streamHeartbeatPollRig{}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			f.stream = func(ctx context.Context, publish func(context.Context, ipsec.RuntimeRecoveryHeartbeat) error) error {
				out := streamHeartbeatFixture()
				owner, stop := context.WithTimeout(ctx, 5*time.Second)
				defer stop()
				switch kind {
				case "duplicate":
					if publish(owner, out) != nil {
						t.Fatal("valid first publication")
					}
				case "foreign":
					out.ConnectionID = uuid.New()
				case "bad_revision", "ignored_invalid":
					out.Report.DesiredRevision++
				case "canceled_owner":
					stop()
				case "canceled_parent":
					cancel()
				case "http", "ignored_http":
					f.failPost = true
				}
				err := publish(owner, out)
				if kind == "ignored_invalid" || kind == "ignored_http" {
					return nil // The control layer must retain its own rejected callback.
				}
				return err
			}
			if RefreshIPsecRuntimeStatus(ctx, f, f) == nil || f.legacyCalls != 0 {
				t.Fatal("invalid streaming publication accepted")
			}
			want := 0
			if kind == "duplicate" || kind == "http" || kind == "ignored_http" {
				want = 1
			}
			if f.posts != want {
				t.Fatal("invalid report reached HTTP", f.posts)
			}
		})
	}
}
