// Package relay bridges authenticated ICE sessions to the existing kernel WG
// listener. It never installs peers, changes policy, or forwards plaintext.
package relay

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tunnexio/tunnex/apps/node/internal/control"
	"github.com/tunnexio/tunnex/apps/node/internal/icewire"
)

type controlChannel interface {
	ConnectivityPending(context.Context, string) (control.ConnectivityPage, error)
	ConnectivityRead(context.Context, control.ConnectivitySession) (control.ConnectivitySession, error)
	ConnectivityPublish(context.Context, control.ConnectivitySession, int64, string) (control.ConnectivitySession, error)
}

type Runtime struct {
	client       controlChannel
	key          string
	logger       *slog.Logger
	port         atomic.Int32
	pollInterval time.Duration
}

func New(client *control.Client, key string, logger *slog.Logger) *Runtime {
	return &Runtime{client: client, key: key, logger: logger, pollInterval: 5 * time.Second}
}
func (r *Runtime) SetPort(port int) {
	if port > 0 && port <= 65535 {
		r.port.Store(int32(port))
	} else {
		r.port.Store(0)
	}
}

type running struct {
	cancel context.CancelFunc
	done   chan struct{}
}

func (r *Runtime) Run(ctx context.Context) {
	active := map[string]running{}
	backoff := map[string]time.Time{}
	cursor := ""
	defer func() {
		for _, v := range active {
			v.cancel()
		}
		for _, v := range active {
			<-v.done
		}
	}()
	ticker := time.NewTicker(r.pollInterval)
	defer ticker.Stop()
	for {
		for id, v := range active {
			select {
			case <-v.done:
				delete(active, id)
				backoff[id] = time.Now().Add(15 * time.Second)
			default:
			}
		}
		if r.port.Load() > 0 {
			page, err := r.client.ConnectivityPending(ctx, cursor)
			if err == nil {
				// One bounded page per tick, continuing on the next tick. A busy
				// first page cannot permanently hide later devices.
				cursor = page.NextCursor
				for _, s := range page.Items {
					if _, ok := active[s.SessionID]; ok || len(active) >= 64 || time.Now().Before(backoff[s.SessionID]) || s.Relay == nil || s.GatewayPublicKey != r.key {
						continue
					}
					worker, cancel := context.WithCancel(ctx)
					done := make(chan struct{})
					active[s.SessionID] = running{cancel, done}
					go func(s control.ConnectivitySession) { defer close(done); r.session(worker, s) }(s)
				}
				// Keep only unexpired retry deadlines, including previous pages.
				for id := range backoff {
					if !time.Now().Before(backoff[id]) {
						delete(backoff, id)
					}
				}
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (r *Runtime) session(ctx context.Context, s control.ConnectivitySession) {
	ctx, cancel := context.WithDeadline(ctx, s.ExpiresAt)
	defer cancel()
	neg, stop := icewire.Deadline(ctx)
	defer stop()
	endpoint, offer, err := icewire.Gather(neg, icewire.Relay{URL: s.Relay.URL, Username: s.Relay.Username, Password: s.Relay.Password}, r.key)
	if err != nil {
		return
	}
	defer endpoint.Close()
	raw, _ := json.Marshal(offer)
	authorizedUntil := time.Now().Add(30 * time.Second)
	s, err = r.client.ConnectivityPublish(neg, s, s.GatewaySequence+1, string(raw))
	if err != nil {
		return
	}
	var remote icewire.Signal
	for {
		if remote, err = icewire.Decode(s.DevicePayload, s.DevicePublicKey); err == nil {
			break
		}
		select {
		case <-neg.Done():
			return
		case <-time.After(time.Second):
		}
		s, authorizedUntil, err = r.authorizeForwarding(neg, s, authorizedUntil, false)
		if err != nil {
			return
		}
	}
	conn, err := endpoint.Connect(neg, remote, false)
	if err != nil {
		return
	}
	defer conn.Close()
	// ICE success is not authorization. Recheck under the remaining prior
	// lease before any application packet can reach the kernel listener.
	s, authorizedUntil, err = r.authorizeForwarding(neg, s, authorizedUntil, true)
	if err != nil {
		return
	}
	port := r.port.Load()
	if port < 1 {
		return
	}
	udp, err := net.Dial("udp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port))))
	if err != nil {
		return
	}
	defer udp.Close()
	r.logger.Info("relay_session_connected", slog.String("path", endpoint.Path()))
	var pumps sync.WaitGroup
	pumps.Add(2)
	go func() {
		defer pumps.Done()
		defer cancel()
		buf := make([]byte, 65535)
		for {
			n, e := conn.Read(buf)
			if e != nil {
				return
			}
			if _, e = udp.Write(buf[:n]); e != nil {
				return
			}
		}
	}()
	go func() {
		defer pumps.Done()
		defer cancel()
		buf := make([]byte, 65535)
		for {
			n, e := udp.Read(buf)
			if e != nil {
				return
			}
			if _, e = conn.Write(buf[:n]); e != nil {
				return
			}
		}
	}()
	leaseDeadline := authorizedUntil
	lease := time.NewTimer(time.Until(leaseDeadline))
	defer lease.Stop()
	poll := time.NewTicker(5 * time.Second)
	defer poll.Stop()
loop:
	for {
		select {
		case <-ctx.Done():
			break loop
		case <-lease.C:
			break loop
		case <-poll.C:
			current, nextDeadline, e := r.authorizeForwarding(ctx, s, leaseDeadline, true)
			if errors.Is(e, control.ErrConnectivityDenied) || !time.Now().Before(leaseDeadline) {
				break loop
			}
			if e != nil {
				continue
			} // hard lease still expires; no fail-open on CP loss
			if current.DevicePublicKey != s.DevicePublicKey || current.GatewayPublicKey != r.key || r.port.Load() != port {
				break loop
			}
			if !lease.Stop() {
				select {
				case <-lease.C:
				default:
				}
			}
			leaseDeadline = nextDeadline
			lease.Reset(time.Until(leaseDeadline))
		}
	}
	cancel()
	_ = conn.Close()
	_ = udp.Close()
	pumps.Wait()
}

// Anchor renewal to request start, never response arrival or ICE completion.
// The previous deadline bounds even a stalled control-plane request.
func (r *Runtime) authorizeForwarding(ctx context.Context, s control.ConnectivitySession, previous time.Time, established bool) (control.ConnectivitySession, time.Time, error) {
	started := time.Now()
	if !started.Before(previous) {
		return s, previous, context.DeadlineExceeded
	}
	readCtx, cancel := context.WithDeadline(ctx, previous)
	defer cancel()
	current, err := r.client.ConnectivityRead(readCtx, s)
	if err == nil {
		err = readCtx.Err()
	}
	if err != nil {
		return s, previous, err
	}
	if current.DevicePublicKey != s.DevicePublicKey || current.GatewayPublicKey != s.GatewayPublicKey ||
		(established && (current.DeviceSequence != s.DeviceSequence || current.DevicePayload != s.DevicePayload ||
			current.GatewaySequence != s.GatewaySequence || current.GatewayPayload != s.GatewayPayload)) {
		return s, previous, control.ErrConnectivityDenied
	}
	return current, started.Add(30 * time.Second), nil
}
