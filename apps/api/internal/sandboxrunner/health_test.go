package sandboxrunner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestHealthLaneKeepsEffectBoundAndReplyIsolation(t *testing.T) {
	b, _ := NewBroker("spiffe://tunnex/runner/health-fixture")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	effectDone := make(chan error, 1)
	go func() { _, err := b.Call(ctx, json.RawMessage(`{"Operation":"enroll"}`)); effectDone <- err }()
	waitPending := func(health bool) {
		t.Helper()
		for {
			b.mu.Lock()
			p := b.pending
			if health {
				p = b.health
			}
			b.mu.Unlock()
			if p != nil {
				return
			}
			select {
			case <-ctx.Done():
				t.Fatal("lane not queued")
			case <-time.After(time.Millisecond):
			}
		}
	}
	waitPending(false)
	healthDone := make(chan error, 1)
	go func() { _, err := b.CallHealth(ctx); healthDone <- err }()
	waitPending(true)
	if _, err := b.Call(ctx, json.RawMessage(`{}`)); err != ErrUnavailable {
		t.Fatal("second effect admitted", err)
	}
	secondHealthDone := startHealth(ctx, b)
	waitHealthWaiters(t, b, 2)
	if w := request(b, "/internal/sandbox-runners/v1/health/poll", nil, false); w.Code != 403 {
		t.Fatal("unauthenticated health poll", w.Code)
	}
	var probe, effect Command
	if err := json.Unmarshal(request(b, "/internal/sandbox-runners/v1/health/poll", nil, true).Body.Bytes(), &probe); err != nil {
		t.Fatal(err)
	}
	if string(probe.Payload) != healthPayload {
		t.Fatal("caller-controlled health command")
	}
	if err := json.Unmarshal(request(b, "/internal/sandbox-runners/v1/poll", nil, true).Body.Bytes(), &effect); err != nil {
		t.Fatal(err)
	}
	probeReply, _ := json.Marshal(Reply{probe.ID, json.RawMessage(`{}`)})
	if w := request(b, "/internal/sandbox-runners/v1/reply", probeReply, true); w.Code != 409 {
		t.Fatal("probe reply completed effect", w.Code)
	}
	effectReply, _ := json.Marshal(Reply{effect.ID, json.RawMessage(`{}`)})
	if w := request(b, "/internal/sandbox-runners/v1/health/reply", effectReply, true); w.Code != 409 {
		t.Fatal("effect reply completed probe", w.Code)
	}
	if w := request(b, "/internal/sandbox-runners/v1/health/reply", probeReply, true); w.Code != 204 {
		t.Fatal(w.Code)
	}
	if err := <-healthDone; err != nil {
		t.Fatal(err)
	}
	if got := healthResultBefore(t, ctx, secondHealthDone); got.err != nil || string(got.payload) != "{}" {
		t.Fatal("concurrent check did not share fresh probe", got.err)
	}
	select {
	case <-effectDone:
		t.Fatal("probe consumed effect")
	default:
	}
	if w := request(b, "/internal/sandbox-runners/v1/reply", effectReply, true); w.Code != 204 {
		t.Fatal(w.Code)
	}
	if err := <-effectDone; err != nil {
		t.Fatal(err)
	}
}

type healthResult struct {
	payload json.RawMessage
	err     error
}

func startHealth(ctx context.Context, b *Broker) <-chan healthResult {
	done := make(chan healthResult, 1)
	go func() {
		payload, err := b.CallHealth(ctx)
		done <- healthResult{payload, err}
	}()
	return done
}

func waitHealthWaiters(t *testing.T, b *Broker, count int) *pending {
	t.Helper()
	deadline := time.After(2 * time.Second)
	for {
		b.mu.Lock()
		p := b.health
		ready := p != nil && p.waiters == count
		b.mu.Unlock()
		if ready {
			return p
		}
		select {
		case <-deadline:
			t.Fatal("health callers did not join one probe")
		case <-time.After(time.Millisecond):
		}
	}
}

func healthResultBefore(t *testing.T, ctx context.Context, done <-chan healthResult) healthResult {
	t.Helper()
	select {
	case got := <-done:
		return got
	case <-ctx.Done():
		t.Fatal("health result did not complete")
		return healthResult{}
	}
}

func healthCommand(t *testing.T, b *Broker) Command {
	t.Helper()
	out := request(b, "/internal/sandbox-runners/v1/health/poll", nil, true)
	var command Command
	if out.Code != 200 || json.Unmarshal(out.Body.Bytes(), &command) != nil || string(command.Payload) != healthPayload || !command.Deadline.After(time.Now()) || time.Until(command.Deadline) > healthProbeLifetime {
		t.Fatal("invalid fixed health command", out.Code)
	}
	return command
}

func healthReply(t *testing.T, b *Broker, command Command, payload json.RawMessage) int {
	t.Helper()
	body, err := json.Marshal(Reply{command.ID, payload})
	if err != nil {
		t.Fatal(err)
	}
	return request(b, "/internal/sandbox-runners/v1/health/reply", body, true).Code
}

func TestHealthConcurrentCallersShareFreshProbe(t *testing.T) {
	b, _ := NewBroker("spiffe://tunnex/runner/health-fixture")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	const callers = 12
	done := make([]<-chan healthResult, callers)
	for i := range done {
		done[i] = startHealth(ctx, b)
	}
	waitHealthWaiters(t, b, callers)
	command := healthCommand(t, b)
	const reply = `{"Version":1,"Binding":{"GatewayID":"fixture"}}`
	if code := healthReply(t, b, command, json.RawMessage(reply)); code != 204 {
		t.Fatal("health reply refused", code)
	}
	results := make([]healthResult, callers)
	for i := range done {
		results[i] = healthResultBefore(t, ctx, done[i])
		if results[i].err != nil || string(results[i].payload) != reply {
			t.Fatal("parallel readiness lost the fresh reply", results[i].err)
		}
	}
	results[0].payload[0] = 'x'
	if string(results[1].payload) != reply {
		t.Fatal("callers shared mutable reply bytes")
	}
	if code := healthReply(t, b, command, json.RawMessage(reply)); code != 409 {
		t.Fatal("completed probe accepted duplicate reply", code)
	}
	next := startHealth(ctx, b)
	waitHealthWaiters(t, b, 1)
	fresh := healthCommand(t, b)
	if fresh.ID == command.ID {
		t.Fatal("later readiness reused completed probe")
	}
	select {
	case <-next:
		t.Fatal("later readiness used cached success")
	default:
	}
	if code := healthReply(t, b, fresh, json.RawMessage(`{}`)); code != 204 || healthResultBefore(t, ctx, next).err != nil {
		t.Fatal("fresh follow-up probe failed", code)
	}
}

func TestHealthFirstCallerCancellationAndDeadlineLeaveOtherWaiter(t *testing.T) {
	for _, mode := range []string{"cancel", "deadline"} {
		t.Run(mode, func(t *testing.T) {
			b, _ := NewBroker("spiffe://tunnex/runner/health-fixture")
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			firstCtx, firstCancel := context.WithTimeout(ctx, 300*time.Millisecond)
			defer firstCancel()
			first := startHealth(firstCtx, b)
			waitHealthWaiters(t, b, 1)
			command := healthCommand(t, b)
			firstDeadline, _ := firstCtx.Deadline()
			if !command.Deadline.After(firstDeadline) {
				t.Fatal("shared command borrowed first caller deadline")
			}
			survivor := startHealth(ctx, b)
			waitHealthWaiters(t, b, 2)
			if mode == "cancel" {
				firstCancel()
			}
			if got := healthResultBefore(t, ctx, first); !errors.Is(got.err, ErrUnavailable) || len(got.payload) != 0 {
				t.Fatal("first caller ignored its cancellation/deadline", got.err)
			}
			waitHealthWaiters(t, b, 1)
			if still := healthCommand(t, b); still.ID != command.ID || !still.Deadline.Equal(command.Deadline) {
				t.Fatal("departure replaced or extended shared command")
			}
			if code := healthReply(t, b, command, json.RawMessage(`{}`)); code != 204 || healthResultBefore(t, ctx, survivor).err != nil {
				t.Fatal("first caller closed surviving readiness check", code)
			}
		})
	}
}

func TestHealthAllCallersCancelAndLateReplyCannotCompleteReplacement(t *testing.T) {
	b, _ := NewBroker("spiffe://tunnex/runner/health-fixture")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	firstCtx, firstCancel := context.WithCancel(ctx)
	secondCtx, secondCancel := context.WithCancel(ctx)
	first, second := startHealth(firstCtx, b), startHealth(secondCtx, b)
	waitHealthWaiters(t, b, 2)
	old := healthCommand(t, b)
	firstCancel()
	secondCancel()
	for _, done := range []<-chan healthResult{first, second} {
		if got := healthResultBefore(t, ctx, done); !errors.Is(got.err, ErrUnavailable) {
			t.Fatal("canceled caller returned success", got.err)
		}
	}
	if out := request(b, "/internal/sandbox-runners/v1/health/poll", nil, true); out.Code != 204 {
		t.Fatal("all canceled callers left a pending command", out.Code)
	}
	next := startHealth(ctx, b)
	waitHealthWaiters(t, b, 1)
	fresh := healthCommand(t, b)
	if fresh.ID == old.ID || healthReply(t, b, old, json.RawMessage(`{}`)) != 409 {
		t.Fatal("late reply was accepted for replacement probe")
	}
	if code := healthReply(t, b, fresh, json.RawMessage(`{}`)); code != 204 || healthResultBefore(t, ctx, next).err != nil {
		t.Fatal("replacement probe was retired by previous callers", code)
	}
}

func TestHealthCanceledCallerDoesNotWinSharedReplyRace(t *testing.T) {
	b, _ := NewBroker("spiffe://tunnex/runner/health-fixture")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for i := 0; i < 16; i++ {
		firstCtx, firstCancel := context.WithCancel(ctx)
		first, survivor := startHealth(firstCtx, b), startHealth(ctx, b)
		waitHealthWaiters(t, b, 2)
		command := healthCommand(t, b)
		// Publish the reply immediately after cancellation, without waiting for
		// the first caller to leave. Either select branch must honor its ctx.
		firstCancel()
		if code := healthReply(t, b, command, json.RawMessage(`{}`)); code != 204 {
			t.Fatal("survivor's fresh reply was refused", code)
		}
		if got := healthResultBefore(t, ctx, first); !errors.Is(got.err, ErrUnavailable) || len(got.payload) != 0 {
			t.Fatal("canceled caller consumed a healthy reply", got.err)
		}
		if got := healthResultBefore(t, ctx, survivor); got.err != nil || string(got.payload) != "{}" {
			t.Fatal("canceled caller closed survivor's probe", got.err)
		}
	}
}

func TestHealthSharedCommandExpiryWakesAllWaiters(t *testing.T) {
	b, _ := NewBroker("spiffe://tunnex/runner/health-fixture")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	first, second := startHealth(ctx, b), startHealth(ctx, b)
	p := waitHealthWaiters(t, b, 2)
	command := healthCommand(t, b)
	// Advance only this test's shared command expiry without a thirty-second
	// wall-clock wait. Its timer exercises the actual expiration callback.
	b.mu.Lock()
	p.command.Deadline = time.Now().Add(20 * time.Millisecond)
	p.timer.Reset(20 * time.Millisecond)
	b.mu.Unlock()
	for _, done := range []<-chan healthResult{first, second} {
		if got := healthResultBefore(t, ctx, done); !errors.Is(got.err, ErrUnavailable) || len(got.payload) != 0 {
			t.Fatal("expired shared command returned a healthy result", got.err)
		}
	}
	if healthReply(t, b, command, json.RawMessage(`{}`)) != 409 {
		t.Fatal("expired command accepted a late reply")
	}
}

func TestHealthInvalidAndCanceledCallersDoNotPublishProbe(t *testing.T) {
	b, _ := NewBroker("spiffe://tunnex/runner/health-fixture")
	if _, err := b.CallHealth(context.Background()); !errors.Is(err, ErrInvalid) {
		t.Fatal("unbounded caller admitted", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	cancel()
	if _, err := b.CallHealth(ctx); !errors.Is(err, ErrUnavailable) {
		t.Fatal("already canceled caller admitted", err)
	}
	if out := request(b, "/internal/sandbox-runners/v1/health/poll", nil, true); out.Code != 204 || !bytes.Equal(out.Body.Bytes(), nil) {
		t.Fatal("invalid/canceled caller left a probe", out.Code)
	}
}
