package main

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/tunnexio/tunnex/apps/node/internal/control"
	"github.com/tunnexio/tunnex/apps/node/internal/dnsforward"
	"github.com/tunnexio/tunnex/apps/node/internal/ownershiplease"
	"github.com/tunnexio/tunnex/apps/node/internal/reconcile"
)

type dataplaneCommand struct {
	name   string
	urgent bool
	run    func(context.Context) error
}

func produceDNSBindCommands(ctx context.Context, lane *dataplaneCommandLane, forwarder *dnsforward.Forwarder, wgIface string, every time.Duration) {
	if forwarder == nil || every <= 0 {
		return
	}
	apply := func() bool {
		_ = lane.submitAndWait(ctx, "dns_bind_reconcile", func(commandCtx context.Context) error {
			forwarder.ReconcileK8sBinds(commandCtx, wgIface)
			return nil
		})
		return ctx.Err() == nil
	}
	if !apply() {
		return
	}
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !apply() {
				return
			}
		}
	}
}

func produceOwnershipCommands(ctx context.Context, lane *dataplaneCommandLane, client *control.Client, attestor *control.PoolVIPOwnershipAttestorV3, lifecycle *ownershiplease.Lifecycle, pollEvery, watchdogEvery time.Duration, logger *slog.Logger) {
	if pollEvery <= 0 || watchdogEvery <= 0 {
		return
	}
	pollTicker := time.NewTicker(pollEvery)
	defer pollTicker.Stop()
	go produceOwnershipWatchdogCommands(ctx, lane, lifecycle, watchdogEvery)
	for {
		select {
		case <-ctx.Done():
			return
		case <-pollTicker.C:
			transportCtx, cancel := context.WithTimeout(ctx, pollEvery)
			envelope, found, fetchErr := client.FetchPoolVIPOwnershipDeliveryV3(transportCtx)
			cancel()
			if fetchErr != nil || !found {
				if fetchErr != nil && ctx.Err() == nil {
					logger.Warn("ownership_delivery_fetch_failed", slog.String("error", fetchErr.Error()))
				}
				continue
			}
			var ack control.PoolVIPOwnershipDeliveryAckV3
			if err := lane.submitAndWait(ctx, "ownership_delivery_apply_readback", func(commandCtx context.Context) error {
				var err error
				ack, err = attestor.PreparePoolVIPOwnershipDeliveryAckV3(commandCtx, envelope)
				return err
			}); err != nil {
				if ctx.Err() != nil {
					return
				}
				continue
			}
			transportCtx, cancel = context.WithTimeout(ctx, pollEvery)
			ackErr := client.AcknowledgePoolVIPOwnershipDeliveryV3(transportCtx, ack)
			cancel()
			if ackErr != nil && ctx.Err() != nil {
				return
			}
			if ackErr != nil {
				logger.Warn("ownership_delivery_ack_failed", slog.String("error", ackErr.Error()))
			}
		}
	}
}

func produceOwnershipWatchdogCommands(ctx context.Context, lane *dataplaneCommandLane, lifecycle *ownershiplease.Lifecycle, every time.Duration) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := lane.submitUrgentAndWait(ctx, "ownership_lease_watchdog", lifecycle.Check); err != nil && ctx.Err() != nil {
				return
			}
		}
	}
}

// dataplaneCommandLane is the agent's single mutation owner. Producers may do
// read-only waits (control Watch, tickers, EndpointSlice notifications), but
// every operation that can change WG, routes, nftables, DNS binds, OpenVPN or
// durable ownership state is submitted here and runs to completion before the
// next command starts.
type dataplaneCommandLane struct {
	mu          sync.Mutex
	commands    []dataplaneCommand
	urgent      []dataplaneCommand
	wake        chan struct{}
	normalSlots chan struct{}
	urgentSlots chan struct{}
	logger      *slog.Logger

	leaseDeadline func() (time.Time, bool)
	leaseCheck    func(context.Context) error
}

func newDataplaneCommandLane(logger *slog.Logger) *dataplaneCommandLane {
	return &dataplaneCommandLane{
		wake: make(chan struct{}, 1), normalSlots: make(chan struct{}, 8), urgentSlots: make(chan struct{}, 8), logger: logger,
	}
}

func (l *dataplaneCommandLane) setLeaseGuard(deadline func() (time.Time, bool), check func(context.Context) error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.leaseDeadline = deadline
	l.leaseCheck = check
}

func (l *dataplaneCommandLane) submitUrgentAndWait(ctx context.Context, name string, run func(context.Context) error) error {
	if run == nil {
		return fmt.Errorf("dataplane command %q has no operation", name)
	}
	done := make(chan error, 1)
	command := dataplaneCommand{name: name, urgent: true, run: func(commandCtx context.Context) error {
		err := run(commandCtx)
		done <- err
		return err
	}}
	if err := l.enqueue(ctx, command); err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-done:
		return err
	}
}

func (l *dataplaneCommandLane) submit(ctx context.Context, name string, run func(context.Context) error) error {
	if run == nil {
		return fmt.Errorf("dataplane command %q has no operation", name)
	}
	return l.enqueue(ctx, dataplaneCommand{name: name, run: run})
}

func (l *dataplaneCommandLane) enqueue(ctx context.Context, command dataplaneCommand) error {
	slots := l.normalSlots
	if command.urgent {
		slots = l.urgentSlots
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case slots <- struct{}{}:
	}
	l.mu.Lock()
	if command.urgent {
		l.urgent = append(l.urgent, command)
	} else {
		l.commands = append(l.commands, command)
	}
	l.mu.Unlock()
	select {
	case l.wake <- struct{}{}:
	default:
	}
	return nil
}

func (l *dataplaneCommandLane) submitAndWait(ctx context.Context, name string, run func(context.Context) error) error {
	done := make(chan error, 1)
	if err := l.submit(ctx, name, func(commandCtx context.Context) error {
		err := run(commandCtx)
		done <- err
		return err
	}); err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-done:
		return err
	}
}

func (l *dataplaneCommandLane) run(ctx context.Context) {
	for {
		if ctx.Err() != nil {
			return
		}
		if command, ok := l.pop(); ok {
			l.execute(ctx, command)
			continue
		}
		select {
		case <-ctx.Done():
			return
		case <-l.wake:
		}
	}
}

func (l *dataplaneCommandLane) pop() (dataplaneCommand, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	var command dataplaneCommand
	switch {
	case len(l.urgent) > 0:
		command = l.urgent[0]
		l.urgent = l.urgent[1:]
		<-l.urgentSlots
	case len(l.commands) > 0:
		command = l.commands[0]
		l.commands = l.commands[1:]
		<-l.normalSlots
	default:
		return dataplaneCommand{}, false
	}
	return command, true
}

func (l *dataplaneCommandLane) urgentLen() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.urgent)
}

func (l *dataplaneCommandLane) execute(ctx context.Context, command dataplaneCommand) {
	commandCtx := ctx
	cancel := func() {}
	var deadline time.Time
	var guarded bool
	l.mu.Lock()
	deadlineSource := l.leaseDeadline
	leaseCheck := l.leaseCheck
	l.mu.Unlock()
	if !command.urgent && deadlineSource != nil {
		if value, ok := deadlineSource(); ok {
			deadline, guarded = value, true
			commandCtx, cancel = context.WithDeadline(ctx, deadline)
		}
	}
	err := command.run(commandCtx)
	cancel()
	if err != nil && ctx.Err() == nil {
		l.logger.Warn("dataplane_command_failed", slog.String("command", command.name), slog.String("error", err.Error()))
	}
	// A normal operation that reaches the exact CP lease deadline must hand the
	// lane directly to the fail-closed withdrawal check; it cannot let another
	// queued normal mutation run first.
	if guarded && leaseCheck != nil && !time.Now().Before(deadline) && ctx.Err() == nil {
		if err := leaseCheck(ctx); err != nil {
			l.logger.Warn("ownership_lease_deadline_withdraw_failed", slog.String("error", err.Error()))
		}
	}
}

// produceDesiredStateCommands owns only the read-only trigger logic. Both the
// initial resync and every later fetch/apply are commands on the shared lane.
type baseAuthorityAckClient interface {
	AcknowledgeKubernetesOwnershipBaseAuthority(context.Context, reconcile.KubernetesOwnershipBaseAuthorityAck) error
}

func produceDesiredStateCommands(ctx context.Context, lane *dataplaneCommandLane, r *reconcile.Reconciler, client reconcile.ControlClient, ownership *ownershiplease.Coordinator, interval, backoff time.Duration, logger *slog.Logger) {
	submit := func(name string) bool {
		desired, err := client.FetchDesired(ctx)
		if err != nil {
			logger.Warn("desired_state_fetch_failed", slog.String("command", name), slog.String("error", err.Error()))
			return ctx.Err() == nil
		}
		var ack reconcile.KubernetesOwnershipBaseAuthorityAck
		var ackReady bool
		err = lane.submitAndWait(ctx, name, func(commandCtx context.Context) error {
			if _, err := r.ApplyDesiredState(commandCtx, desired); err != nil {
				return err
			}
			if ownership == nil {
				return nil
			}
			var err error
			ack, ackReady, err = ownership.PrepareBaseAuthorityAck(commandCtx, desired, time.Now())
			return err
		})
		if err != nil {
			return ctx.Err() == nil
		}
		if ackReady {
			transport, ok := client.(baseAuthorityAckClient)
			if !ok {
				logger.Warn("base_authority_ack_transport_unavailable")
				return ctx.Err() == nil
			}
			transportCtx, cancel := context.WithTimeout(ctx, backoff)
			postErr := transport.AcknowledgeKubernetesOwnershipBaseAuthority(transportCtx, ack)
			cancel()
			if postErr != nil {
				if ctx.Err() == nil {
					logger.Warn("base_authority_ack_failed", slog.String("error", postErr.Error()))
				}
				return ctx.Err() == nil
			}
			if err := lane.submitAndWait(ctx, "base_authority_ack_checkpoint", func(commandCtx context.Context) error {
				return ownership.MarkBaseAuthorityAckDelivered(commandCtx, ack)
			}); err != nil {
				if ctx.Err() == nil {
					logger.Warn("base_authority_ack_checkpoint_failed", slog.String("error", err.Error()))
				}
				return ctx.Err() == nil
			}
		}
		return ctx.Err() == nil
	}
	if !submit("desired_state_initial") {
		return
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		watchCtx, cancelWatch := context.WithCancel(ctx)
		watchCh := make(chan error, 1)
		go func(version uint64) { watchCh <- client.Watch(watchCtx, version) }(r.DesiredVersion())

		select {
		case <-ctx.Done():
			cancelWatch()
			return
		case err := <-watchCh:
			cancelWatch()
			if err != nil {
				logger.Warn("watch_failed_backing_off", slog.String("error", err.Error()))
				timer := time.NewTimer(backoff)
				select {
				case <-ctx.Done():
					if !timer.Stop() {
						<-timer.C
					}
					return
				case <-timer.C:
				}
				continue
			}
			if !submit("desired_state_push") {
				return
			}
		case <-ticker.C:
			cancelWatch()
			if !submit("desired_state_interval") {
				return
			}
		}
	}
}
