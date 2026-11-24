package serveraccess

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/tunnexio/tunnex/apps/node/internal/control"
	"github.com/tunnexio/tunnex/packages/apptransport/terminalwire"
)

// Mode is the gateway-local Server Access setting (SA-UI-1), from TUNNEX_SERVER_ACCESS_ENABLED.
type Mode int

const (
	// ModeFollow (unset or empty): run while the control plane reports the capability on.
	ModeFollow Mode = iota
	// ModeOn ("true"): always run, as before SA-UI-1.
	ModeOn
	// ModeOff ("false", or anything unrecognised): gateway-local hard lock, never run.
	ModeOff
)

func (m Mode) String() string {
	switch m {
	case ModeOn:
		return "on"
	case ModeOff:
		return "off"
	}
	return "follow"
}

// ModeFromEnv parses TUNNEX_SERVER_ACCESS_ENABLED. An unrecognised value is a hard lock: a typo must never
// turn a remote shell on.
func ModeFromEnv(value string) Mode {
	switch strings.TrimSpace(value) {
	case "":
		return ModeFollow
	case "true":
		return ModeOn
	}
	return ModeOff
}

// FollowInterval is how often a following gateway asks the control plane for the capability.
const FollowInterval = 5 * time.Second

// Supervise runs the Server Access runtime according to mode. In follow mode it starts the runtime when
// the control plane reports the capability on and cancels it (closing in-flight terminals, which run under
// the same context) when it reports off. An unreachable control plane keeps the current state; the runtime
// itself cannot obtain sessions without control-plane authority.
func Supervise(ctx context.Context, client *control.Client, mode Mode, logger *slog.Logger) {
	start := func(ctx context.Context) func() {
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); Run(ctx, client) }()
		go func() { defer wg.Done(); RunEnrollment(ctx, client) }()
		return wg.Wait
	}
	switch mode {
	case ModeOff:
		logger.Info("server_access_gateway_locked")
		return
	case ModeOn:
		start(ctx)()
		return
	}
	poll := func(ctx context.Context) (bool, error) {
		var c terminalwire.Capability
		err := client.TerminalRPC(ctx, "GET", "capability", nil, &c)
		return c.Enabled, err
	}
	follow(ctx, FollowInterval, poll, start, logger)
}

func follow(ctx context.Context, interval time.Duration, poll func(context.Context) (bool, error), start func(context.Context) func(), logger *slog.Logger) {
	var running struct {
		cancel context.CancelFunc
		wait   func()
	}
	stop := func() {
		if running.cancel != nil {
			running.cancel()
			running.wait()
			running.cancel, running.wait = nil, nil
		}
	}
	defer stop()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		enabled, err := poll(ctx)
		switch {
		case err != nil:
			// Keep the current state.
		case enabled && running.cancel == nil:
			var child context.Context
			child, running.cancel = context.WithCancel(ctx)
			running.wait = start(child)
			logger.Info("server_access_runtime_started", slog.String("source", "control_plane"))
		case !enabled && running.cancel != nil:
			stop()
			logger.Info("server_access_runtime_stopped", slog.String("source", "control_plane"))
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
