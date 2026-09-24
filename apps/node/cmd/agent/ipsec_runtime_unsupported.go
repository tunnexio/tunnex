//go:build !linux

package main

import (
	"context"
	"github.com/tunnexio/tunnex/apps/node/internal/control"
	"log/slog"
)

func startIPsecRuntime(context.Context, *control.Client, string, *slog.Logger) error { return nil }
