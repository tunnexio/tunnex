//go:build !linux

package ipsec

import "context"

func readRuntimeClock() (runtimeClock, error)     { return runtimeClock{}, ErrRuntimeProbe }
func runtimeProbePrivilege(context.Context) error { return ErrRuntimeProbe }

func runtimeProbePackage(context.Context) error { return ErrRuntimeProbe }
