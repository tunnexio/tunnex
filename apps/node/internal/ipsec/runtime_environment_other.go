//go:build !linux

package ipsec

import "context"

func runtimeDrainConntrack(context.Context, []RuntimeJournalEntry) error {
	return ErrRuntimeEnvironment
}
