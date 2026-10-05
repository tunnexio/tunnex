//go:build !linux

package sandboxes

import "net"

// Runtime authority is Linux-only. Portable unit/integration tests exercise the
// protocol handler directly; a non-Linux host cannot activate this client.
func verifyWorkerSocket(string, uint32) error      { return ErrDisabled }
func verifyConnectedWorker(net.Conn, uint32) error { return ErrDisabled }
