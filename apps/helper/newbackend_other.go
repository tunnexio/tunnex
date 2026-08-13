//go:build !darwin && !windows

package helper

// NewBackend on platforms with no real tunnel backend (Linux/CI) returns the
// StubBackend (tunnel ops report not_implemented). Real backends: macOS =
// backend_darwin.go (pf), Windows = backend_windows.go (WFP).
func NewBackend() Backend { return StubBackend{} }
