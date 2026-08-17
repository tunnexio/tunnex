package cli

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestRunWireGuardQuickDownAlpineAbsentInterfaceIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	tool := filepath.Join(dir, "wg-quick")
	if err := os.WriteFile(tool, []byte("#!/bin/sh\nif [ \"$1\" = down ]; then\n  echo \"wg-quick: \\\x60runtime' is not a WireGuard interface\" >&2\n  exit 1\nfi\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	if err := runWireGuardQuick(context.Background(), "/etc/wireguard/runtime.conf", "disable"); err != nil {
		t.Fatalf("Alpine absent-interface stderr should be idempotent: %v", err)
	}
}
