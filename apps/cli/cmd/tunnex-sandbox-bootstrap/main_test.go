package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestShelvedBootstrapRefusesBeforeFlagsAndStdin(t *testing.T) {
	if os.Getenv("TUNNEX_TEST_SHELVED_BOOTSTRAP") == "1" {
		os.Args = append([]string{"tunnex-sandbox-bootstrap"}, os.Args[3:]...)
		main()
		return
	}
	for _, args := range [][]string{
		{"--not-a-flag"},
		{"--server", "https://fixture.invalid", "--sandbox-id", "715a3dc3-6d55-4844-b589-2bc3822ec275", "--generation", "1", "--handoff-dir", filepath.Join(t.TempDir(), "handoff")},
	} {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		cmd := exec.CommandContext(ctx, os.Args[0], append([]string{"-test.run=^TestShelvedBootstrapRefusesBeforeFlagsAndStdin$", "--"}, args...)...)
		cmd.Env = append(os.Environ(), "TUNNEX_TEST_SHELVED_BOOTSTRAP=1", "TUNNEX_SANDBOX_ENABLED=true")
		input, writer, err := os.Pipe()
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		// Leave stdin open and empty: any token read would block until timeout.
		cmd.Stdin = input
		output, runErr := cmd.CombinedOutput()
		input.Close()
		writer.Close()
		cancel()
		exit, ok := runErr.(*exec.ExitError)
		if !ok || exit.ExitCode() != 1 || string(output) != "sandbox development is paused\n" {
			t.Fatalf("args %v: exit=%v output=%q; want immediate shelved refusal", args, runErr, output)
		}
	}
}
