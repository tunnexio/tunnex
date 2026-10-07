package main

import (
	"context"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestShelvedFixtureStreamRefusesBeforeFlagsAndDial(t *testing.T) {
	if os.Getenv("TUNNEX_TEST_SHELVED_FIXTURE_STREAM") == "1" {
		os.Args = append([]string{"tunnex-sandbox-fixture-stream"}, os.Args[3:]...)
		main()
		return
	}
	for _, args := range [][]string{{"--not-a-flag"}, {"--source", "10.254.242.2", "--target", "10.254.242.3"}} {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		cmd := exec.CommandContext(ctx, os.Args[0], append([]string{"-test.run=^TestShelvedFixtureStreamRefusesBeforeFlagsAndDial$", "--"}, args...)...)
		cmd.Env = append(os.Environ(), "TUNNEX_TEST_SHELVED_FIXTURE_STREAM=1", "TUNNEX_SANDBOX_ENABLED=true")
		output, runErr := cmd.CombinedOutput()
		cancel()
		exit, ok := runErr.(*exec.ExitError)
		if !ok || exit.ExitCode() != 1 || string(output) != "sandbox development is paused\n" {
			t.Fatalf("args %v: exit=%v output=%q; want shelved refusal before dialing", args, runErr, output)
		}
	}
}
