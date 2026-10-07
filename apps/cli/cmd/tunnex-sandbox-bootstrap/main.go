// Command tunnex-sandbox-bootstrap is preloaded into qualified runtime images.
// It consumes the one-time token from stdin, never command-line arguments.
package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/cli/internal/cli"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
)

func main() {
	// TODO(sandbox-reentry): see docs/S-sandbox-shelved-main-reentry.md.
	// Refuse before parsing flags, reading a token or opening any CA/handoff file.
	if !cli.SandboxProductAvailable {
		fmt.Fprintln(os.Stderr, cli.ErrSandboxShelved)
		os.Exit(1)
	}
	server := flag.String("server", "", "HTTPS control-plane URL")
	directory := flag.String("handoff-dir", "", "new private handoff directory")
	identity := flag.String("sandbox-id", "", "expected sandbox UUID")
	caFile := flag.String("ca-file", "", "optional task-scoped public HTTPS CA PEM; system trust is unchanged")
	generation := flag.Int64("generation", 0, "expected desired generation")
	flag.Parse()
	id, err := uuid.Parse(*identity)
	if err != nil {
		fmt.Fprintln(os.Stderr, "sandbox bootstrap: invalid expected identity")
		os.Exit(1)
	}
	var ca []byte
	if *caFile != "" {
		file, e := os.Open(*caFile)
		if e != nil {
			fmt.Fprintln(os.Stderr, "sandbox bootstrap: invalid CA input")
			os.Exit(1)
		}
		ca, e = io.ReadAll(io.LimitReader(file, 32769))
		file.Close()
		if e != nil || len(ca) == 0 || len(ca) > 32768 {
			fmt.Fprintln(os.Stderr, "sandbox bootstrap: invalid CA input")
			os.Exit(1)
		}
	}
	token, err := io.ReadAll(io.LimitReader(os.Stdin, 67))
	if err != nil || len(token) > 66 {
		fmt.Fprintln(os.Stderr, "sandbox bootstrap: invalid token input")
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	_, err = cli.BootstrapSandbox(ctx, cli.SandboxBootstrapOptions{Server: *server, Token: strings.TrimSpace(string(token)), HandoffDir: *directory, SandboxID: id, Generation: *generation, CACertificatePEM: ca})
	if err != nil {
		fmt.Fprintln(os.Stderr, "sandbox bootstrap: handoff could not be confirmed; reconcile the existing operation")
		os.Exit(1)
	}
}
