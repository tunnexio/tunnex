// Command tunnex is the Tunnex CLI: login/logout, device creation (one-time
// config capture), and the wg-quick up/down wrapper (S5.1).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/tunnexio/tunnex/apps/cli/internal/cli"
)

// version is set from the release tag with -X main.version=<tag>. A source
// build remains "dev" and the Kubernetes lifecycle then requires an explicit
// chart version or local chart path instead of guessing a published artifact.
var version = "dev"

func usage() {
	fmt.Fprint(os.Stderr, `tunnex — self-hosted VPN & Zero Trust

Usage:
  tunnex login  [--server URL] [--device]   sign in (browser; --device for browserless hosts)
  tunnex logout                             revoke the credential and forget it locally
  tunnex device create --name NAME [--full-tunnel]
                                            create a device and capture its one-time config
  tunnex up | down                          bring the WireGuard tunnel up/down (wg-quick)
  tunnex k8s <verb> [flags]                 Kubernetes gateway install and lifecycle
  tunnex version                            print the exact CLI build version
`)
}

func buildVersionLine() string {
	v := strings.TrimSpace(version)
	if v == "" {
		return "unknown"
	}
	return v
}

func writeVersion(out io.Writer) error {
	_, err := fmt.Fprintln(out, buildVersionLine())
	return err
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "login":
		fs := flag.NewFlagSet("login", flag.ExitOnError)
		server := fs.String("server", os.Getenv("TUNNEX_SERVER"), "Tunnex server base URL (or TUNNEX_SERVER)")
		device := fs.Bool("device", false, "use the device-code flow (no local browser)")
		_ = fs.Parse(os.Args[2:])
		if *server == "" {
			err = fmt.Errorf("no server: pass --server https://your-tunnex or set TUNNEX_SERVER")
			break
		}
		s := strings.TrimRight(*server, "/")
		if *device {
			err = cli.LoginDevice(ctx, s)
		} else {
			err = cli.Login(ctx, s)
		}
	case "logout":
		err = cli.Logout(ctx)
	case "device":
		if len(os.Args) < 3 || os.Args[2] != "create" {
			usage()
			os.Exit(2)
		}
		fs := flag.NewFlagSet("device create", flag.ExitOnError)
		name := fs.String("name", "", "device name (required)")
		full := fs.Bool("full-tunnel", false, "route all traffic through the tunnel")
		_ = fs.Parse(os.Args[3:])
		if *name == "" {
			err = fmt.Errorf("--name is required")
			break
		}
		err = cli.CreateDevice(ctx, *name, *full)
	case "up", "down":
		err = cli.WgQuick(os.Args[1])
	case "k8s":
		err = cli.RunK8s(ctx, os.Args[2:], version)
	case "version":
		err = writeVersion(os.Stdout)
	case "-h", "--help", "help":
		usage()
		return
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		// An expired credential prints ONLY the actionable line (S5.1 acceptance),
		// never a raw "error: …" dump.
		if errors.Is(err, cli.ErrCredentialExpired) {
			fmt.Fprintln(os.Stderr, cli.ExpiredCredentialLine)
			os.Exit(1)
		}
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
