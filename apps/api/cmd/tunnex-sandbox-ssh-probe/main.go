package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"os"
	"time"

	"github.com/tunnexio/tunnex/apps/api/internal/sandboxruntime"
	"golang.org/x/crypto/ssh"
)

// Executed only by the trusted namespace helper, never as a user-selected
// command. The dedicated worker key arrives on stdin, never argv/environment.
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "private SSH probe unavailable")
		os.Exit(1)
	}
}
func run() error {
	if len(os.Args) != 1 {
		return sandboxruntime.ErrInvalid
	}
	decoder := json.NewDecoder(io.LimitReader(os.Stdin, 24577))
	decoder.DisallowUnknownFields()
	var input struct {
		Address       netip.Addr `json:"address"`
		HostPublicKey string     `json:"host_public_key"`
		PrivateKey    string     `json:"private_key"`
	}
	if decoder.Decode(&input) != nil || decoder.Decode(new(any)) != io.EOF || len(input.HostPublicKey) > 8192 || len(input.PrivateKey) > 16384 {
		return sandboxruntime.ErrInvalid
	}
	host, _, options, rest, err := ssh.ParseAuthorizedKey([]byte(input.HostPublicKey))
	if err != nil || len(options) != 0 || len(rest) != 0 {
		return sandboxruntime.ErrInvalid
	}
	identity, err := ssh.ParsePrivateKey([]byte(input.PrivateKey))
	if err != nil {
		return sandboxruntime.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, err := sandboxruntime.ProbePrivateSSH(ctx, input.Address, host, identity)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(result)
}
