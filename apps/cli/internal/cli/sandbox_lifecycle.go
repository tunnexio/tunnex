package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/cli/internal/api"
	"io"
	"net/url"
	"os"
	"time"
)

// SandboxLifecycle uses only an explicitly supplied existing machine bearer.
// It performs a single request: caller-owned idempotency keys and generations
// survive uncertain responses. It never logs in, enrolls or polls/provisions.
func SandboxLifecycle(ctx context.Context, args []string, out io.Writer) error {
	if !SandboxProductAvailable {
		return ErrSandboxShelved
	}
	return sandboxLifecycle(ctx, args, out)
}

// Retain the implementation for deliberate re-entry and historical contract tests.
// TODO(sandbox-reentry): see docs/S-sandbox-shelved-main-reentry.md.
func sandboxLifecycle(ctx context.Context, args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: tunnex sandbox create|get|start|stop|delete --org UUID [--id UUID --generation N --request FILE --idempotency-key KEY]")
	}
	fs := flag.NewFlagSet("sandbox", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	orgRaw := fs.String("org", "", "organization UUID")
	idRaw := fs.String("id", "", "sandbox UUID")
	generation := fs.Int64("generation", 0, "current generation")
	request := fs.String("request", "", "create JSON file")
	key := fs.String("idempotency-key", "", "stable create retry key")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	org, err := uuid.Parse(*orgRaw)
	if err != nil || org == uuid.Nil || fs.NArg() != 0 {
		return errors.New("valid --org UUID required")
	}
	server := os.Getenv("TUNNEX_SERVER")
	token := os.Getenv("TUNNEX_MACHINE_TOKEN")
	u, err := url.Parse(server)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || len(token) < 6 || token[:5] != "tnxm_" {
		return errors.New("set HTTPS TUNNEX_SERVER and existing TUNNEX_MACHINE_TOKEN")
	}
	c, err := NewAuthedClient(Credential{Server: server, Token: token})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 35*time.Second)
	defer cancel()
	var body *api.Sandbox
	switch args[0] {
	case "create":
		if *key == "" || len(*key) > 128 || *request == "" {
			return errors.New("create requires --request FILE and stable --idempotency-key")
		}
		f, err := os.Open(*request)
		if err != nil {
			return err
		}
		defer f.Close()
		dec := json.NewDecoder(io.LimitReader(f, 65537))
		dec.DisallowUnknownFields()
		var input api.SandboxCreate
		if err = dec.Decode(&input); err != nil {
			return errors.New("invalid sandbox create JSON")
		}
		var extra any
		if dec.Decode(&extra) != io.EOF {
			return errors.New("invalid sandbox create JSON")
		}
		r, err := c.CreateSandboxWithResponse(ctx, org, &api.CreateSandboxParams{IdempotencyKey: *key}, input)
		if err != nil {
			return err
		}
		if r.JSON202 == nil {
			return apiErr(r.StatusCode(), r.Body, "sandbox create failed")
		}
		body = r.JSON202
	case "get", "start", "stop", "delete":
		id, err := uuid.Parse(*idRaw)
		if err != nil || id == uuid.Nil {
			return errors.New("valid --id UUID required")
		}
		if args[0] == "get" {
			r, err := c.GetSandboxWithResponse(ctx, org, id)
			if err != nil {
				return err
			}
			if r.JSON200 == nil {
				return apiErr(r.StatusCode(), r.Body, "sandbox read failed")
			}
			body = r.JSON200
		} else {
			if *generation < 1 {
				return errors.New("current --generation required")
			}
			desired := map[string]api.SandboxActionDesiredState{"start": "started", "stop": "stopped", "delete": "deleted"}[args[0]]
			r, err := c.SandboxActionWithResponse(ctx, org, id, api.SandboxAction{DesiredState: desired, Generation: *generation})
			if err != nil {
				return err
			}
			if r.JSON202 == nil {
				return apiErr(r.StatusCode(), r.Body, "sandbox action failed")
			}
			body = r.JSON202
		}
	default:
		return fmt.Errorf("unknown sandbox verb %q", args[0])
	}
	return json.NewEncoder(out).Encode(body)
}
