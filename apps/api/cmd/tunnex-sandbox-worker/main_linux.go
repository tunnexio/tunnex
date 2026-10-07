//go:build linux

// The qualification worker runs independently of the API and human SSH login.
// Its private configuration contains newly generated fixture secrets only.
package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tunnexio/tunnex/apps/api/db"
	appcrypto "github.com/tunnexio/tunnex/apps/api/internal/crypto"
	"github.com/tunnexio/tunnex/apps/api/internal/dbconn"
	"github.com/tunnexio/tunnex/apps/api/internal/nodes"
	"github.com/tunnexio/tunnex/apps/api/internal/policy"
	"github.com/tunnexio/tunnex/apps/api/internal/sandboxes"
	"github.com/tunnexio/tunnex/apps/api/internal/sandboxproduct"
	"github.com/tunnexio/tunnex/apps/api/internal/sandboxruntime"
	"golang.org/x/crypto/ssh"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
)

type config struct {
	OrgID           uuid.UUID `json:"org_id"`
	GatewayID       uuid.UUID `json:"gateway_id"`
	DatabaseURL     string    `json:"database_url"`
	MasterKey       string    `json:"master_key"`
	Server          string    `json:"server"`
	BootstrapBinary string    `json:"bootstrap_binary"`
	BootstrapSHA256 string    `json:"bootstrap_sha256"`
	CAFile          string    `json:"ca_file"`
	ProbeKeyFile    string    `json:"probe_key_file"`
}

const state = "/var/lib/tunnex-sandbox-qual"
const runtime = "/run/tunnex-sandbox-qual"

func privateFile(path string, limit int64) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, sandboxes.ErrInvalid
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > limit {
		return nil, sandboxes.ErrInvalid
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(os.Geteuid()) {
		return nil, sandboxes.ErrInvalid
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, sandboxes.ErrInvalid
	}
	defer file.Close()
	current, err := file.Stat()
	if err != nil || !os.SameFile(info, current) {
		return nil, sandboxes.ErrInvalid
	}
	return io.ReadAll(io.LimitReader(file, limit+1))
}
func openOwned(path string) (*os.Root, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, sandboxes.ErrInvalid
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(os.Geteuid()) {
		return nil, sandboxes.ErrInvalid
	}
	return os.OpenRoot(path)
}
func main() {
	// TODO(sandbox-reentry): docs/S-sandbox-shelved-main-reentry.md.
	if sandboxproduct.Shelved {
		fmt.Fprintln(os.Stderr, sandboxproduct.Message)
		os.Exit(1)
	}
	configPath := flag.String("fixture-config", state+"/worker/config.json", "private task fixture config")
	supplemental := flag.Bool("qualification-supplemental", false, "explicit approved supplemental Minimal/Python identities only")
	action := flag.String("qualification-action", "", "explicit existing-fixture action: preflight/migrate/restore-schema/create/status/start/stop/delete/finish")
	image := flag.String("qualification-image", "", "exact approved native AMD64 config digest")
	sandbox := flag.String("qualification-sandbox", "", "owned qualification sandbox UUID")
	generation := flag.Int64("qualification-generation", 0, "expected lifecycle generation")
	baseline := flag.Uint("qualification-schema-baseline", 0, "exact prior fixture schema, restore only after all workloads deleted")
	ttl := flag.Int("qualification-ttl-seconds", 300, "300 or900 seconds, within approved900 ceiling")
	flag.Parse()
	if *supplemental && *action != "create" {
		fail()
	}
	if flag.NArg() != 0 || os.Geteuid() == 0 || *configPath != state+"/worker/config.json" {
		fail()
	}
	raw, err := privateFile(*configPath, 32768)
	if err != nil {
		fail()
	}
	var cfg config
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&cfg) != nil || decoder.Decode(new(any)) != io.EOF || cfg.OrgID == uuid.Nil || cfg.GatewayID == uuid.Nil || cfg.DatabaseURL == "" || cfg.ProbeKeyFile != state+"/worker/probe_key" || cfg.CAFile != state+"/worker/fixture-ca.pem" {
		fail()
	}
	master, err := base64.StdEncoding.DecodeString(cfg.MasterKey)
	if err != nil {
		fail()
	}
	sealer, err := appcrypto.NewSealer(master)
	if err != nil {
		fail()
	}
	probeKey, err := privateFile(cfg.ProbeKeyFile, 16384)
	if err != nil {
		fail()
	}
	identity, err := ssh.ParsePrivateKey(probeKey)
	if err != nil {
		fail()
	}
	assetsRoot, err := openOwned(state + "/workload-assets")
	if err != nil {
		fail()
	}
	defer assetsRoot.Close()
	controlRoot, err := openOwned(state + "/worker/control")
	if err != nil {
		fail()
	}
	defer controlRoot.Close()
	assets, err := sandboxruntime.NewFilesystemAssets(assetsRoot)
	if err != nil {
		fail()
	}
	provider, err := sandboxruntime.NewPodmanWithAssets(sandboxruntime.RootlessRunner{Root: state + "/worker/storage", RunRoot: runtime + "/worker/storage", Home: state + "/worker/home"}, assets)
	if err != nil {
		fail()
	}
	files, err := sandboxes.NewFileBootstrapTransport(controlRoot, cfg.Server, sandboxes.CommandBootstrap{Binary: cfg.BootstrapBinary, SHA256: cfg.BootstrapSHA256, CAFile: cfg.CAFile})
	if err != nil {
		fail()
	}
	network := &sandboxes.SocketNetwork{Provider: provider, Files: files, Socket: runtime + "/helper/control.sock", ProbePrivateKey: probeKey}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	poolCfg, err := dbconn.ParsePoolConfig(cfg.DatabaseURL)
	if err != nil {
		fail()
	}
	poolCfg.MaxConns = 4
	poolCfg.MinConns = 0
	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		fail()
	}
	defer pool.Close()
	if pool.Ping(ctx) != nil {
		fail()
	}
	store := sandboxes.NewStore(pool).WithQualificationOrg(cfg.OrgID)
	op, err := sandboxes.NewQualificationProfileOperator(ctx, store, cfg.OrgID, cfg.GatewayID)
	if err != nil {
		fail()
	}
	if *action != "" {
		if *action == "preflight" {
			if *image != "" || *sandbox != "" || *generation != 0 || *baseline != 0 {
				fail()
			}
			var version uint
			var dirty bool
			var retained int
			if pool.QueryRow(ctx, `SELECT version,dirty FROM schema_migrations`).Scan(&version, &dirty) != nil || pool.QueryRow(ctx, `SELECT count(*) FROM sandboxes WHERE observed_state<>'deleted'`).Scan(&retained) != nil {
				fail()
			}
			if json.NewEncoder(os.Stdout).Encode(struct {
				Org, Gateway uuid.UUID
				Schema       uint
				Dirty        bool
				Retained     int
			}{cfg.OrgID, cfg.GatewayID, version, dirty, retained}) != nil {
				fail()
			}
			return
		}
		if *action == "restore-schema" {
			if *image != "" || *sandbox != "" || *generation != 0 || *baseline < 175 || *baseline > 177 {
				fail()
			}
			var retained int
			var version uint
			var dirty bool
			if pool.QueryRow(ctx, `SELECT count(*) FROM sandboxes WHERE observed_state<>'deleted'`).Scan(&retained) != nil || retained != 0 || pool.QueryRow(ctx, `SELECT version,dirty FROM schema_migrations`).Scan(&version, &dirty) != nil || version != 178 || dirty {
				fail()
			}
			if db.MigrateTo(cfg.DatabaseURL, *baseline) != nil {
				fail()
			}
			fmt.Println(`{"fixture_schema_restored":true}`)
			return
		}
		if *baseline != 0 {
			fail()
		}
		if *action == "migrate" {
			if *image != "" || *sandbox != "" || *generation != 0 || db.Up(cfg.DatabaseURL) != nil {
				fail()
			}
			fmt.Println(`{"migration":"complete"}`)
			return
		}
		var out sandboxes.Sandbox
		if *action == "create" {
			if *sandbox != "" || *generation != 0 {
				fail()
			}
			var input struct {
				SSHPublicKeys []string `json:"ssh_public_keys"`
			}
			decoder := json.NewDecoder(io.LimitReader(os.Stdin, 32769))
			decoder.DisallowUnknownFields()
			if decoder.Decode(&input) != nil || decoder.Decode(new(any)) != io.EOF {
				fail()
			}
			if *ttl != 300 && *ttl != 900 {
				fail()
			}
			if *supplemental {
				out, _, err = op.CreateSupplementalWithTTL(ctx, *image, input.SSHPublicKeys, int32(*ttl))
			} else {
				out, _, err = op.CreateWithTTL(ctx, *image, input.SSHPublicKeys, int32(*ttl))
			}
		} else {
			if *image != "" {
				fail()
			}
			id, parseErr := uuid.Parse(*sandbox)
			if parseErr != nil {
				fail()
			}
			switch *action {
			case "status":
				if *generation != 0 {
					fail()
				}
				out, err = op.Status(ctx, id)
			case "finish":
				if *generation != 0 {
					fail()
				}
				out, err = op.Status(ctx, id)
				if err == nil && out.State == sandboxes.StateDeleted && out.DesiredState == "deleted" {
					if _, inspectErr := provider.Inspect(ctx, id); !errors.Is(inspectErr, sandboxruntime.ErrMissing) {
						fail()
					}
					if assetsRoot.RemoveAll(id.String()) != nil || controlRoot.RemoveAll(id.String()) != nil {
						fail()
					}
					err = op.Finish(ctx, id)
				} else {
					fail()
				}
			case "start", "stop", "delete":
				desired := map[string]string{"start": "started", "stop": "stopped", "delete": "deleted"}[*action]
				out, err = op.SetDesired(ctx, id, *generation, desired)
			default:
				fail()
			}
		}
		if err != nil {
			fail()
		}
		public := struct {
			ID         uuid.UUID                 `json:"id"`
			Desired    string                    `json:"desired"`
			State      sandboxes.State           `json:"state"`
			Generation int64                     `json:"generation"`
			Connection *sandboxes.ConnectionInfo `json:"connection,omitempty"`
		}{out.Identity.ID, out.DesiredState, out.State, out.Revision, out.Connection}
		if json.NewEncoder(os.Stdout).Encode(public) != nil {
			fail()
		}
		return
	}
	if *image != "" || *sandbox != "" || *generation != 0 || *baseline != 0 {
		fail()
	}
	// Static community fixture rules only. The full API provider remains the
	// production canonical source; no paid entitlement or inference proxy added.
	policies := nodes.NewService(pool, nil, nil)
	policies.SetPolicyProvider(policy.NewService(pool))
	initial := &sandboxes.InitialLaunchCoordinator{Store: store, Provider: provider, AssetsRoot: assetsRoot, Assets: assets, Files: files, Network: network, Probe: network, ProbeIdentity: identity, Policies: policies, Sealer: sealer, GatewayID: cfg.GatewayID}
	cleanup := &sandboxes.PrivateNetworkCleanup{Store: store, Network: network, Gateway: network, Files: files, Policies: policies}
	worker := &sandboxes.QualificationWorker{Store: store, OrgID: cfg.OrgID, Initial: initial, Provider: provider, Cleanup: cleanup}
	if err = worker.Run(ctx, func(id uuid.UUID, failure error) {
		stage := "reconcile"
		var staged *sandboxes.LaunchStageError
		if errors.As(failure, &staged) {
			stage = staged.Stage
		}
		var providerStep *sandboxruntime.ProviderStepError
		if errors.As(failure, &providerStep) {
			stage += "/" + providerStep.Step
		}
		var networkError *sandboxes.NetworkHelperError
		if errors.As(failure, &networkError) {
			stage += "/helper-" + networkError.Code
		}
		code := "adapter"
		for label, target := range map[string]error{"invalid": sandboxes.ErrInvalid, "conflict": sandboxes.ErrConflict, "disabled": sandboxes.ErrDisabled, "forbidden": sandboxes.ErrForbidden, "provider-invalid": sandboxruntime.ErrInvalid, "provider-unavailable": sandboxruntime.ErrUnavailable, "provider-ownership": sandboxruntime.ErrOwnership} {
			if errors.Is(failure, target) {
				code = label
				break
			}
		}
		fmt.Fprintf(os.Stderr, "sandbox qualification reconciliation pending sandbox=%s stage=%s code=%s\n", id, stage, code)
	}); err != nil && ctx.Err() == nil {
		fail()
	}
}
func fail() { fmt.Fprintln(os.Stderr, "sandbox qualification worker unavailable"); os.Exit(1) }
