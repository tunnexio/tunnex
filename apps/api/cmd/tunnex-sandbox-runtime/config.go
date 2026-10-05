package main

import (
	"bytes"
	"path/filepath"
	"strings"

	"github.com/tunnexio/tunnex/apps/api/internal/sandboxes"
	"github.com/tunnexio/tunnex/apps/api/internal/sandboxruntime"
	"golang.org/x/crypto/ssh"
)

const state = "/var/lib/tunnex-sandbox-qual"
const runtime = "/run/tunnex-sandbox-qual"
const actorSocket = runtime + "/api/control.sock"

const (
	roleCombined  = "combined"
	roleActor     = "actor"
	roleTransport = "transport"
)

type remoteConfig struct{ URL, ServerName, ControllerURI, CertificateFile, PrivateKeyFile, CAFile string }

// Supervision is operator-only and deliberately absent from legacy profiles.
// Both roles share one trusted dedicated OS identity; this is process lifecycle
// separation, not a new credential-isolation boundary.
type supervisionConfig struct {
	Enabled                 bool
	ActorUID, SupervisorUID uint32
	ProbePublicKey          string
}

type config struct {
	StateRoot, RunRoot, ActorControlCgroup                         string `json:",omitempty"`
	Remote                                                         *remoteConfig
	Supervision                                                    *supervisionConfig
	Binding                                                        sandboxes.BoundedRuntimeBinding
	APIUID                                                         uint32
	Server, BootstrapBinary, BootstrapSHA256, CAFile, ProbeKeyFile string
}

type runtimePaths struct{ State, Run, ActorControl string }

func (cfg config) paths() (runtimePaths, error) {
	paths := runtimePaths{State: state, Run: runtime, ActorControl: "/tnxsandboxqual.slice/tunnex-sandbox-qual-actor.service/control"}
	if cfg.StateRoot != "" || cfg.RunRoot != "" {
		if !cleanRoot(cfg.StateRoot) || !cleanRoot(cfg.RunRoot) {
			return runtimePaths{}, sandboxes.ErrInvalid
		}
		paths.State, paths.Run = cfg.StateRoot, cfg.RunRoot
	}
	if paths.State == paths.Run || strings.HasPrefix(paths.State, paths.Run+"/") || strings.HasPrefix(paths.Run, paths.State+"/") {
		return runtimePaths{}, sandboxes.ErrInvalid
	}
	if cfg.ActorControlCgroup != "" {
		paths.ActorControl = cfg.ActorControlCgroup
	}
	if !sandboxruntime.ValidActorControlCgroup(paths.ActorControl) {
		return runtimePaths{}, sandboxes.ErrInvalid
	}
	return paths, nil
}

func cleanRoot(value string) bool {
	return filepath.IsAbs(value) && filepath.Clean(value) == value && value != "/" && !strings.ContainsAny(value, "\x00\n\r")
}

func validateRole(cfg config, role string, uid uint32) (ssh.PublicKey, error) {
	paths, err := cfg.paths()
	if err != nil || uid == 0 || cfg.Binding.Validate() != nil || cfg.APIUID == 0 || cfg.ProbeKeyFile != paths.State+"/worker/main-probe-key" || cfg.CAFile != paths.State+"/worker/main-api-ca.pem" {
		return nil, sandboxes.ErrInvalid
	}
	if role == roleCombined {
		if cfg.Supervision != nil || cfg.APIUID == uid {
			return nil, sandboxes.ErrInvalid
		}
		return nil, nil
	}
	if (role != roleActor && role != roleTransport) || !cfg.Binding.Persistent() || cfg.Supervision == nil || !cfg.Supervision.Enabled || cfg.Supervision.ActorUID != uid || cfg.Supervision.SupervisorUID != uid {
		return nil, sandboxes.ErrInvalid
	}
	if role == roleTransport && cfg.Remote == nil {
		return nil, sandboxes.ErrInvalid
	}
	// The independent delegated scope has the exact qualified workload limits.
	// Broader profiles remain unavailable in this explicit supervision layout.
	for _, profile := range cfg.Binding.Profiles {
		if profile.PIDs != 64 {
			return nil, sandboxes.ErrInvalid
		}
	}
	key, _, options, trailing, err := ssh.ParseAuthorizedKey([]byte(cfg.Supervision.ProbePublicKey))
	if err != nil || key == nil || len(options) != 0 || len(bytes.TrimSpace(trailing)) != 0 || strings.TrimSpace(cfg.Supervision.ProbePublicKey) != strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key))) {
		return nil, sandboxes.ErrInvalid
	}
	return key, nil
}
