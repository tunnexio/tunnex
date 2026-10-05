package main

import (
	"context"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/config"
	apphttp "github.com/tunnexio/tunnex/apps/api/internal/http"
	"github.com/tunnexio/tunnex/apps/api/internal/sandboxes"
)

type sandboxModule struct {
	state         string
	store         *sandboxes.Store
	enrollment    *sandboxes.RunnerEnrollmentService
	qualification *sandboxes.RunnerQualificationService
	available     func() bool
	wake          func()
	run           func(context.Context, func(uuid.UUID, error)) error
	close         func() error
}

// configure is intentionally lazy: off cannot construct a worker, listener,
// certificate client, timer or sandbox store. A failed guard never proceeds.
func initializeSandboxModule(c config.Config, retired func() error, configure func() (sandboxModule, error)) (sandboxModule, error) {
	if err := c.ValidateSandboxModule(); err != nil {
		return sandboxModule{}, err
	}
	state := c.SandboxModuleState()
	if state == "disabled" {
		if err := retired(); err != nil {
			return sandboxModule{}, err
		}
		return sandboxModule{state: state, available: func() bool { return false }}, nil
	}
	m, err := configure()
	if err != nil {
		return sandboxModule{}, err
	}
	m.state = state
	if state == "draining" {
		m.available = func() bool { return false }
	}
	return m, nil
}
func (m sandboxModule) deps() apphttp.Deps {
	d := apphttp.Deps{SandboxModuleState: m.state, SandboxProvisioningReady: m.available, SandboxSkillsReady: m.available, SandboxWake: m.wake}
	if m.enrollment != nil {
		d.SandboxRunnerEnrollment = m.enrollment
	}
	if m.qualification != nil {
		d.SandboxRunnerQualification = m.qualification
	}
	if m.store != nil {
		d.Sandboxes = m.store
	}
	return d
}
