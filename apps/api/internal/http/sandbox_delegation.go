package http

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
	"github.com/tunnexio/tunnex/apps/api/internal/sandboxes"
)

type sandboxDelegationRepository interface {
	SetDelegationEnabled(context.Context, uuid.UUID, uuid.UUID, bool) error
	IssueDelegation(context.Context, uuid.UUID, uuid.UUID, sandboxes.Delegation) (sandboxes.Delegation, error)
	RevokeDelegation(context.Context, uuid.UUID, uuid.UUID, uuid.UUID) error
}

// RegisterSandboxDelegationRoutes must run on the authenticated API router with
// the accompanying OpenAPI paths installed. It adds no authentication mechanism.
func RegisterSandboxDelegationRoutes(r chi.Router, repo sandboxDelegationRepository) {
	r.Put("/api/v1/organizations/{orgId}/sandbox-delegation-settings", sandboxDelegationHandler(repo, "settings"))
	r.Post("/api/v1/organizations/{orgId}/sandbox-delegations", sandboxDelegationHandler(repo, "issue"))
	r.Delete("/api/v1/organizations/{orgId}/sandbox-delegations/{delegationId}", sandboxDelegationHandler(repo, "revoke"))
}
func sandboxDelegationBody(w http.ResponseWriter, r *http.Request, v any) error {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16384))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return apierr.BadRequest("invalid_sandbox_delegation", "invalid delegation body")
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		return apierr.BadRequest("invalid_sandbox_delegation", "invalid delegation body")
	}
	return nil
}
func sandboxDelegationHandler(repo sandboxDelegationRepository, operation string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		org, err := uuid.Parse(chi.URLParam(r, "orgId"))
		if err != nil || org == uuid.Nil {
			apierr.Write(w, r, apierr.BadRequest("invalid_organization", "invalid organization"))
			return
		}
		ctx, err := authorize(r.Context(), org, rbac.PermSandboxDelegateManage)
		if err != nil {
			apierr.Write(w, r, err)
			return
		}
		p, ok := authctx.PrincipalFrom(ctx)
		if !ok || p.IsMachine() || p.IsAgent() || p.UserID == uuid.Nil {
			apierr.Write(w, r, apierr.New(403, "forbidden", "human delegation administration required"))
			return
		}
		if repo == nil {
			apierr.Write(w, r, sandboxUnavailable())
			return
		}
		var result any
		status := http.StatusNoContent
		switch operation {
		case "settings":
			var body struct {
				Enabled *bool `json:"enabled"`
			}
			err = sandboxDelegationBody(w, r, &body)
			if err == nil && body.Enabled == nil {
				err = apierr.BadRequest("invalid_sandbox_delegation", "enabled is required")
			}
			if err == nil {
				err = repo.SetDelegationEnabled(ctx, org, p.UserID, *body.Enabled)
			}
		case "issue":
			var body struct {
				MachineID        uuid.UUID         `json:"machine_id"`
				TemplateID       uuid.UUID         `json:"template_id"`
				MaxTTLSeconds    int32             `json:"max_ttl_seconds"`
				MaxActive        int32             `json:"max_active"`
				MaximumScope     []sandboxes.Scope `json:"maximum_scope"`
				SkillRevisionIDs []uuid.UUID       `json:"skill_revision_ids"`
				ExpiresAt        time.Time         `json:"expires_at"`
			}
			err = sandboxDelegationBody(w, r, &body)
			if err == nil {
				result, err = repo.IssueDelegation(ctx, org, p.UserID, sandboxes.Delegation{OrgID: org, OwnerID: p.UserID, MachineID: body.MachineID, TemplateID: body.TemplateID, MaxTTLSeconds: body.MaxTTLSeconds, MaxActive: body.MaxActive, MaximumScope: body.MaximumScope, SkillRevisionIDs: body.SkillRevisionIDs, ExpiresAt: body.ExpiresAt})
				status = http.StatusCreated
			}
		case "revoke":
			id, e := uuid.Parse(chi.URLParam(r, "delegationId"))
			if e != nil || id == uuid.Nil {
				err = apierr.BadRequest("invalid_sandbox_delegation", "invalid delegation ID")
			} else {
				err = repo.RevokeDelegation(ctx, org, p.UserID, id)
			}
		}
		if err != nil {
			if errors.Is(err, sandboxes.ErrConflict) {
				err = apierr.Conflict("sandbox_delegation_conflict", "revoke the existing active delegation first")
			} else if errors.Is(err, sandboxes.ErrDisabled) {
				err = apierr.New(403, "sandbox_delegation_disabled", "organization delegation is disabled")
			}
			if _, ok := err.(*apierr.Error); !ok {
				err = sandboxError(err)
			}
			apierr.Write(w, r, err)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		if result != nil {
			w.Header().Set("Content-Type", "application/json")
		}
		w.WriteHeader(status)
		if result != nil {
			_ = json.NewEncoder(w).Encode(result)
		}
	}
}
