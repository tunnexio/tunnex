package http

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
	"github.com/tunnexio/tunnex/apps/api/internal/vault"
)

// vaultBodyLimit admits the largest valid secret (16,384 characters) at its worst-case JSON escaping
// (an astral character escapes to 12 bytes: 196,608 bytes) plus every other field (VAULT-UX-1 V17).
const vaultBodyLimit int64 = 256 << 10

func isVaultRequest(r *http.Request) bool {
	parts := strings.Split(r.URL.Path, "/")
	return len(parts) >= 6 && parts[1] == "api" && parts[2] == "v1" && parts[3] == "organizations" && parts[5] == "vault"
}

// Validator diagnostics may include body values. Never echo them for Vault.
func vaultRequestError(w http.ResponseWriter, r *http.Request, err error, status int) bool {
	if !isVaultRequest(r) {
		return false
	}
	if r.ContentLength > vaultBodyLimit || strings.Contains(err.Error(), "http: request body too large") {
		apierr.Write(w, r, apierr.New(http.StatusRequestEntityTooLarge, "vault_request_too_large", "Vault request is too large. Secrets can be up to 16,384 characters."))
	} else {
		apierr.Write(w, r, apierr.New(status, "invalid_vault_request", "Invalid Vault request"))
	}
	return true
}

func (s apiServer) vaultContext(ctx context.Context, org uuid.UUID, perm rbac.Permission) (context.Context, *authctx.Principal, error) {
	ctx, err := authorize(ctx, org, perm)
	if err != nil {
		return ctx, nil, err
	}
	p, err := requireVerifiedUser(ctx)
	if err != nil {
		return ctx, nil, err
	}
	if p.UserID == uuid.Nil || p.SessionID == "" || p.IsMachine() || p.IsAgent() || (p.AuthMethod != authctx.AuthLocalPassword && p.AuthMethod != authctx.AuthSSO) {
		return ctx, nil, apierr.Forbidden("vault_browser_session_required", "Vault requires a verified browser login")
	}
	if s.vault == nil {
		return ctx, nil, apierr.New(503, "vault_unavailable", "Vault is unavailable")
	}
	return ctx, p, nil
}

// Authenticate before schema buffering, including malformed IDs and bodies.
func (s apiServer) vaultRequestGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isVaultRequest(r) {
			next.ServeHTTP(w, r)
			return
		}
		if _, ok := authctx.PrincipalFrom(r.Context()); !ok {
			apierr.Write(w, r, apierr.New(401, "unauthenticated", "authentication required"))
			return
		}
		org, err := uuid.Parse(strings.Split(r.URL.Path, "/")[4])
		if err != nil {
			apierr.Write(w, r, apierr.BadRequest("invalid_vault_request", "Invalid Vault request"))
			return
		}
		perm := rbac.PermVaultUse
		if strings.HasSuffix(r.URL.Path, "/subjects") || (r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/services")) {
			perm = rbac.PermVaultAssign
		}
		ctx, _, err := s.vaultContext(r.Context(), org, perm)
		if err != nil {
			apierr.Write(w, r, err)
			return
		}
		if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodPatch {
			body, readErr := io.ReadAll(r.Body)
			if readErr != nil {
				vaultRequestError(w, r, readErr, http.StatusBadRequest)
				return
			}
			trimmed := bytes.TrimSpace(body)
			if len(trimmed) == 0 || trimmed[0] != '{' || !json.Valid(body) {
				apierr.Write(w, r, apierr.BadRequest("invalid_vault_request", "Invalid Vault request"))
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(body))
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// vaultRevealReauthScope names the Vault reveal password-failure budget.
const vaultRevealReauthScope = "vault_reveal"

func vaultPage(limit, offset *int32) (int32, int32) {
	l, o := int32(50), int32(0)
	if limit != nil {
		l = *limit
	}
	if offset != nil {
		o = *offset
	}
	return l, o
}

func (s apiServer) ListVaultEntries(ctx context.Context, req api.ListVaultEntriesRequestObject) (api.ListVaultEntriesResponseObject, error) {
	ctx, p, err := s.vaultContext(ctx, req.OrgId, rbac.PermVaultUse)
	if err != nil {
		return nil, err
	}
	limit, offset := vaultPage(req.Params.Limit, req.Params.Offset)
	q := ""
	if req.Params.Q != nil {
		q = *req.Params.Q
	}
	view := "all"
	if req.Params.View != nil {
		view = string(*req.Params.View)
	}
	out, err := s.vault.ListView(ctx, req.OrgId, p.UserID, limit, offset, q, view)
	if err != nil {
		return nil, err
	}
	// Tell the console what a shared reveal will ask for. Best effort: when it cannot be read the reveal
	// still enforces it and the console handles the refusal.
	if parent, perr := s.mfaParent(ctx); perr == nil {
		if r, rerr := s.installationReauthFor(ctx, p.UserID, &parent); rerr == nil {
			out.Reauthentication = &api.VaultReauthentication{Password: r.password, Mfa: r.mfa || r.ssoMFA, Available: r.available()}
		}
	}
	return api.ListVaultEntries200JSONResponse(out), nil
}

func (s apiServer) CreateVaultEntry(ctx context.Context, req api.CreateVaultEntryRequestObject) (api.CreateVaultEntryResponseObject, error) {
	ctx, p, err := s.vaultContext(ctx, req.OrgId, rbac.PermVaultUse)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_vault_request", "Request body required")
	}
	out, err := s.vault.Create(ctx, req.OrgId, p.UserID, *req.Body)
	if err != nil {
		return nil, err
	}
	return api.CreateVaultEntry201JSONResponse(out), nil
}

func (s apiServer) QuickCreateVaultEntry(ctx context.Context, req api.QuickCreateVaultEntryRequestObject) (api.QuickCreateVaultEntryResponseObject, error) {
	ctx, p, err := s.vaultContext(ctx, req.OrgId, rbac.PermVaultUse)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_vault_request", "Request body required")
	}
	out, err := s.vault.QuickCreate(ctx, req.OrgId, p.UserID, *req.Body)
	if err != nil {
		return nil, err
	}
	return api.QuickCreateVaultEntry200JSONResponse(out), nil
}

func (s apiServer) ConfigureVaultEntry(ctx context.Context, req api.ConfigureVaultEntryRequestObject) (api.ConfigureVaultEntryResponseObject, error) {
	ctx, p, err := s.vaultContext(ctx, req.OrgId, rbac.PermVaultUse)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_vault_request", "Request body required")
	}
	out, err := s.vault.Configure(ctx, req.OrgId, p.UserID, req.EntryId, *req.Body)
	if err != nil {
		return nil, err
	}
	return api.ConfigureVaultEntry200JSONResponse(out), nil
}

func (s apiServer) UpdateVaultEntry(ctx context.Context, req api.UpdateVaultEntryRequestObject) (api.UpdateVaultEntryResponseObject, error) {
	ctx, p, err := s.vaultContext(ctx, req.OrgId, rbac.PermVaultUse)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_vault_request", "Request body required")
	}
	out, err := s.vault.Update(ctx, req.OrgId, p.UserID, req.EntryId, *req.Body)
	if err != nil {
		return nil, err
	}
	return api.UpdateVaultEntry200JSONResponse(out), nil
}

func (s apiServer) UpdateVaultEntryDetails(ctx context.Context, req api.UpdateVaultEntryDetailsRequestObject) (api.UpdateVaultEntryDetailsResponseObject, error) {
	ctx, p, err := s.vaultContext(ctx, req.OrgId, rbac.PermVaultUse)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_vault_request", "Request body required")
	}
	out, err := s.vault.UpdateDetails(ctx, req.OrgId, p.UserID, req.EntryId, *req.Body)
	if err != nil {
		return nil, err
	}
	return api.UpdateVaultEntryDetails200JSONResponse(out), nil
}

func (s apiServer) DeleteVaultEntry(ctx context.Context, req api.DeleteVaultEntryRequestObject) (api.DeleteVaultEntryResponseObject, error) {
	ctx, p, err := s.vaultContext(ctx, req.OrgId, rbac.PermVaultUse)
	if err != nil {
		return nil, err
	}
	if err = s.vault.Delete(ctx, req.OrgId, p.UserID, req.EntryId, req.Params.ExpectedVersion); err != nil {
		return nil, err
	}
	return api.DeleteVaultEntry204Response{}, nil
}

func (s apiServer) ListVaultVersions(ctx context.Context, req api.ListVaultVersionsRequestObject) (api.ListVaultVersionsResponseObject, error) {
	ctx, p, err := s.vaultContext(ctx, req.OrgId, rbac.PermVaultUse)
	if err != nil {
		return nil, err
	}
	limit, offset := vaultPage(req.Params.Limit, req.Params.Offset)
	out, err := s.vault.Versions(ctx, req.OrgId, p.UserID, req.EntryId, limit, offset)
	if err != nil {
		return nil, err
	}
	return api.ListVaultVersions200JSONResponse(out), nil
}

func (s apiServer) RevealVaultEntry(ctx context.Context, req api.RevealVaultEntryRequestObject) (api.RevealVaultEntryResponseObject, error) {
	ctx, p, err := s.vaultContext(ctx, req.OrgId, rbac.PermVaultUse)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_vault_request", "Request body required")
	}
	reveal := vault.RevealRequest{}
	if req.Body.Version != nil {
		reveal.Version = *req.Body.Version
	}
	if req.Body.Purpose != nil {
		reveal.Purpose = string(*req.Body.Purpose)
	}
	// Every reveal or copy is budgeted per person and organization (V4), before any other work.
	if s.sessions == nil {
		return nil, apierr.New(503, "vault_unavailable", "Vault is unavailable")
	}
	allowed, err := s.sessions.VaultRevealAllowed(ctx, req.OrgId, p.UserID)
	if err != nil {
		return nil, apierr.New(503, "vault_unavailable", "Vault is unavailable")
	}
	if !allowed {
		return nil, apierr.New(http.StatusTooManyRequests, "vault_reveal_rate_limited", "You've opened a lot of secrets in a short time. Wait a minute and try again.")
	}
	// Shared (assigned) entries need recent re-authentication, with the same rules as every other
	// step-up action. The vault service runs this inside its transaction, only for assigned entries.
	currentPassword := req.Body.CurrentPassword
	reveal.StepUp = func(ctx context.Context) error {
		return s.requireRecentReauthentication(ctx, p, currentPassword, vaultRevealReauthScope, "open a shared Vault credential")
	}
	out, err := s.vault.Reveal(ctx, req.OrgId, p.UserID, req.EntryId, reveal)
	if err != nil {
		return nil, err
	}
	return api.RevealVaultEntry200JSONResponse(out), nil
}

func (s apiServer) ListVaultServices(ctx context.Context, req api.ListVaultServicesRequestObject) (api.ListVaultServicesResponseObject, error) {
	ctx, p, err := s.vaultContext(ctx, req.OrgId, rbac.PermVaultUse)
	if err != nil {
		return nil, err
	}
	out, err := s.vault.Services(ctx, req.OrgId, p.UserID)
	if err != nil {
		return nil, err
	}
	return api.ListVaultServices200JSONResponse(out), nil
}

func (s apiServer) CreateVaultService(ctx context.Context, req api.CreateVaultServiceRequestObject) (api.CreateVaultServiceResponseObject, error) {
	ctx, p, err := s.vaultContext(ctx, req.OrgId, rbac.PermVaultAssign)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_vault_request", "Request body required")
	}
	out, err := s.vault.AddService(ctx, req.OrgId, p.UserID, req.Body.Name)
	if err != nil {
		return nil, err
	}
	return api.CreateVaultService201JSONResponse(out), nil
}

func (s apiServer) ListVaultSubjects(ctx context.Context, req api.ListVaultSubjectsRequestObject) (api.ListVaultSubjectsResponseObject, error) {
	ctx, p, err := s.vaultContext(ctx, req.OrgId, rbac.PermVaultAssign)
	if err != nil {
		return nil, err
	}
	out, err := s.vault.Subjects(ctx, req.OrgId, p.UserID)
	if err != nil {
		return nil, err
	}
	return api.ListVaultSubjects200JSONResponse(out), nil
}
