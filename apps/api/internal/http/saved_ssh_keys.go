package http

import (
	"context"
	"errors"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
	"github.com/tunnexio/tunnex/apps/api/internal/sandboxes"
)

type savedSSHKeyRepository interface {
	ListSavedSSHKeys(context.Context, uuid.UUID) ([]sandboxes.SavedSSHKey, error)
	SaveSSHKey(context.Context, uuid.UUID, string, string) (sandboxes.SavedSSHKey, error)
	ChangeSavedSSHKey(context.Context, uuid.UUID, uuid.UUID, bool) error
}

func savedKeyResponse(v sandboxes.SavedSSHKey) api.SavedSSHKey {
	return api.SavedSSHKey{Id: v.ID, Name: v.Name, PublicKey: v.PublicKey, Fingerprint: v.Fingerprint, IsDefault: v.IsDefault}
}
func (s apiServer) ListSavedSSHKeys(ctx context.Context, req api.ListSavedSSHKeysRequestObject) (api.ListSavedSSHKeysResponseObject, error) {
	user, err := s.sandboxActor(ctx, req.OrgId, rbac.PermSandboxView)
	if err != nil {
		return nil, err
	}
	repo, ok := s.sandboxes.(savedSSHKeyRepository)
	if !ok {
		return nil, sandboxUnavailable()
	}
	items, err := repo.ListSavedSSHKeys(ctx, user)
	if err != nil {
		return nil, sandboxError(err)
	}
	out := api.SavedSSHKeyList{Items: []api.SavedSSHKey{}}
	for _, v := range items {
		out.Items = append(out.Items, savedKeyResponse(v))
	}
	return api.ListSavedSSHKeys200JSONResponse(out), nil
}
func (s apiServer) SaveSSHKey(ctx context.Context, req api.SaveSSHKeyRequestObject) (api.SaveSSHKeyResponseObject, error) {
	user, err := s.sandboxActor(ctx, req.OrgId, rbac.PermSandboxCreate)
	if err != nil {
		return nil, err
	}
	repo, ok := s.sandboxes.(savedSSHKeyRepository)
	if !ok {
		return nil, sandboxUnavailable()
	}
	if req.Body == nil {
		return nil, sandboxError(sandboxes.ErrInvalid)
	}
	v, err := repo.SaveSSHKey(ctx, user, req.Body.Name, req.Body.PublicKey)
	if err != nil {
		if errors.Is(err, sandboxes.ErrConflict) {
			return nil, apierr.Conflict("saved_ssh_key_duplicate", "this public key is already saved")
		}
		if errors.Is(err, sandboxes.ErrInvalid) {
			return nil, apierr.BadRequest("invalid_saved_ssh_key", "use a name and one valid SSH public key")
		}
		return nil, sandboxError(err)
	}
	return api.SaveSSHKey200JSONResponse(savedKeyResponse(v)), nil
}
func (s apiServer) changeSavedKey(ctx context.Context, org, id uuid.UUID, def bool) error {
	user, err := s.sandboxActor(ctx, org, rbac.PermSandboxCreate)
	if err != nil {
		return err
	}
	repo, ok := s.sandboxes.(savedSSHKeyRepository)
	if !ok {
		return sandboxUnavailable()
	}
	if err = repo.ChangeSavedSSHKey(ctx, user, id, def); err != nil {
		return sandboxError(err)
	}
	return nil
}
func (s apiServer) DeleteSavedSSHKey(ctx context.Context, req api.DeleteSavedSSHKeyRequestObject) (api.DeleteSavedSSHKeyResponseObject, error) {
	if err := s.changeSavedKey(ctx, req.OrgId, req.KeyId, false); err != nil {
		return nil, err
	}
	return api.DeleteSavedSSHKey204Response{}, nil
}
func (s apiServer) DefaultSavedSSHKey(ctx context.Context, req api.DefaultSavedSSHKeyRequestObject) (api.DefaultSavedSSHKeyResponseObject, error) {
	if err := s.changeSavedKey(ctx, req.OrgId, req.KeyId, true); err != nil {
		return nil, err
	}
	return api.DefaultSavedSSHKey204Response{}, nil
}
