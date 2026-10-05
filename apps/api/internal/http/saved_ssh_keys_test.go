package http

import (
	"context"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
	"github.com/tunnexio/tunnex/apps/api/internal/sandboxes"
	"testing"
)

type savedKeyStub struct {
	sandboxStub
	user      uuid.UUID
	key       uuid.UUID
	defaulted bool
}

func (f *savedKeyStub) ListSavedSSHKeys(_ context.Context, u uuid.UUID) ([]sandboxes.SavedSSHKey, error) {
	f.user = u
	return []sandboxes.SavedSSHKey{}, nil
}
func (f *savedKeyStub) SaveSSHKey(_ context.Context, u uuid.UUID, n, p string) (sandboxes.SavedSSHKey, error) {
	f.user = u
	return sandboxes.SavedSSHKey{Name: n, PublicKey: p}, nil
}
func (f *savedKeyStub) ChangeSavedSSHKey(_ context.Context, u, id uuid.UUID, d bool) error {
	f.user = u
	f.key = id
	f.defaulted = d
	return nil
}
func TestSavedSSHKeysBindAuthenticatedHuman(t *testing.T) {
	org, user, id := uuid.New(), uuid.New(), uuid.New()
	repo := &savedKeyStub{}
	s := apiServer{sandboxes: repo}
	ctx := authctx.WithPrincipal(context.Background(), &authctx.Principal{UserID: user, EmailVerified: true, Roles: map[uuid.UUID]string{org: rbac.RoleMember}})
	if _, err := s.SaveSSHKey(ctx, api.SaveSSHKeyRequestObject{OrgId: org, Body: &api.SavedSSHKeyInput{Name: "Laptop", PublicKey: sandboxFixtureSSHKey}}); err != nil || repo.user != user {
		t.Fatal("owner binding", err)
	}
	if _, err := s.DefaultSavedSSHKey(ctx, api.DefaultSavedSSHKeyRequestObject{OrgId: org, KeyId: id}); err != nil || repo.user != user || repo.key != id || !repo.defaulted {
		t.Fatal("default binding", err)
	}
	if _, err := s.DeleteSavedSSHKey(ctx, api.DeleteSavedSSHKeyRequestObject{OrgId: org, KeyId: id}); err != nil || repo.defaulted {
		t.Fatal("delete binding", err)
	}
	for _, p := range []*authctx.Principal{{UserID: user, MachineID: uuid.New(), EmailVerified: true, Roles: map[uuid.UUID]string{org: rbac.RoleOwner}}, {UserID: user, AuthMethod: authctx.AuthAgent, EmailVerified: true, Roles: map[uuid.UUID]string{org: rbac.RoleOwner}}, {UserID: user, EmailVerified: true, Roles: map[uuid.UUID]string{uuid.New(): rbac.RoleOwner}}} {
		repo.user = uuid.Nil
		bad := authctx.WithPrincipal(context.Background(), p)
		if _, err := s.ListSavedSSHKeys(bad, api.ListSavedSSHKeysRequestObject{OrgId: org}); err == nil || repo.user != uuid.Nil {
			t.Fatal("unauthorized registry access")
		}
	}
}
