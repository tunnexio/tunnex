package http

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/ipsec"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

type connectionFake struct {
	calls          int
	org, actor, id uuid.UUID
	revision       int64
	limit          int
	after          *uuid.UUID
	scoped         bool
	result         ipsec.Connection
	page           ipsec.ConnectionPage
	err            error
}

func (f *connectionFake) scope(ctx context.Context, org uuid.UUID) {
	f.calls++
	f.org = org
	got, ok := authctx.OrgFrom(ctx)
	f.scoped = ok && got == org
}
func (f *connectionFake) Read(ctx context.Context, org, id uuid.UUID) (ipsec.Connection, error) {
	f.scope(ctx, org)
	f.id = id
	return f.result, f.err
}
func (f *connectionFake) ListPage(ctx context.Context, org uuid.UUID, after *uuid.UUID, limit int) (ipsec.ConnectionPage, error) {
	f.scope(ctx, org)
	f.after = after
	f.limit = limit
	return f.page, f.err
}
func (f *connectionFake) Delete(ctx context.Context, org, actor, id uuid.UUID, rev int64) (ipsec.Connection, error) {
	f.scope(ctx, org)
	f.actor = actor
	f.id = id
	f.revision = rev
	return f.result, f.err
}
func TestIPsecConnectionAuthorization(t *testing.T) {
	org, id, user := uuid.New(), uuid.New(), uuid.New()
	for _, ctx := range []context.Context{context.Background(), settingsContext(uuid.New(), user, rbac.RoleOwner, true), settingsContext(org, user, rbac.RoleMember, true), settingsContext(org, user, rbac.RoleOwner, false)} {
		f := &connectionFake{}
		_, err := (apiServer{ipsecConnections: f}).DeleteIPsecConnection(ctx, api.DeleteIPsecConnectionRequestObject{OrgId: org, ConnectionId: id, Params: api.DeleteIPsecConnectionParams{IfMatch: `"1"`}})
		if err == nil || f.calls != 0 {
			t.Fatal("unauthorized deletion reached store")
		}
	}
	for _, ctx := range []context.Context{context.Background(), settingsContext(uuid.New(), user, rbac.RoleOwner, true)} {
		f := &connectionFake{}
		s := apiServer{ipsecConnections: f}
		if _, err := s.GetIPsecConnection(ctx, api.GetIPsecConnectionRequestObject{OrgId: org, ConnectionId: id}); err == nil || f.calls != 0 {
			t.Fatal("unauthorized detail reached store")
		}
		if _, err := s.ListIPsecConnections(ctx, api.ListIPsecConnectionsRequestObject{OrgId: org}); err == nil || f.calls != 0 {
			t.Fatal("unauthorized list reached store")
		}
	}
}
func TestIPsecConnectionPrecondition(t *testing.T) {
	org, id, user := uuid.New(), uuid.New(), uuid.New()
	ctx := settingsContext(org, user, rbac.RoleOwner, true)
	for _, header := range []string{"", `1`, `"0"`, `"-1"`, `W/"1"`, `*`, `"1", "2"`, `"01"`, `"+1"`, `"9223372036854775808"`, ` "1" `} {
		f := &connectionFake{}
		_, err := (apiServer{ipsecConnections: f}).DeleteIPsecConnection(ctx, api.DeleteIPsecConnectionRequestObject{OrgId: org, ConnectionId: id, Params: api.DeleteIPsecConnectionParams{IfMatch: header}})
		if !hasCode(err, 400, "invalid_ipsec_connection") || f.calls != 0 {
			t.Fatalf("precondition %q reached store: %v", header, err)
		}
	}
	f := &connectionFake{result: ipsec.Connection{ID: id, OrgID: org, DesiredRevision: 2, DesiredIntent: "deleted"}}
	r, err := (apiServer{ipsecConnections: f}).DeleteIPsecConnection(ctx, api.DeleteIPsecConnectionRequestObject{OrgId: org, ConnectionId: id, Params: api.DeleteIPsecConnectionParams{IfMatch: `"1"`}})
	if err != nil || f.actor != user || f.org != org || f.id != id || f.revision != 1 || !f.scoped {
		t.Fatalf("delete forwarding: %v", err)
	}
	response := r.(api.DeleteIPsecConnection200JSONResponse)
	if response.Headers.ETag != `"2"` || response.Body.DesiredRevision != 2 {
		t.Fatal("delete must return committed ETag")
	}
}
func TestIPsecConnectionReadProjectionAndPaging(t *testing.T) {
	org, id, user, cursor := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	ctx := settingsContext(org, user, rbac.RoleMember, false)
	f := &connectionFake{result: ipsec.Connection{ID: id, OrgID: org, DesiredRevision: 3, DesiredIntent: "disabled"}, page: ipsec.ConnectionPage{Items: []ipsec.Connection{}, NextCursor: &cursor}}
	s := apiServer{ipsecConnections: f}
	r, err := s.GetIPsecConnection(ctx, api.GetIPsecConnectionRequestObject{OrgId: org, ConnectionId: id})
	if err != nil || !f.scoped || f.id != id {
		t.Fatalf("detail: %v", err)
	}
	response := r.(api.GetIPsecConnection200JSONResponse)
	if response.Headers.ETag != `"3"` {
		t.Fatal("wrong detail ETag")
	}
	encoded, _ := json.Marshal(response.Body)
	for _, secret := range []string{"psk", "ciphertext", "tunnels", "secret", "credential"} {
		if strings.Contains(string(encoded), secret) {
			t.Fatal("nonpublic field")
		}
	}
	if _, err = s.ListIPsecConnections(ctx, api.ListIPsecConnectionsRequestObject{OrgId: org}); err != nil || f.limit != 50 || f.after != nil {
		t.Fatalf("default page: %v", err)
	}
	limit := 2
	page, err := s.ListIPsecConnections(ctx, api.ListIPsecConnectionsRequestObject{OrgId: org, Params: api.ListIPsecConnectionsParams{Limit: &limit, After: &cursor}})
	if err != nil || f.limit != 2 || f.after == nil || *f.after != cursor {
		t.Fatalf("page forward: %v", err)
	}
	if page.(api.ListIPsecConnections200JSONResponse).Body.NextCursor == nil {
		t.Fatal("cursor missing")
	}
	for _, limit := range []int{0, 101} {
		before := f.calls
		_, err = s.ListIPsecConnections(ctx, api.ListIPsecConnectionsRequestObject{OrgId: org, Params: api.ListIPsecConnectionsParams{Limit: &limit}})
		if !hasCode(err, 400, "invalid_ipsec_connection") || f.calls != before {
			t.Fatal("bad limit reached store")
		}
	}
}
func TestIPsecConnectionStaticErrors(t *testing.T) {
	org, id, user := uuid.New(), uuid.New(), uuid.New()
	ctx := settingsContext(org, user, rbac.RoleOwner, true)
	for _, tc := range []struct {
		err    error
		status int
		code   string
	}{{ipsec.ErrConnectionInvalid, 400, "invalid_ipsec_connection"}, {ipsec.ErrConnectionNotFound, 404, "ipsec_connection_not_found"}, {ipsec.ErrConnectionConflict, 409, "ipsec_connection_conflict"}, {errors.New("private details"), 500, "ipsec_connection_unavailable"}} {
		_, err := (apiServer{ipsecConnections: &connectionFake{err: tc.err}}).GetIPsecConnection(ctx, api.GetIPsecConnectionRequestObject{OrgId: org, ConnectionId: id})
		if !hasCode(err, tc.status, tc.code) || strings.Contains(err.Error(), "private") {
			t.Fatalf("unsafe error: %v", err)
		}
	}
}

func TestIPsecConnectionActorRefusals(t *testing.T) {
	org, id := uuid.New(), uuid.New()
	for _, p := range []*authctx.Principal{{EmailVerified: true, Roles: map[uuid.UUID]string{org: rbac.RoleOwner}}, {UserID: uuid.New(), MachineID: uuid.New(), AuthMethod: authctx.AuthMachine, Roles: map[uuid.UUID]string{org: rbac.RoleOwner}}, {UserID: uuid.New(), EmailVerified: true, MustChangePassword: true, Roles: map[uuid.UUID]string{org: rbac.RoleOwner}}} {
		f := &connectionFake{}
		_, err := (apiServer{ipsecConnections: f}).DeleteIPsecConnection(authctx.WithPrincipal(context.Background(), p), api.DeleteIPsecConnectionRequestObject{OrgId: org, ConnectionId: id, Params: api.DeleteIPsecConnectionParams{IfMatch: `"1"`}})
		if err == nil || f.calls != 0 {
			t.Fatal("invalid actor reached store")
		}
	}
	f := &connectionFake{result: ipsec.Connection{DesiredRevision: 2}}
	_, err := (apiServer{ipsecConnections: f}).DeleteIPsecConnection(settingsContext(org, uuid.New(), rbac.RoleAdmin, true), api.DeleteIPsecConnectionRequestObject{OrgId: org, ConnectionId: id, Params: api.DeleteIPsecConnectionParams{IfMatch: `"1"`}})
	if err != nil || f.calls != 1 {
		t.Fatal("verified admin refused")
	}
}
func TestIPsecConnectionRouteValidation(t *testing.T) {
	org, id, user := uuid.New(), uuid.New(), uuid.New()
	f := &connectionFake{}
	router, err := NewRouter(slog.New(slog.NewTextHandler(io.Discard, nil)), Deps{IPsecConnections: f, AuthFn: func(*http.Request) *authctx.Principal {
		return &authctx.Principal{UserID: user, EmailVerified: true, Roles: map[uuid.UUID]string{org: rbac.RoleOwner}}
	}})
	if err != nil {
		t.Fatal(err)
	}
	path := "/api/v1/organizations/" + org.String() + "/ipsec/connections"
	for _, tc := range []struct {
		method, path string
		headers      []string
	}{{"DELETE", path + "/" + id.String(), nil}, {"DELETE", path + "/" + id.String(), []string{`"1"`, `"1"`}}, {"DELETE", path + "/" + id.String(), []string{"private-value"}}, {"GET", path + "?limit=private-value", nil}, {"GET", path + "?after=private-value", nil}, {"GET", path + "?limit=101", nil}, {"GET", path + "?limit=9223372036854775808", nil}, {"GET", path + "/private-value", nil}, {"DELETE", path + "/private-value", []string{`"1"`}}} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(tc.method, tc.path, nil)
		for _, v := range tc.headers {
			req.Header.Add("If-Match", v)
		}
		router.ServeHTTP(rec, req)
		if rec.Code != 400 || f.calls != 0 || strings.Contains(rec.Body.String(), "private-value") {
			t.Fatalf("unsafe route validation %d calls%d: %s", rec.Code, f.calls, rec.Body.String())
		}
	}
}

func TestIPsecConnectionRouteAuthorizationPrecedesValidation(t *testing.T) {
	org, id := uuid.New(), uuid.New()
	path := "/api/v1/organizations/" + org.String() + "/ipsec/connections"
	for _, tc := range []struct {
		name, method, path string
		p                  *authctx.Principal
		status             int
	}{
		{"anonymous missing header", "DELETE", path + "/" + id.String(), nil, 401},
		{"member malformed header", "DELETE", path + "/" + id.String(), &authctx.Principal{UserID: uuid.New(), EmailVerified: true, Roles: map[uuid.UUID]string{org: rbac.RoleMember}}, 403},
		{"foreign org invalid query", "GET", path + "?limit=bad", &authctx.Principal{UserID: uuid.New(), Roles: map[uuid.UUID]string{uuid.New(): rbac.RoleOwner}}, 404},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &connectionFake{}
			router, err := NewRouter(slog.New(slog.NewTextHandler(io.Discard, nil)), Deps{IPsecConnections: f, AuthFn: func(*http.Request) *authctx.Principal { return tc.p }})
			if err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest(tc.method, tc.path, nil)
			if tc.p != nil {
				req.Header.Set("If-Match", "bad")
			}
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)
			if rec.Code != tc.status || f.calls != 0 {
				t.Fatalf("authority must precede input validation: status%d body%s", rec.Code, rec.Body.String())
			}
		})
	}
}
