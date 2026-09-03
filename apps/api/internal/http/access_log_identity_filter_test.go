package http

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	openapi_types "github.com/oapi-codegen/runtime/types"

	"github.com/tunnexio/tunnex/apps/api/internal/accesslog"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

type accessLogIdentityCapture struct {
	calls    int
	identity *accessEventIdentityFilter
}

func (c *accessLogIdentityCapture) List(_ context.Context, _ uuid.UUID, identity *accessEventIdentityFilter, _ bool, _ time.Time, _ uuid.UUID, _ int32) ([]accesslog.Event, error) {
	c.calls++
	if identity != nil {
		copy := *identity
		c.identity = &copy
	} else {
		c.identity = nil
	}
	return []accesslog.Event{}, nil
}

func (*accessLogIdentityCapture) Health() accesslog.Snapshot { return accesslog.Snapshot{} }

func (*accessLogIdentityCapture) Collectors(context.Context, uuid.UUID) ([]accessLogCollectorStatus, error) {
	return []accessLogCollectorStatus{}, nil
}

func TestListAccessEventsSelectsOneHistoricalIdentityFilter(t *testing.T) {
	org := uuid.New()
	ctx := principalWithRole(org, rbac.RoleAdmin)
	tests := []struct {
		name   string
		kind   accessEventIdentityKind
		params func(*openapi_types.UUID) api.ListAccessEventsParams
	}{
		{"agent", accessEventIdentityAgent, func(id *openapi_types.UUID) api.ListAccessEventsParams {
			return api.ListAccessEventsParams{SrcAgentId: id}
		}},
		{"device", accessEventIdentityDevice, func(id *openapi_types.UUID) api.ListAccessEventsParams {
			return api.ListAccessEventsParams{SrcDeviceId: id}
		}},
		{"user", accessEventIdentityUser, func(id *openapi_types.UUID) api.ListAccessEventsParams {
			return api.ListAccessEventsParams{SrcUserId: id}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id := openapi_types.UUID(uuid.New())
			capture := &accessLogIdentityCapture{}
			s := apiServer{accessLog: capture}
			if _, err := s.ListAccessEvents(ctx, api.ListAccessEventsRequestObject{OrgId: org, Params: tt.params(&id)}); err != nil {
				t.Fatal(err)
			}
			if capture.calls != 1 || capture.identity == nil || capture.identity.Kind != tt.kind || capture.identity.ID != uuid.UUID(id) {
				t.Fatalf("captured filter = %+v calls=%d", capture.identity, capture.calls)
			}
		})
	}
}

func TestListAccessEventsRejectsMultipleIdentityFilters(t *testing.T) {
	org := uuid.New()
	agentID := openapi_types.UUID(uuid.New())
	deviceID := openapi_types.UUID(uuid.New())
	userID := openapi_types.UUID(uuid.New())
	tests := []struct {
		name   string
		params api.ListAccessEventsParams
	}{
		{"agent and device", api.ListAccessEventsParams{SrcAgentId: &agentID, SrcDeviceId: &deviceID}},
		{"agent and user", api.ListAccessEventsParams{SrcAgentId: &agentID, SrcUserId: &userID}},
		{"device and user", api.ListAccessEventsParams{SrcDeviceId: &deviceID, SrcUserId: &userID}},
		{"all three", api.ListAccessEventsParams{SrcAgentId: &agentID, SrcDeviceId: &deviceID, SrcUserId: &userID}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			capture := &accessLogIdentityCapture{}
			s := apiServer{accessLog: capture}
			_, err := s.ListAccessEvents(principalWithRole(org, rbac.RoleAdmin), api.ListAccessEventsRequestObject{
				OrgId:  org,
				Params: tt.params,
			})
			if !hasCode(err, 400, "invalid_access_event_identity_filter") {
				t.Fatalf("multiple identity filters: want stable 400, got %v", err)
			}
			if capture.calls != 0 {
				t.Fatal("invalid identity combination must be rejected before the store")
			}
		})
	}
}
