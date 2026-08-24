package http

import (
	"testing"

	"github.com/google/uuid"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/devices"
)

func TestPendingDeviceOwnerProjectionIsServedFromDeviceStatus(t *testing.T) {
	email := "pending.owner@example.test"
	out := toAPIDeviceWithStatus(devices.DeviceWithStatus{
		Device:     sqlc.Device{ID: uuid.New(), UserID: uuid.New(), NodeID: uuid.New(), Name: "pending laptop", PublicKey: "key", Status: "pending"},
		OwnerEmail: &email,
	})
	if out.OwnerEmail == nil || string(*out.OwnerEmail) != email {
		t.Fatalf("pending owner attribution: got %#v, want %q", out.OwnerEmail, email)
	}
}

func TestPendingDeviceOwnerProjectionDoesNotInventAnOwner(t *testing.T) {
	out := toAPIDeviceWithStatus(devices.DeviceWithStatus{
		Device: sqlc.Device{ID: uuid.New(), UserID: uuid.New(), NodeID: uuid.New(), Name: "pending laptop", PublicKey: "key", Status: "pending"},
	})
	if out.OwnerEmail != nil {
		t.Fatalf("unresolved owner must remain absent, got %#v", *out.OwnerEmail)
	}
}
