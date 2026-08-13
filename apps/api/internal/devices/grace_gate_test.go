package devices

import (
	"errors"
	"testing"
	"time"

	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/licence"
)

// ⛔ THE SAME GATE, THE OTHER PRINCIPAL. Devices and gateways are separate call sites with separate
// services; proving one says nothing about the other, which is why this file exists twice.
func TestDeviceCreationGateFollowsTheLadder(t *testing.T) {
	if (&Service{}).checkNewPrincipalAllowed() != nil {
		t.Fatal("⛔ an unwired manager refused a device — Community just lost device creation")
	}
	if (&Service{licence: licence.NewTestManager("starter", time.Now().Add(time.Hour))}).checkNewPrincipalAllowed() != nil {
		t.Fatal("a valid licence refused a device")
	}
	err := (&Service{licence: licence.NewTestManager("starter", time.Now().Add(-time.Hour))}).checkNewPrincipalAllowed()
	if err == nil {
		t.Fatal("⛔ AN EXPIRED LICENCE CREATED A NEW DEVICE")
	}
	var ae *apierr.Error
	if !errors.As(err, &ae) || ae.Status != 403 || ae.Code != "licence_expired" {
		t.Fatalf("refusal = %v, want a 403 licence_expired", err)
	}
}
