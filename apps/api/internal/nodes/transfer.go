package nodes

import (
	"fmt"
	"net/http"

	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
)

// errDevicesStillHomed is the refusal a gateway revoke returns while devices are homed on it (S12.12 D1).
//
// ⛔ IT NAMES THE COUNT, AND THAT IS NOT DECORATION. "This gateway still has devices" tells an operator they
// are blocked; "34 devices are still homed to this gateway" tells them what the alternative would have cost.
// That number is what the confirm dialog promised and the API never carried, and a refusal that withholds the
// figure an operator needs in order to decide is a refusal they will route around.
//
// ⚠ AND IT OFFERS THE WAY OUT IN THE SAME BREATH. A dead-end refusal on the only path to removing a gateway
// teaches an operator that gateways cannot be removed. This message names the move because the refusal exists
// to send them to it, not to stop them.
//
// `devices_still_homed` is its own code — never a reuse of a generic conflict — because the UI has exactly
// one correct response to it (offer the transfer) and none to the others.
func errDevicesStillHomed(count int64) *apierr.Error {
	noun := "devices are"
	if count == 1 {
		noun = "device is"
	}
	return apierr.New(http.StatusConflict, "devices_still_homed",
		fmt.Sprintf("%d %s still homed to this gateway. Revoking is permanent and would disconnect them "+
			"immediately, so move them to another gateway first.", count, noun))
}
