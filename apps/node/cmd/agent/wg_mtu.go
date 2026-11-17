package main

import (
	"fmt"
	"strconv"
	"strings"
)

// The default leaves room for remote Internet paths even when a cloud NIC has
// a jumbo MTU. An explicit cap overrides this compatibility default; neither is
// an applied-MTU report without the backend's exact link readback.
func configuredWireGuardMTUCap(raw string) (int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 1380, nil
	}
	cap, err := strconv.Atoi(raw)
	if err != nil || cap < 1280 || cap > 1420 {
		return 0, fmt.Errorf("TUNNEX_WG_MTU_CAP must be an integer between 1280 and 1420")
	}
	return cap, nil
}
