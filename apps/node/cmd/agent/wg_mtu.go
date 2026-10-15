package main

import (
	"fmt"
	"strconv"
	"strings"
)

// An explicit gateway cap lowers normal WireGuard owner configuration. It is
// never accepted as an applied-MTU report without the backend's link readback.
func configuredWireGuardMTUCap(raw string) (int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, nil
	}
	cap, err := strconv.Atoi(raw)
	if err != nil || cap < 1280 || cap > 1420 {
		return 0, fmt.Errorf("TUNNEX_WG_MTU_CAP must be an integer between 1280 and 1420")
	}
	return cap, nil
}
