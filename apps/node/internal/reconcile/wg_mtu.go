package reconcile

import "fmt"

// WireGuard reserves 80 bytes for the UDP/IPv6 envelope. This matches
// wg-quick's conservative automatic MTU, including transport padding.
func wireGuardMTU(requested, underlay int) (int, error) {
	if requested <= 0 || underlay < 1360 || underlay > 65535 {
		return 0, fmt.Errorf("invalid WireGuard MTU inputs")
	}
	ceiling := underlay - 80
	if requested < ceiling {
		return requested, nil
	}
	return ceiling, nil
}
