package reconcile

import "strings"

// parseRouteGetDev extracts the egress interface from `ip -o route get` output, for example
// "10.50.1.10 via 172.31.32.1 dev ens5 src 172.31.47.225 uid 0". ok=false when the kernel named none
// (an unreachable or prohibit route prints no dev).
func parseRouteGetDev(out string) (string, bool) {
	fields := strings.Fields(out)
	for i := 0; i+1 < len(fields); i++ {
		if fields[i] == "dev" {
			return fields[i+1], true
		}
	}
	return "", false
}
