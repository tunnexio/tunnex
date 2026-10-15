package fqdn

import "strings"

// StaticNamesOwnedByProfile proves each record's effective longest-suffix owner.
// The index identifies a profile in one immutable configuration, not a caller.
// Equal suffixes belonging to different profiles are ambiguous and fail closed.
func StaticNamesOwnedByProfile(selected int, names []string, zoneSets [][]string) bool {
	if selected < 0 || selected >= len(zoneSets) {
		return false
	}
	owners := map[string]int{}
	for owner, zones := range zoneSets {
		for _, zone := range zones {
			canonical, err := Normalize(zone)
			if err != nil || canonical != zone {
				return false
			}
			if prior, exists := owners[zone]; exists && prior != owner {
				return false
			}
			owners[zone] = owner
		}
	}
	for _, name := range names {
		canonical, err := Normalize(name)
		if err != nil || canonical != name {
			return false
		}
		best, owner := -1, -1
		for zone, candidate := range owners {
			if (name == zone || strings.HasSuffix(name, "."+zone)) && len(zone) > best {
				best, owner = len(zone), candidate
			}
		}
		if owner != selected {
			return false
		}
	}
	return true
}
