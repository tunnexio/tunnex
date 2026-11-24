package nodes

import (
	"regexp"
	"strings"
)

// Agent-supplied, shown verbatim in dashboards: a short version token only,
// bounded like the enrollment field (maxLength 50). Anything else is ignored.
var agentVersionPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+~-]{0,49}$`)

// reportedAgentVersion returns the version to store, or "" to keep the stored one.
func reportedAgentVersion(raw string) string {
	v := strings.TrimSpace(raw)
	if !agentVersionPattern.MatchString(v) {
		return ""
	}
	return v
}
