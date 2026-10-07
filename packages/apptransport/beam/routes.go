package beam

import (
	"errors"
	"path"
	"strings"
)

const PathRoutesCapability = "path_routes_v1"

// ValidateTarget accepts only fixed loopback destinations and literal path segments.
func ValidateTarget(t Target) error {
	if _, e := validateTarget(t); e != nil {
		return e
	}
	if len(t.Routes) > 8 {
		return errors.New("Beam supports at most eight local routes")
	}
	seen := map[string]bool{}
	for _, r := range t.Routes {
		if !ValidPathPrefix(r.PathPrefix) || seen[r.PathPrefix] || len(r.Target.Routes) > 0 {
			return errors.New("invalid or duplicate Beam route")
		}
		seen[r.PathPrefix] = true
		if _, e := validateTarget(r.Target); e != nil {
			return e
		}
	}
	return nil
}
func ValidPathPrefix(s string) bool {
	if len(s) < 2 || len(s) > 128 || !strings.HasPrefix(s, "/") || path.Clean(s) != s {
		return false
	}
	for _, c := range s {
		if !(c == '/' || c == '-' || c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9') {
			return false
		}
	}
	return !strings.Contains(s, "//")
}

// Matching uses path segment boundaries; forwarding preserves the original path.
func TargetForPath(t Target, requestPath string) (Target, error) {
	if e := ValidateTarget(t); e != nil {
		return Target{}, e
	}
	if !strings.HasPrefix(requestPath, "/") || strings.HasPrefix(requestPath, "//") || strings.ContainsAny(requestPath, "\\\x00\r\n") || len(t.Routes) > 0 && path.Clean(requestPath) != strings.TrimSuffix(requestPath, "/") && requestPath != "/" {
		return Target{}, errRefused
	}
	best := t
	length := 0
	for _, r := range t.Routes {
		if (requestPath == r.PathPrefix || strings.HasPrefix(requestPath, r.PathPrefix+"/")) && len(r.PathPrefix) > length {
			best = r.Target
			length = len(r.PathPrefix)
		}
	}
	best.Routes = nil
	return best, nil
}
