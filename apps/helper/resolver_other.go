//go:build !darwin && !windows

package helper

// setResolvers on platforms OTHER than macOS (/etc/resolver) and Windows (NRPT, S8.4b) is not implemented:
// a set_resolvers call is refused with a stable code; the app fail-STATIC (tunnel stays up, cross-site
// names just don't resolve) exactly as against an old helper. macOS → resolver_darwin.go; Windows →
// resolver_windows.go.
func setResolvers(_ []ResolverForward) error {
	return &ProtocolError{Code: "resolvers_unsupported", Msg: "domain-scoped resolvers are not supported on this platform"}
}
