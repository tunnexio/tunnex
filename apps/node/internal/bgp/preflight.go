package bgp

// PreflightQualification can only be constructed by actual native observer
// qualification. It is evidence of host support, never forwarding authority.
type PreflightQualification struct {
	namespace, bootID string
	packageFiles      []preflightPackageFile
	qualified         bool
}
type preflightPackageFile struct {
	Path           string
	Identity       FileIdentity
	Size, Modified int64
}

func (q *PreflightQualification) Namespace() string {
	if q == nil {
		return ""
	}
	return q.namespace
}
