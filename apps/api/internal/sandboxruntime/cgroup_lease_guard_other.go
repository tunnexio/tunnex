//go:build !linux

package sandboxruntime

// NewActorCgroupLeaseGuard requires the native delegated Linux cgroupv2 tree.
func NewActorCgroupLeaseGuard() (*ActorCgroupLeaseGuard, error) { return nil, ErrUnavailable }

// Operator configuration cannot grant native cgroup support on another OS.
func NewActorCgroupLeaseGuardAt(string) (*ActorCgroupLeaseGuard, error) {
	return nil, ErrUnavailable
}
