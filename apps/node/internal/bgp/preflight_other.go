//go:build !linux

package bgp

import "context"

func (q *PreflightQualification) Current() bool { return false }
func QualifyPreflight(context.Context, string) (*PreflightQualification, error) {
	return nil, ErrPackage
}
