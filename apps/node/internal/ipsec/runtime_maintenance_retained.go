package ipsec

import (
	"context"
	"reflect"
	"time"

	"github.com/google/uuid"
)

// A fresh whole-set eligibility pass (or the complete native commit) precedes
// this final read-only fence. It grants nothing and changes no observation clock.
func (c *RuntimeController) retainedMaintenanceCurrent(ctx context.Context, owners map[uuid.UUID]runtimeActive, bgpCurrent func() bool) error {
	if c == nil || c.journal == nil || c.guard == nil || c.guard.reader == nil || len(owners) == 0 || len(owners) > 256 {
		return ErrRuntimeController
	}
	current := func() bool {
		if ctx.Err() != nil || !c.started || c.closed || !c.qualification.current() || c.config.DaemonAlive == nil || !c.config.DaemonAlive() || !reflect.DeepEqual(c.active, owners) {
			return false
		}
		for _, a := range owners {
			if a.Authority == nil || !c.fqdnGrantsCurrent(a.Grants) {
				return false
			}
			if _, err := a.Authority.RemainingForApply(a.Identity, 5*time.Second); err != nil {
				return false
			}
			for _, g := range a.Grants {
				if g.FQDN.Version == 2 {
					if _, err := a.Authority.RemainingFQDNForApply(a.Identity, guardFQDNGrantDigest(g), time.Millisecond); err != nil {
						return false
					}
				}
			}
			if a.Entry.ContractVersion == 3 {
				p := c.bgpProcesses[a.Entry.DeliveryID]
				if bgpCurrent == nil || !bgpCurrent() || p == nil || !p.Alive() {
					return false
				}
			}
		}
		return true
	}
	if !current() {
		return ErrRuntimeController
	}
	templates, seq, err := c.journal.guardTemplates()
	if err != nil || len(templates) != 1 {
		return ErrRuntimeController
	}
	for _, a := range owners {
		if a.Entry.Allocation.Namespace != templates[0].Namespace || c.proveDesktopGrants(ctx, a.Grants) != nil || !current() {
			return ErrRuntimeController
		}
	}
	// This one fresh complete read verifies actual positive members and exact
	// structure for all owners, bracketed by namespace and interface observations.
	if c.guard.reader.Check(ctx, GuardManifest{Namespace: templates[0].Namespace, ExpectedJSON: templates[0].ExpectedJSON}) != nil || !current() {
		return ErrRuntimeController
	}
	after, afterSeq, err := c.journal.guardTemplates()
	if err != nil || seq != afterSeq || !reflect.DeepEqual(templates, after) || !current() {
		return ErrRuntimeController
	}
	return nil
}
