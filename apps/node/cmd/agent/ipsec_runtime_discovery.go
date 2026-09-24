package main

import (
	"bytes"
	"context"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/node/internal/control"
	"github.com/tunnexio/tunnex/apps/node/internal/ipsec"
)

type runtimePendingSource interface {
	IPsecPending(context.Context, *uuid.UUID, int) (ipsec.RuntimePendingPage, error)
}

// Discovery authorizes only starting the cleanup machinery, never application.
// Activation continues to require material and a fresh exact controller lease.
func discoverIPsecRuntime(ctx context.Context, source runtimePendingSource) (ipsec.RuntimePendingPage, bool, error) {
	var first ipsec.RuntimePendingPage
	var cursor *uuid.UUID
	for n := 0; n < 16; n++ {
		page, e := source.IPsecPending(ctx, cursor, 100)
		if e != nil || page.OrgID == uuid.Nil || page.NodeID == uuid.Nil || len(page.Items) > 100 {
			return first, false, control.ErrIPsecControl
		}
		if n == 0 {
			first = page
		} else if page.OrgID != first.OrgID || page.NodeID != first.NodeID || page.IPsecEnabled != first.IPsecEnabled {
			return first, false, control.ErrIPsecControl
		}
		cleanup := false
		for _, item := range page.Items {
			if item.Kind != "apply" && item.Kind != "cleanup" || item.ConnectionID == uuid.Nil || item.DesiredRevision <= 0 {
				return first, false, control.ErrIPsecControl
			}
			cleanup = cleanup || item.Kind == "cleanup"
		}
		if cleanup || page.IPsecEnabled {
			return first, cleanup, nil
		}
		if page.NextCursor == nil {
			return first, false, nil
		}
		next := *page.NextCursor
		if next == uuid.Nil || len(page.Items) == 0 || next != page.Items[len(page.Items)-1].ConnectionID || cursor != nil && bytes.Compare(next[:], cursor[:]) <= 0 {
			return first, false, control.ErrIPsecControl
		}
		cursor = &next
	}
	return first, false, control.ErrIPsecControl
}
