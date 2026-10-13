//go:build linux

package main

import (
	"errors"
	"os"
	"strings"
	"time"
)

// This schedules observations only. It cannot manufacture qualification or
// authority; success is supplied only after native preflight and receipt attach.
type bgpQualificationRetry struct {
	qualified bool
	next      time.Time
	backoff   time.Duration
}

func (r *bgpQualificationRetry) due(now time.Time) bool {
	return !r.qualified && (r.next.IsZero() || !now.Before(r.next))
}
func (r *bgpQualificationRetry) completed(now time.Time, succeeded bool) {
	if succeeded {
		r.qualified = true
		return
	}
	if r.backoff == 0 {
		r.backoff = 5 * time.Second
	} else {
		r.backoff *= 2
	}
	if r.backoff > 30*time.Second {
		r.backoff = 30 * time.Second
	}
	r.next = now.Add(r.backoff)
}

// Never overwrite, adopt or discard retained observer cleanup obligations.
func bgpPreflightResidueClear(parent string) error {
	entries, err := os.ReadDir(parent)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "bgp-preflight-") {
			return errors.New("BGP preflight retained cleanup")
		}
	}
	return nil
}
