package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"
)

type beamBeat struct {
	share       beamShare
	originReady bool
	err         error
}

func beamCheckLogin(d beamDependencies, c Credential) error {
	current, e := d.loadCredential()
	if e != nil || !beamSameCredential(current, c) {
		return errors.New("Beam login changed or was removed; serving stopped")
	}
	if !c.ExpiresAt.After(d.clock()) {
		return ErrCredentialExpired
	}
	return nil
}
func beamSameCredential(a, b Credential) bool {
	return a.Server == b.Server && a.Token == b.Token && a.Fingerprint == b.Fingerprint && a.ExpiresAt.Equal(b.ExpiresAt)
}
func beamCleanup(api beamAPI, d beamDependencies, credential Credential, org, id string, version int64) error {
	return beamCleanupAction(api, d, credential, org, id, version, "stop")
}
func beamCleanupAction(api beamAPI, d beamDependencies, credential Credential, org, id string, version int64, action string) error {
	// Only an invocation-owned observed version may be changed. Never refresh or
	// retry on conflict into another connector's generation.
	uncertain := func() error {
		return fmt.Errorf("Beam connector is closed; server %s was not confirmed. Check 'tunnex beam get --org %s --share %s'", action, org, id)
	}
	current, e := d.loadCredential()
	if e != nil || !beamSameCredential(current, credential) {
		return uncertain()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	s, e := api.Action(ctx, org, id, beamAction{Action: action, ExpectedVersion: version})
	expectedState := "stopped"
	if action == "pause" {
		expectedState = "paused"
	}
	if e != nil || s.ID != id || s.OrgID != org || s.State != expectedState {
		return uncertain()
	}
	return nil
}
func beamForeground(ctx context.Context, api beamAPI, d beamDependencies, credential Credential, o beamCommand, original beamShare, connector beamConnectorWire, runner beamRunner, out io.Writer) error {
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	poolDone := make(chan error, 1)
	poolStopped := make(chan struct{})
	go func() { defer close(poolStopped); poolDone <- runner.Run(runCtx) }()
	beats := make(chan beamBeat, 1)
	workerDone := make(chan struct{})
	go func() {
		defer close(workerDone)
		tick := time.NewTicker(d.heartbeatInterval)
		defer tick.Stop()
		for {
			// The entire local check + CP heartbeat fits inside half the uncertainty
			// ceiling; the main loop still cancels independently at the full ceiling.
			bounded, stop := context.WithTimeout(runCtx, d.uncertainty/2)
			local := false
			if runner.Ready() {
				probe, stopProbe := context.WithTimeout(bounded, time.Second)
				local = d.checkTarget(probe, o.target.transport()) == nil
				stopProbe()
			}
			s, e := api.Heartbeat(bounded, o.org, original.ID, connector.Binding.Generation, local)
			stop()
			select {
			case beats <- beamBeat{s, local, e}:
			case <-runCtx.Done():
				return
			}
			select {
			case <-tick.C:
			case <-runCtx.Done():
				return
			}
		}
	}()
	defer func() {
		cancel()
		select {
		case <-workerDone:
		case <-time.After(time.Second):
		}
		select {
		case <-poolStopped:
		case <-time.After(time.Second):
		}
	}()
	tick := time.NewTicker(d.interval)
	defer tick.Stop()
	lastAuthority := d.clock()
	expiry := original.ExpiresAt
	for _, t := range []time.Time{credential.ExpiresAt, connector.ExpiresAt, connector.CertificateExpiresAt} {
		if t.Before(expiry) {
			expiry = t
		}
	}
	readyPrinted := false
	observedVersion := connector.ShareVersion
	observedAuthority := connector.Binding.AuthorityVersion
	stopOwned := func() error {
		cancel()
		select {
		case <-poolStopped:
			return beamCleanup(api, d, credential, o.org, original.ID, observedVersion)
		case <-time.After(time.Second):
			return errors.New("could not confirm Beam channel shutdown; check the share state before retrying Stop")
		}
	}
	for {
		select {
		case <-ctx.Done():
			// Cancellation shuts native channels before the bounded server Stop attempt.
			return stopOwned()
		case e := <-poolDone:
			if ctx.Err() != nil {
				return stopOwned()
			}
			_ = e // Raw native/TLS errors may include upstream addresses; do not expose them.
			return errors.New("Beam connector ended; fetch the share before explicitly resuming")
		case event := <-beats:
			if event.err != nil {
				var remote *beamAPIError
				if errors.As(event.err, &remote) && remote.status >= 400 && remote.status < 500 {
					return event.err
				}
				// No local successful check can replace CP authority. Transport is closed
				// by the independent ticker if the last successful heartbeat ages out.
				continue
			}
			s := event.share
			if s.ID != original.ID || s.OrgID != o.org || s.Version < observedVersion || s.AuthorityVersion < observedAuthority || s.Hostname != original.Hostname || s.Target == nil || beamTargetDigest(*s.Target) != beamTargetDigest(o.target) {
				return errors.New("Beam authority changed; serving stopped")
			}
			if beamTerminal(s.State) || s.State == "paused" || !s.ExpiresAt.After(d.clock()) {
				return errors.New("Beam share ended or was paused; serving stopped")
			}
			lastAuthority = d.clock()
			observedVersion = s.Version
			observedAuthority = s.AuthorityVersion
			// A policy reduction or server expiry update always shortens local authority.
			// An explicit extension may be observed, but certificate/source deadlines
			// remain absolute and the connector never renews itself here.
			expiry = s.ExpiresAt
			for _, t := range []time.Time{credential.ExpiresAt, connector.CertificateExpiresAt} {
				if t.Before(expiry) {
					expiry = t
				}
			}
			if !readyPrinted && s.State == "active" && s.Connectivity == "online" && event.originReady && runner.Ready() {
				canonical, e := beamCanonicalURL(s)
				if e != nil {
					return e
				}
				if _, e = fmt.Fprintf(out, "Share: %s\nURL: %s\nExpires: %s\nKeep this process running. Ctrl+C stops this share.\n", s.ID, canonical, s.ExpiresAt.UTC().Format(time.RFC3339)); e != nil {
					return errors.New("could not write Beam publication status")
				}
				readyPrinted = true
			}
		case <-tick.C:
			at := d.clock()
			current, e := d.loadCredential()
			if e != nil || !beamSameCredential(current, credential) {
				return errors.New("Beam login changed or was removed; serving stopped")
			}
			if !credential.ExpiresAt.After(at) || !expiry.After(at) {
				return errors.New("Beam share or publishing authority expired; serving stopped")
			}
			if at.Sub(lastAuthority) >= d.uncertainty {
				return errors.New("Beam control-plane authority could not be refreshed; serving stopped")
			}
		}
	}
}
