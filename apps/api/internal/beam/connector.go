package beam

import (
	"context"
	"github.com/google/uuid"
	"slices"
	"time"
)

func (s *Service) IssueConnector(ctx context.Context, org, id uuid.UUID, a Actor, in ConnectorInput) (Connector, error) {
	var out Connector
	if a.CredentialID == uuid.Nil || s.signer == nil || len(in.CSR) > 16384 {
		return out, deny()
	}
	tx, e := s.transaction(ctx, org)
	if e != nil {
		return out, e
	}
	defer tx.Rollback(ctx)
	r, e := scanShare(tx.QueryRow(ctx, `SELECT `+shareColumns+` FROM beam_shares WHERE org_id=$1 AND id=$2 FOR UPDATE`, org, id))
	if e != nil || r.PublisherID != a.ID || r.SourceCredentialID == nil || *r.SourceCredentialID != a.CredentialID {
		return out, missing()
	}
	if r.Target != nil && len(r.Target.Routes) > 0 && !slices.Contains(in.Capabilities, "path_routes_v1") {
		return out, invalid("Update the publisher: this share requires path_routes_v1 support")
	}
	if r.Version != in.ExpectedVersion {
		return out, conflict()
	}
	p, e := s.policy(ctx, tx, org)
	if e != nil {
		return out, e
	}
	deadline, e := s.source(ctx, tx, r, p)
	if e != nil || r.State == "paused" {
		return out, deny()
	}
	issued, e := s.signer.SignCSR([]byte(in.CSR), "beam:"+org.String()+":"+id.String())
	if e != nil {
		return out, invalid("A signed RSA connector CSR is required")
	}
	issued.Serial = canonicalSerial(issued.Serial)
	if issued.Serial == "" {
		return out, deny()
	}
	r.Generation = uuid.New()
	r.AuthorityVersion++
	r.ServingAuthorityVersion = r.AuthorityVersion
	r.Version++
	r.Serial = &issued.Serial
	r.State = "starting"
	_, e = tx.Exec(ctx, `UPDATE beam_shares SET generation=$3,certificate_serial=$4,authority_version=$5,version=$6,state='starting',origin_ready=false,last_heartbeat_at=NULL,last_channel_at=NULL,serving_authority_version=$5 WHERE org_id=$1 AND id=$2`, org, id, r.Generation, issued.Serial, r.AuthorityVersion, r.Version)
	if e != nil {
		return out, e
	}
	if e = audit(ctx, tx, org, a.ID, "connector.issued", id); e != nil {
		return out, e
	}
	if e = tx.Commit(ctx); e != nil {
		return out, e
	}
	if issued.NotAfter.Before(deadline) {
		deadline = issued.NotAfter
	}
	return Connector{Binding: r.Binding(), ShareVersion: r.Version, ProxyURL: p.domainProxyURL, ProxyServerName: "tunnex-beam-proxy", CAPEM: string(s.signer.CertPEM()), CertificatePEM: issued.CertPEM, ExpiresAt: deadline, CertificateExpiresAt: issued.NotAfter}, nil
}
func (s *Service) Heartbeat(ctx context.Context, org, id uuid.UUID, a Actor, in Heartbeat) (Share, error) {
	tx, e := s.transaction(ctx, org)
	if e != nil {
		return Share{}, e
	}
	defer tx.Rollback(ctx)
	r, e := scanShare(tx.QueryRow(ctx, `SELECT `+shareColumns+` FROM beam_shares WHERE org_id=$1 AND id=$2 FOR UPDATE`, org, id))
	if e != nil || r.PublisherID != a.ID || a.CredentialID == uuid.Nil || r.SourceCredentialID == nil || *r.SourceCredentialID != a.CredentialID {
		return r, missing()
	}
	p, e := s.policy(ctx, tx, org)
	if e != nil {
		return r, e
	}
	if _, e = s.source(ctx, tx, r, p); e != nil || r.State == "paused" || r.Generation != in.Generation || r.Serial == nil {
		return r, deny()
	}
	state := r.State
	if in.OriginReady && r.LastChannel != nil && r.LastChannel.After(time.Now().Add(-6*time.Second)) {
		state = "active"
	}
	_, e = tx.Exec(ctx, `UPDATE beam_shares SET last_heartbeat_at=now(),origin_ready=$3,state=$4 WHERE org_id=$1 AND id=$2`, org, id, in.OriginReady, state)
	if e != nil {
		return r, e
	}
	if e = tx.Commit(ctx); e != nil {
		return r, e
	}
	return s.Get(ctx, org, id, a)
}

// Sweep terminalizes persisted resources; request authority never depends on its availability.
func (s *Service) Sweep(ctx context.Context) error {
	s.sweepMu.Lock()
	defer s.sweepMu.Unlock()
	var after any
	if !s.sweepAfterTime.IsZero() {
		after = s.sweepAfterTime
	}
	rows, e := s.pool.Query(ctx, `SELECT `+shareColumns+` FROM beam_shares WHERE state IN ('starting','active','paused') AND ($1::timestamptz IS NULL OR (expires_at,id)>($1,$2::uuid)) ORDER BY expires_at,id LIMIT 500`, after, s.sweepAfterID)
	if e != nil {
		return e
	}
	var candidates []Share
	for rows.Next() {
		r, e := scanShare(rows)
		if e != nil {
			rows.Close()
			return e
		}
		candidates = append(candidates, r)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	if len(candidates) == 0 {
		s.sweepAfterTime, s.sweepAfterID = time.Time{}, uuid.Nil
	} else {
		last := candidates[len(candidates)-1]
		s.sweepAfterTime, s.sweepAfterID = last.ExpiresAt, last.ID
	}
	for _, r := range candidates {
		p, e := s.policy(ctx, s.pool, r.OrgID)
		if e != nil {
			return e
		}
		state := ""
		if !r.ExpiresAt.After(time.Now()) || !r.CreatedAt.Add(time.Duration(p.MaxDuration)*time.Second).After(time.Now()) {
			state = "expired"
		} else if _, e = s.source(ctx, s.pool, r, p); e != nil {
			state = "revoked"
		} else if r.State == "starting" && r.CreatedAt.Before(time.Now().Add(-2*time.Minute)) && r.LastHeartbeat == nil {
			state = "stopped"
		}
		if state == "" {
			continue
		}
		tx, e := s.transaction(ctx, r.OrgID)
		if e != nil {
			return e
		}
		tag, e := tx.Exec(ctx, `UPDATE beam_shares SET state=$3,origin_ready=false,certificate_serial=NULL,version=version+1,authority_version=authority_version+1 WHERE org_id=$1 AND id=$2 AND version=$4 AND state IN ('starting','active','paused')`, r.OrgID, r.ID, state, r.Version)
		if e == nil && tag.RowsAffected() > 0 {
			e = audit(ctx, tx, r.OrgID, uuid.Nil, "share."+state, r.ID)
		}
		if e == nil {
			e = tx.Commit(ctx)
		} else {
			_ = tx.Rollback(ctx)
		}
		if e != nil {
			return e
		}
	}
	_, e = s.pool.Exec(ctx, `DELETE FROM beam_streams WHERE expires_at<now()-interval '1 minute'; DELETE FROM beam_browser_sessions WHERE expires_at<now(); DELETE FROM beam_launch_codes WHERE expires_at<now(); DELETE FROM beam_pending_launches WHERE expires_at<now()`)
	return e
}
