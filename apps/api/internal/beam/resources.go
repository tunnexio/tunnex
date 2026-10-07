package beam

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
	"strings"
	"time"
	"unicode/utf8"
)

func (s *Service) transaction(ctx context.Context, org uuid.UUID) (pgx.Tx, error) {
	if s.pool == nil {
		return nil, unavailable()
	}
	tx, e := s.pool.Begin(ctx)
	if e != nil {
		return nil, e
	}
	if _, e = tx.Exec(ctx, `SELECT version FROM beam_installation_settings WHERE singleton FOR SHARE`); e != nil {
		_ = tx.Rollback(ctx)
		return nil, e
	}
	if _, e = tx.Exec(ctx, `INSERT INTO beam_policies(org_id) VALUES($1) ON CONFLICT DO NOTHING`, org); e == nil {
		_, e = tx.Exec(ctx, `SELECT version FROM beam_policies WHERE org_id=$1 FOR UPDATE`, org)
	}
	if e != nil {
		_ = tx.Rollback(ctx)
		return nil, e
	}
	return tx, nil
}
func audit(ctx context.Context, tx pgx.Tx, org, actor uuid.UUID, action string, id uuid.UUID) error {
	var who any
	if actor != uuid.Nil {
		who = actor
	}
	_, e := tx.Exec(ctx, `INSERT INTO audit_logs(org_id,actor_user_id,action,target_type,target_id,metadata) VALUES($1,$2,$3,'beam_share',$4,'{"outcome":"success"}')`, org, who, "beam."+action, id.String())
	return e
}
func (s *Service) validateSubjects(ctx context.Context, q reader, org, owner uuid.UUID, p Policy, grants []Grant) error {
	if len(grants) > 100 {
		return invalid("At most 100 reviewers are supported")
	}
	seen := map[Grant]bool{}
	for _, g := range grants {
		if g.SubjectID == uuid.Nil || seen[g] {
			return invalid("Invalid or duplicate reviewer")
		}
		seen[g] = true
		var exists bool
		switch g.SubjectKind {
		case "user":
			if p.OpenForAllUsers && s.member(ctx, q, org, g.SubjectID, rbac.PermBeamUse) != nil {
				return invalid("Reviewer is not an eligible member of this organization")
			}
			e := q.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM memberships m JOIN users u ON u.id=m.user_id WHERE m.org_id=$1 AND m.user_id=$2 AND u.status='active' AND u.deleted_at IS NULL AND ($5 OR $2=$3 OR $2=ANY($4::uuid[])))`, org, g.SubjectID, owner, p.ReviewerUsers, p.OpenForAllUsers).Scan(&exists)
			if e != nil {
				return e
			}
		case "group":
			e := q.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM user_groups WHERE org_id=$1 AND id=$2 AND ($4 OR id=ANY($3::uuid[])))`, org, g.SubjectID, p.ReviewerGroups, p.OpenForAllUsers).Scan(&exists)
			if e != nil {
				return e
			}
		default:
			return invalid("Reviewer must be a user or group")
		}
		if !exists {
			return invalid("Reviewer is outside the permitted audience")
		}
	}
	return nil
}
func (s *Service) UpdatePolicy(ctx context.Context, org uuid.UUID, a Actor, in PolicyInput) (Policy, error) {
	tx, p, e := s.preparePolicy(ctx, org, a, in)
	if e != nil {
		return p, e
	}
	defer tx.Rollback(ctx)
	impact, e := s.policyImpact(ctx, tx, org, p, in)
	if e != nil {
		return p, e
	}
	if impact.RequiresConfirmation && !in.ConfirmEndActiveShares {
		return p, confirmation("Confirm the policy impact before saving")
	}
	_, e = tx.Exec(ctx, `UPDATE beam_policies SET enabled=$2,version=version+1,publisher_group_ids=$3,reviewer_user_ids=$4,reviewer_group_ids=$5,max_duration_seconds=$6,max_shares=$7,require_mfa=$8,open_for_all_users=$9 WHERE org_id=$1`, org, in.Enabled, nonNil(in.PublisherGroups), nonNil(in.ReviewerUsers), nonNil(in.ReviewerGroups), in.MaxDuration, in.MaxShares, in.RequireMFA, nextPolicy(p, in).OpenForAllUsers)
	if e != nil {
		return p, e
	}
	if !in.Enabled {
		_, e = tx.Exec(ctx, `UPDATE beam_shares SET state='revoked',version=version+1,authority_version=authority_version+1,certificate_serial=NULL,origin_ready=false WHERE org_id=$1 AND state IN ('starting','active','paused')`, org)
	} else {
		_, e = tx.Exec(ctx, `UPDATE beam_shares SET expires_at=LEAST(expires_at,created_at+make_interval(secs=>$2)),version=version+1,authority_version=authority_version+1 WHERE org_id=$1 AND state IN ('starting','active','paused')`, org, in.MaxDuration)
	}
	if e != nil {
		return p, e
	}
	if e = audit(ctx, tx, org, a.ID, "policy.updated", org); e != nil {
		return p, e
	}
	if e = tx.Commit(ctx); e != nil {
		return p, e
	}
	return s.GetPolicy(ctx, org, a)
}
func nonNil[T any](v []T) []T {
	if v == nil {
		return []T{}
	}
	return v
}
func (s *Service) Create(ctx context.Context, org uuid.UUID, a Actor, in CreateInput) (Share, error) {
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" || !utf8.ValidString(in.Name) || utf8.RuneCountInString(in.Name) > 100 || strings.ContainsAny(in.Name, "\r\n\x00") || in.IdempotencyKey == uuid.Nil {
		return Share{}, invalid("Name and idempotency key required")
	}
	if e := ValidateTarget(in.Target); e != nil {
		return Share{}, e
	}
	if a.CredentialID == uuid.Nil {
		return Share{}, deny()
	}
	requestDigest := digest(in)
	tx, e := s.transaction(ctx, org)
	if e != nil {
		return Share{}, e
	}
	defer tx.Rollback(ctx)
	p, e := s.policy(ctx, tx, org)
	if e != nil {
		return Share{}, e
	}
	if e = s.publisher(ctx, tx, org, a.ID, p); e != nil {
		return Share{}, e
	}
	if in.ProjectID != nil {
		if _, e = s.project(ctx, tx, org, *in.ProjectID, a); e != nil {
			return Share{}, e
		}
	}
	var previous string
	r, e := scanShare(tx.QueryRow(ctx, `SELECT `+shareColumns+` FROM beam_shares WHERE org_id=$1 AND publisher_id=$2 AND idempotency_key=$3`, org, a.ID, in.IdempotencyKey))
	if e == nil {
		e = tx.QueryRow(ctx, `SELECT request_digest FROM beam_shares WHERE org_id=$1 AND id=$2`, org, r.ID).Scan(&previous)
		if e != nil {
			return r, e
		}
		if requestDigest != previous {
			return r, conflict()
		}
		return s.decorate(ctx, tx, r, a, true)
	}
	if !errors.Is(e, pgx.ErrNoRows) {
		return Share{}, e
	}
	if in.Duration < 60 || in.Duration > p.MaxDuration {
		return Share{}, invalid("Duration exceeds organization policy")
	}
	if e = s.validateSubjects(ctx, tx, org, a.ID, p, in.Grants); e != nil {
		return Share{}, e
	}
	var count int
	e = tx.QueryRow(ctx, `SELECT count(*) FROM beam_shares WHERE org_id=$1 AND publisher_id=$2 AND state IN ('starting','active','paused') AND expires_at>now()`, org, a.ID).Scan(&count)
	if e != nil {
		return Share{}, e
	}
	if count >= p.MaxShares {
		return Share{}, apiQuota()
	}
	var credUntil time.Time
	e = tx.QueryRow(ctx, `SELECT expires_at FROM cli_credentials WHERE id=$1 AND user_id=$2 AND revoked_at IS NULL AND expires_at>now()`, a.CredentialID, a.ID).Scan(&credUntil)
	if e != nil {
		return Share{}, deny()
	}
	bytes := make([]byte, 16)
	if _, e = rand.Read(bytes); e != nil {
		return Share{}, e
	}
	hostname := "p-" + hex.EncodeToString(bytes) + "." + p.BaseDomain
	target, _ := json.Marshal(in.Target)
	r, e = scanShare(tx.QueryRow(ctx, `INSERT INTO beam_shares(org_id,publisher_id,source_credential_id,name,hostname,target,digest,idempotency_key,request_digest,expires_at,project_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,LEAST(now()+make_interval(secs=>$10),$11),$12) RETURNING `+shareColumns, org, a.ID, a.CredentialID, in.Name, hostname, target, digest(in.Target), in.IdempotencyKey, requestDigest, in.Duration, credUntil, in.ProjectID))
	if e != nil {
		return r, e
	}
	grants := append([]Grant{{"user", a.ID}}, in.Grants...)
	for _, g := range grants {
		_, e = tx.Exec(ctx, `INSERT INTO beam_grants(org_id,share_id,subject_kind,subject_id) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING`, org, r.ID, g.SubjectKind, g.SubjectID)
		if e != nil {
			return r, e
		}
	}
	if e = audit(ctx, tx, org, a.ID, "share.created", r.ID); e != nil {
		return r, e
	}
	if e = tx.Commit(ctx); e != nil {
		return r, e
	}
	return s.Get(ctx, org, r.ID, a)
}
func apiQuota() error { return apierr.New(429, "beam_quota_reached", "Publisher share quota reached") }
func (s *Service) decorate(ctx context.Context, q reader, r Share, a Actor, owner bool) (Share, error) {
	e := q.QueryRow(ctx, `SELECT name FROM users WHERE id=$1`, r.PublisherID).Scan(&r.PublisherName)
	if e != nil {
		return r, e
	}
	p, e := s.policy(ctx, q, r.OrgID)
	if e != nil {
		return r, e
	}
	r.CanManage = r.PublisherID == a.ID || a.ManageAll
	r.CanOpen = r.State == "active" && r.Connectivity == "online" && s.reviewer(ctx, q, r, a.ID, p) == nil
	_, e = s.source(ctx, q, r, p)
	if e != nil {
		r.CanOpen = false
		if !terminal(r.State) {
			r.State = "revoked"
		}
	}
	if owner && r.CanManage {
		rows, e := q.Query(ctx, `SELECT subject_kind,subject_id FROM beam_grants WHERE org_id=$1 AND share_id=$2 ORDER BY subject_kind,subject_id`, r.OrgID, r.ID)
		if e != nil {
			return r, e
		}
		defer rows.Close()
		r.Grants = []Grant{}
		for rows.Next() {
			var g Grant
			if e = rows.Scan(&g.SubjectKind, &g.SubjectID); e != nil {
				return r, e
			}
			r.Grants = append(r.Grants, g)
		}
		if e = rows.Err(); e != nil {
			return r, e
		}
	} else {
		r.Target = nil
	}
	return r, nil
}
func (s *Service) Get(ctx context.Context, org, id uuid.UUID, a Actor) (Share, error) {
	r, e := scanShare(s.pool.QueryRow(ctx, `SELECT `+shareColumns+` FROM beam_shares WHERE org_id=$1 AND id=$2`, org, id))
	if errors.Is(e, pgx.ErrNoRows) {
		return r, missing()
	}
	if e != nil {
		return r, e
	}
	if r.PublisherID != a.ID && !a.ManageAll {
		p, e := s.policy(ctx, s.pool, org)
		if e != nil {
			return r, e
		}
		if s.reviewer(ctx, s.pool, r, a.ID, p) != nil {
			return Share{}, missing()
		}
	}
	return s.decorate(ctx, s.pool, r, a, true)
}
func (s *Service) List(ctx context.Context, org uuid.UUID, a Actor, shared bool, limit, offset int) (Page[Share], error) {
	return s.ListFiltered(ctx, org, a, shared, limit, offset, "")
}
func (s *Service) ListFiltered(ctx context.Context, org uuid.UUID, a Actor, shared bool, limit, offset int, search string) (Page[Share], error) {
	return s.ListQuery(ctx, org, a, shared, limit, offset, search, "", "")
}
func (s *Service) ListQuery(ctx context.Context, org uuid.UUID, a Actor, shared bool, limit, offset int, search, state, connectivity string) (Page[Share], error) {
	return s.ListQueryScope(ctx, org, a, shared, limit, offset, search, state, connectivity, "")
}
func (s *Service) ListQueryScope(ctx context.Context, org uuid.UUID, a Actor, shared bool, limit, offset int, search, state, connectivity, scope string) (Page[Share], error) {
	return s.listProjectQuery(ctx, org, a, shared, limit, offset, search, state, connectivity, scope, nil)
}
func (s *Service) listProjectQuery(ctx context.Context, org uuid.UUID, a Actor, shared bool, limit, offset int, search, state, connectivity, scope string, project *uuid.UUID) (Page[Share], error) {
	if scope != "" && scope != "active" && scope != "history" {
		return Page[Share]{}, invalid("Invalid share scope")
	}
	if !validStateFilter(state) || !validConnectivityFilter(connectivity) {
		return Page[Share]{}, invalid("Invalid share filter")
	}
	if e := validateSearch(search); e != nil {
		return Page[Share]{}, e
	}
	out := Page[Share]{Items: []Share{}, Limit: limit, Offset: offset, ServerTime: time.Now()}
	p, e := s.policy(ctx, s.pool, org)
	if e != nil {
		return out, e
	}
	if !shared {
		out.Quota = &Quota{MaxShares: p.MaxShares}
		if e = s.pool.QueryRow(ctx, `SELECT count(*) FROM beam_shares WHERE org_id=$1 AND publisher_id=$2 AND state IN ('starting','active','paused') AND expires_at>now()`, org, a.ID).Scan(&out.Quota.ActiveShares); e != nil {
			return out, e
		}
	}
	where := "publisher_id=$2"
	if shared {
		where = `EXISTS(SELECT 1 FROM beam_grants g WHERE g.org_id=beam_shares.org_id AND g.share_id=beam_shares.id AND ((g.subject_kind='user' AND g.subject_id=$2) OR (g.subject_kind='group' AND EXISTS(SELECT 1 FROM group_members m WHERE m.org_id=g.org_id AND m.group_id=g.subject_id AND m.user_id=$2))))`
	}
	// Filter reviewer history before pagination using the same effective state
	// as owner filters. Ended shares remain available in the owner inventory.
	projectedState := `CASE WHEN state IN ('stopped','expired','revoked') THEN state WHEN expires_at<=now() THEN 'expired' WHEN NOT $8 OR right(hostname,length($10)+1)<>'.'||$10 OR NOT EXISTS(SELECT 1 FROM memberships pm JOIN users pu ON pu.id=pm.user_id JOIN organizations po ON po.id=pm.org_id WHERE pm.org_id=beam_shares.org_id AND pm.user_id=beam_shares.publisher_id AND pu.status='active' AND pu.deleted_at IS NULL AND pu.email_verified_at IS NOT NULL AND NOT pu.must_change_password AND po.deleted_at IS NULL AND pm.roles && ARRAY['owner','admin','member']::text[]) OR (NOT $12 AND NOT EXISTS(SELECT 1 FROM group_members pgm WHERE pgm.org_id=beam_shares.org_id AND pgm.user_id=beam_shares.publisher_id AND pgm.group_id=ANY($9::uuid[]))) OR NOT EXISTS(SELECT 1 FROM cli_credentials pc WHERE pc.id=beam_shares.source_credential_id AND pc.user_id=beam_shares.publisher_id AND pc.revoked_at IS NULL AND pc.expires_at>now()) THEN 'revoked' ELSE state END`
	rows, e := s.pool.Query(ctx, `SELECT `+shareColumns+` FROM beam_shares WHERE org_id=$1 AND `+where+` AND ($5='' OR position(lower($5) in lower(name))>0 OR position(lower($5) in lower(hostname))>0) AND (NOT $11 OR (`+projectedState+`) IN ('active','paused')) AND ($6='' OR (`+projectedState+`)=$6) AND ($7='' OR (CASE WHEN last_heartbeat_at>now()-interval '6 seconds' AND last_channel_at>now()-interval '6 seconds' THEN CASE WHEN origin_ready THEN 'online' ELSE 'origin_unavailable' END ELSE 'offline' END)=$7) AND ($14::uuid IS NULL OR project_id=$14) AND ($13='' OR ($13='active' AND (`+projectedState+`) IN ('starting','active','paused')) OR ($13='history' AND (`+projectedState+`) IN ('stopped','expired','revoked'))) ORDER BY created_at DESC,id LIMIT $3 OFFSET $4`, org, a.ID, limit, offset, search, state, connectivity, p.Enabled && p.DomainReady, p.PublisherGroups, p.BaseDomain, shared, p.OpenForAllUsers, scope, project)
	if e != nil {
		return out, e
	}
	defer rows.Close()
	for rows.Next() {
		r, e := scanShare(rows)
		if e != nil {
			return out, e
		}
		if shared && s.reviewer(ctx, s.pool, r, a.ID, p) != nil {
			continue
		}
		r, e = s.decorate(ctx, s.pool, r, a, !shared)
		if e != nil {
			return out, e
		}
		out.Items = append(out.Items, r)
	}
	return out, rows.Err()
}
func (s *Service) Action(ctx context.Context, org, id uuid.UUID, a Actor, in ActionInput) (Share, error) {
	tx, e := s.transaction(ctx, org)
	if e != nil {
		return Share{}, e
	}
	defer tx.Rollback(ctx)
	r, e := scanShare(tx.QueryRow(ctx, `SELECT `+shareColumns+` FROM beam_shares WHERE org_id=$1 AND id=$2 FOR UPDATE`, org, id))
	if e != nil {
		return r, missing()
	}
	if r.PublisherID != a.ID && !a.ManageAll {
		return r, missing()
	}
	perm := rbac.PermBeamManageOwn
	if r.PublisherID != a.ID {
		perm = rbac.PermBeamManageAll
	}
	if e = s.member(ctx, tx, org, a.ID, perm); e != nil {
		return r, e
	}
	if r.Version != in.ExpectedVersion {
		return r, conflict()
	}
	if terminal(r.State) {
		return r, invalid("Terminal shares cannot be reopened")
	}
	p, e := s.policy(ctx, tx, org)
	if e != nil {
		return r, e
	}
	state := r.State
	expiry := r.ExpiresAt
	switch in.Action {
	case "pause":
		state = "paused"
	case "stop":
		state = "stopped"
	case "resume":
		if a.CredentialID != uuid.Nil && (r.SourceCredentialID == nil || *r.SourceCredentialID != a.CredentialID) {
			// A native publisher must restore its original source credential
			// before changing state, just as connector issuance requires.
			return r, missing()
		}
		if r.State != "paused" {
			return r, invalid("Only paused shares can resume")
		}
		if _, e = s.source(ctx, tx, r, p); e != nil {
			return r, e
		}
		state = "starting"
	case "extend":
		if in.ExpiresAt == nil || !in.ExpiresAt.After(r.ExpiresAt) || in.ExpiresAt.After(r.CreatedAt.Add(time.Duration(p.MaxDuration)*time.Second)) {
			return r, invalid("Extension exceeds the original lifetime ceiling")
		}
		if _, e = s.source(ctx, tx, r, p); e != nil {
			return r, e
		}
		expiry = *in.ExpiresAt
	default:
		return r, invalid("Unsupported lifecycle action")
	}
	if in.Action == "extend" {
		_, e = tx.Exec(ctx, `UPDATE beam_shares SET expires_at=$3,version=version+1,authority_version=authority_version+1 WHERE org_id=$1 AND id=$2`, org, id, expiry)
	} else {
		_, e = tx.Exec(ctx, `UPDATE beam_shares SET state=$3,expires_at=$4,version=version+1,authority_version=authority_version+1,origin_ready=false,certificate_serial=NULL,generation=$5 WHERE org_id=$1 AND id=$2`, org, id, state, expiry, uuid.New())
	}
	if e != nil {
		return r, e
	}
	if e = audit(ctx, tx, org, a.ID, "share."+in.Action, id); e != nil {
		return r, e
	}
	if e = tx.Commit(ctx); e != nil {
		return r, e
	}
	return s.Get(ctx, org, id, a)
}
func (s *Service) UpdateGrants(ctx context.Context, org, id uuid.UUID, a Actor, in GrantsInput) (Share, error) {
	tx, e := s.transaction(ctx, org)
	if e != nil {
		return Share{}, e
	}
	defer tx.Rollback(ctx)
	r, e := scanShare(tx.QueryRow(ctx, `SELECT `+shareColumns+` FROM beam_shares WHERE org_id=$1 AND id=$2 FOR UPDATE`, org, id))
	if e != nil {
		return r, missing()
	}
	if r.PublisherID != a.ID && !a.ManageAll {
		return r, missing()
	}
	if r.Version != in.ExpectedVersion {
		return r, conflict()
	}
	p, e := s.policy(ctx, tx, org)
	if e != nil {
		return r, e
	}
	if _, e = s.source(ctx, tx, r, p); e != nil {
		return r, e
	}
	if e = s.validateSubjects(ctx, tx, org, r.PublisherID, p, in.Grants); e != nil {
		return r, e
	}
	perm := rbac.PermBeamManageOwn
	if r.PublisherID != a.ID {
		perm = rbac.PermBeamManageAll
	}
	if e = s.member(ctx, tx, org, a.ID, perm); e != nil {
		return r, e
	}
	impact, e := s.grantsImpact(ctx, tx, r, p, in)
	if e != nil {
		return r, e
	}
	if impact.RequiresConfirmation && !in.ConfirmReviewerRemoval {
		return r, confirmation("Confirm reviewer removal before saving")
	}
	if _, e = tx.Exec(ctx, `DELETE FROM beam_grants WHERE org_id=$1 AND share_id=$2`, org, id); e != nil {
		return r, e
	}
	for _, g := range in.Grants {
		if _, e = tx.Exec(ctx, `INSERT INTO beam_grants(org_id,share_id,subject_kind,subject_id) VALUES($1,$2,$3,$4)`, org, id, g.SubjectKind, g.SubjectID); e != nil {
			return r, e
		}
	}
	_, e = tx.Exec(ctx, `UPDATE beam_shares SET version=version+1,authority_version=authority_version+1 WHERE org_id=$1 AND id=$2`, org, id)
	if e != nil {
		return r, e
	}
	if e = audit(ctx, tx, org, a.ID, "grants.updated", id); e != nil {
		return r, e
	}
	if e = tx.Commit(ctx); e != nil {
		return r, e
	}
	return s.Get(ctx, org, id, a)
}
func (s *Service) Audience(ctx context.Context, org uuid.UUID, a Actor) (Audience, error) {
	out := Audience{Users: []User{}, Groups: []Group{}}
	p, e := s.policy(ctx, s.pool, org)
	if e != nil {
		return out, e
	}
	var rows pgx.Rows
	if a.ManagePolicy {
		rows, e = s.pool.Query(ctx, `SELECT u.id,u.name,u.email FROM memberships m JOIN users u ON u.id=m.user_id WHERE m.org_id=$1 AND u.deleted_at IS NULL AND u.status='active' ORDER BY u.name,u.id LIMIT CASE WHEN $2 THEN NULL ELSE 500 END`, org, p.OpenForAllUsers)
	} else {
		if e = s.publisher(ctx, s.pool, org, a.ID, p); e != nil {
			return out, e
		}
		rows, e = s.pool.Query(ctx, `SELECT u.id,u.name,u.email FROM memberships m JOIN users u ON u.id=m.user_id WHERE m.org_id=$1 AND u.deleted_at IS NULL AND u.status='active' AND ($4 OR u.id=$2 OR u.id=ANY($3::uuid[])) AND (NOT $4 OR (u.email_verified_at IS NOT NULL AND NOT u.must_change_password AND m.roles && ARRAY['owner','admin','member']::text[])) ORDER BY u.name,u.id LIMIT CASE WHEN $4 THEN NULL ELSE 500 END`, org, a.ID, p.ReviewerUsers, p.OpenForAllUsers)
	}
	if e != nil {
		return out, e
	}
	for rows.Next() {
		var u User
		if e = rows.Scan(&u.ID, &u.Name, &u.Email); e != nil {
			rows.Close()
			return out, e
		}
		out.Users = append(out.Users, u)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return out, e
	}
	ids := p.ReviewerGroups
	if a.ManagePolicy || p.OpenForAllUsers {
		rows, e = s.pool.Query(ctx, `SELECT id,name FROM user_groups WHERE org_id=$1 ORDER BY name,id LIMIT CASE WHEN $2 THEN NULL ELSE 500 END`, org, p.OpenForAllUsers)
	} else {
		rows, e = s.pool.Query(ctx, `SELECT id,name FROM user_groups WHERE org_id=$1 AND id=ANY($2::uuid[]) ORDER BY name,id LIMIT 500`, org, ids)
	}
	if e != nil {
		return out, e
	}
	defer rows.Close()
	for rows.Next() {
		var g Group
		if e = rows.Scan(&g.ID, &g.Name); e != nil {
			return out, e
		}
		out.Groups = append(out.Groups, g)
	}
	return out, rows.Err()
}
func (s *Service) Events(ctx context.Context, org uuid.UUID, limit, offset int) (Page[Event], error) {
	return s.EventsFiltered(ctx, org, limit, offset, EventFilter{})
}
