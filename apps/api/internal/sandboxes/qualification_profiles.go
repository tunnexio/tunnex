package sandboxes

import (
	"context"
	"strings"
	"time"

	"github.com/google/uuid"
)

const qualificationBundle = "native-amd64-20261003"

var qualificationProfiles = []struct{ name, digest string }{
	{"Minimal", "sha256:ba91b86b3ffd50880f47d14be0d04b9e6cfaca454435b7fe5ed5bb51cf4b16d5"},
	{"Python", "sha256:a1ae8007032ccd196d7d52efd62f656190bc24349c3dd7c41e13601907a21994"},
	{"Node.js", "sha256:0c8afe8d5f8c8bca193dc496dc9f82438e6db72cedb07360a72a6f15f280c6fb"},
}

// QualificationProfileOperator is a trusted, explicitly invoked fixture tool.
// It never accepts an organization, principal, runtime limit or scope from HTTP.
type QualificationProfileOperator struct {
	store                 *Store
	org, gateway, creator uuid.UUID
}

func qualificationDatabase(name string) bool {
	suffix := strings.TrimPrefix(name, "tunnex_sandbox_qual_")
	if suffix == name || len(suffix) < 8 || len(suffix) > 64 {
		return false
	}
	for _, r := range suffix {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_') {
			return false
		}
	}
	return true
}
func NewQualificationProfileOperator(ctx context.Context, store *Store, org, gateway uuid.UUID) (*QualificationProfileOperator, error) {
	if store == nil || store.pool == nil || store.qualificationOrg != org || org == uuid.Nil || gateway == uuid.Nil {
		return nil, ErrDisabled
	}
	var database string
	if err := store.pool.QueryRow(ctx, `SELECT current_database()`).Scan(&database); err != nil || !qualificationDatabase(database) {
		return nil, ErrDisabled
	}
	creator, err := qualificationCreator(ctx, store, org, gateway)
	if err != nil {
		return nil, err
	}
	return &QualificationProfileOperator{store, org, gateway, creator}, nil
}
func qualificationCreator(ctx context.Context, store *Store, org, gateway uuid.UUID) (uuid.UUID, error) {
	var valid bool
	if err := store.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM organizations o JOIN nodes n ON n.org_id=o.id WHERE o.id=$1 AND n.id=$2 AND o.name='Sandbox qualification 0' AND o.slug=o.id::text AND o.pool_cidr='10.254.242.0/24' AND o.sandboxes_enabled AND o.zero_trust_mode='enforcing' AND o.max_sandboxes=1 AND o.max_sandboxes_per_user=1 AND n.status='active' AND n.name='sandbox-qualification-gateway')`, org, gateway).Scan(&valid); err != nil || !valid {
		return uuid.Nil, ErrDisabled
	}
	rows, err := store.pool.Query(ctx, `SELECT m.user_id FROM memberships m JOIN users u ON u.id=m.user_id WHERE m.org_id=$1 AND m.role='owner' AND u.email=u.id::text||'@sandbox.example.test' AND u.deleted_at IS NULL`, org)
	if err != nil {
		return uuid.Nil, ErrDisabled
	}
	defer rows.Close()
	var creators []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err = rows.Scan(&id); err != nil {
			return uuid.Nil, ErrDisabled
		}
		creators = append(creators, id)
	}
	if rows.Err() != nil || len(creators) != 1 {
		return uuid.Nil, ErrDisabled
	}
	return creators[0], nil
}
func qualificationProfile(digest string) (int, string, error) {
	for i, p := range qualificationProfiles {
		if p.digest == digest {
			return i, p.name, nil
		}
	}
	return 0, "", ErrInvalid
}
func qualificationTemplate(org uuid.UUID, digest string) uuid.UUID {
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte(qualificationBundle+":"+org.String()+":"+digest))
}
func qualificationKey(index int) string {
	name, _ := qualificationProfileAt(index)
	return qualificationBundle + ":" + name
}

func (o *QualificationProfileOperator) Create(ctx context.Context, digest string, publicKeys []string) (Sandbox, bool, error) {
	return o.CreateWithTTL(ctx, digest, publicKeys, 900)
}

// CreateWithTTL permits a shorter five-minute qualification within the same
// fifteen-minute approved ceiling, so actual expiry can be observed naturally.
func (o *QualificationProfileOperator) CreateWithTTL(ctx context.Context, digest string, publicKeys []string, ttl int32) (Sandbox, bool, error) {
	index, _, err := qualificationProfile(digest)
	if err != nil {
		return Sandbox{}, false, err
	}
	return o.createProfile(ctx, index, publicKeys, ttl)
}

// Supplemental admission is explicit and limited to the approved fourth/fifth identities.
func (o *QualificationProfileOperator) CreateSupplementalWithTTL(ctx context.Context, digest string, publicKeys []string, ttl int32) (Sandbox, bool, error) {
	index, _, err := qualificationProfile(digest)
	if err != nil || index > 1 {
		return Sandbox{}, false, ErrInvalid
	}
	return o.createProfile(ctx, index+3, publicKeys, ttl)
}
func qualificationProfileAt(index int) (name, digest string) {
	if index < 3 {
		return qualificationProfiles[index].name, qualificationProfiles[index].digest
	}
	return "Supplemental " + qualificationProfiles[index-3].name, qualificationProfiles[index-3].digest
}
func qualificationProfileTemplate(org uuid.UUID, index int) uuid.UUID {
	_, digest := qualificationProfileAt(index)
	if index < 3 {
		return qualificationTemplate(org, digest)
	}
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte(qualificationBundle+":supplemental:"+org.String()+":"+digest))
}
func (o *QualificationProfileOperator) createProfile(ctx context.Context, index int, publicKeys []string, ttl int32) (Sandbox, bool, error) {
	if ttl != 300 && ttl != 900 {
		return Sandbox{}, false, ErrInvalid
	}
	if o == nil || o.store == nil {
		return Sandbox{}, false, ErrDisabled
	}
	name, digest := qualificationProfileAt(index)
	keys, err := NormalizeSSHPublicKeys(publicKeys, 1)
	if err != nil || len(keys) != 1 {
		return Sandbox{}, false, ErrInvalid
	}
	conn, err := o.store.pool.Acquire(ctx)
	if err != nil {
		return Sandbox{}, false, err
	}
	defer conn.Release()
	lock := qualificationBundle + ":" + o.org.String()
	if _, err = conn.Exec(ctx, `SELECT pg_advisory_lock(hashtextextended($1,1))`, lock); err != nil {
		return Sandbox{}, false, err
	}
	defer func() {
		unlock, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		if _, e := conn.Exec(unlock, `SELECT pg_advisory_unlock(hashtextextended($1,1))`, lock); e != nil {
			_ = conn.Conn().Close(unlock)
		}
	}()
	input := CreateInput{TemplateID: qualificationProfileTemplate(o.org, index), Name: "Native " + name, SSHPublicKeys: keys, Requested: []Scope{}, SelectedSkills: []SkillSelection{}, TTLSeconds: ttl, IdempotencyKey: qualificationKey(index)}
	var replay bool
	if err = conn.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM sandboxes WHERE org_id=$1 AND creator_id=$2 AND idempotency_key=$3)`, o.org, o.creator, input.IdempotencyKey).Scan(&replay); err != nil {
		return Sandbox{}, false, err
	}
	if replay {
		return o.store.Create(ctx, o.org, o.creator, input)
	}
	var retained, accepted int
	if err = conn.QueryRow(ctx, `SELECT count(*) FILTER(WHERE observed_state<>'deleted'),count(*) FILTER(WHERE idempotency_key LIKE $2) FROM sandboxes WHERE org_id=$1`, o.org, qualificationBundle+":%").Scan(&retained, &accepted); err != nil {
		return Sandbox{}, false, err
	}
	if retained != 0 || accepted != index || accepted >= 5 {
		return Sandbox{}, false, ErrQuota
	}
	if index > 0 {
		var previous bool
		if err = conn.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM sandboxes s JOIN sandbox_templates t ON t.id=s.template_id AND t.org_id=s.org_id WHERE s.org_id=$1 AND s.creator_id=$2 AND s.idempotency_key=$3 AND s.observed_state='deleted' AND s.desired_state='deleted' AND NOT t.enabled)`, o.org, o.creator, qualificationKey(index-1)).Scan(&previous); err != nil {
			return Sandbox{}, false, err
		}
		if !previous {
			return Sandbox{}, false, ErrConflict
		}
	}
	var deadline *time.Time
	if err = conn.QueryRow(ctx, `SELECT min(created_at) FROM sandbox_templates WHERE org_id=$1 AND name LIKE $2`, o.org, qualificationBundle+":%").Scan(&deadline); err != nil {
		return Sandbox{}, false, err
	}
	if deadline != nil && !qualificationAdmissionAllowed(time.Now(), ttl, *deadline) {
		return Sandbox{}, false, ErrDisabled
	}
	if _, err = conn.Exec(ctx, `INSERT INTO sandbox_templates(id,org_id,name,image_digest,maximum_scope,memory_mib,max_ttl_seconds,enabled) VALUES($1,$2,$3,$4,'[]',128,900,true) ON CONFLICT DO NOTHING`, input.TemplateID, o.org, qualificationBundle+":"+name, digest); err != nil {
		return Sandbox{}, false, err
	}
	var compatible bool
	if err = conn.QueryRow(ctx, `SELECT image_digest=$3 AND memory_mib=128 AND max_ttl_seconds=900 AND maximum_scope='[]'::jsonb AND enabled AND name=$4 FROM sandbox_templates WHERE id=$1 AND org_id=$2`, input.TemplateID, o.org, digest, qualificationBundle+":"+name).Scan(&compatible); err != nil || !compatible {
		return Sandbox{}, false, ErrConflict
	}
	out, replayed, err := o.store.Create(ctx, o.org, o.creator, input)
	if err != nil {
		_, _ = conn.Exec(ctx, `UPDATE sandbox_templates SET enabled=false WHERE id=$1 AND org_id=$2`, input.TemplateID, o.org)
	}
	return out, replayed, err
}
func (o *QualificationProfileOperator) owned(ctx context.Context, id uuid.UUID) (Sandbox, error) {
	if o == nil || o.store == nil {
		return Sandbox{}, ErrDisabled
	}
	out, err := o.store.Get(ctx, o.org, o.creator, id)
	if err != nil {
		return Sandbox{}, err
	}
	var key string
	if err = o.store.pool.QueryRow(ctx, `SELECT idempotency_key FROM sandboxes WHERE id=$1 AND org_id=$2 AND creator_id=$3`, id, o.org, o.creator).Scan(&key); err != nil {
		return Sandbox{}, ErrForbidden
	}
	for i := 0; i < 5; i++ {
		if key == qualificationKey(i) && out.TemplateVersionID == qualificationProfileTemplate(o.org, i) {
			return out, nil
		}
	}
	return Sandbox{}, ErrForbidden
}
func (o *QualificationProfileOperator) Status(ctx context.Context, id uuid.UUID) (Sandbox, error) {
	return o.owned(ctx, id)
}
func (o *QualificationProfileOperator) SetDesired(ctx context.Context, id uuid.UUID, generation int64, desired string) (Sandbox, error) {
	if _, err := o.owned(ctx, id); err != nil {
		return Sandbox{}, err
	}
	return o.store.SetDesired(ctx, o.org, o.creator, id, generation, desired)
}

// Finish withdraws only this operator's temporary catalog publication after
// physical cleanup proof. Immutable audit/lifecycle tombstones remain retained.
func (o *QualificationProfileOperator) Finish(ctx context.Context, id uuid.UUID) error {
	out, err := o.owned(ctx, id)
	if err != nil {
		return err
	}
	if out.State != StateDeleted || out.DesiredState != "deleted" {
		return ErrConflict
	}
	_, err = o.store.pool.Exec(ctx, `UPDATE sandbox_templates SET enabled=false WHERE id=$1 AND org_id=$2`, out.TemplateVersionID, o.org)
	return err
}

// Fixed renewal for the existing native-amd64-20261003 bundle only.
// Admission changes neither accepted expiry nor identities, order or quotas.
func qualificationAdmissionAllowed(now time.Time, ttl int32, firstTemplate time.Time) bool {
	deadline := firstTemplate.Add(45 * time.Minute)
	approved := time.Date(2026, time.October, 3, 15, 30, 0, 0, time.UTC)
	if deadline.Before(approved) {
		deadline = approved
	}
	return now.Add(time.Duration(ttl) * time.Second).Before(deadline)
}
