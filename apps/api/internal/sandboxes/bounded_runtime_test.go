package sandboxes

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func boundedTestBinding() BoundedRuntimeBinding {
	return BoundedRuntimeBinding{OrgID: uuid.New(), CreatorID: uuid.New(), GatewayID: uuid.New(), TerminalDeviceID: uuid.New(), TemplateID: uuid.New(), ImageDigest: "sha256:" + strings.Repeat("a", 64), MemoryMiB: 128, CPUs: 1, PIDs: 128, MaxTTLSeconds: 3600, ExpiresAt: time.Now().UTC().Add(time.Hour)}
}
func TestBoundedRuntimeIdentityDeadlineAndLimits(t *testing.T) {
	b := boundedTestBinding()
	if b.Validate() != nil || !b.Allows(b.OrgID, b.CreatorID, time.Now()) {
		t.Fatal("valid binding denied")
	}
	if b.Allows(uuid.New(), b.CreatorID, time.Now()) || b.Allows(b.OrgID, uuid.New(), time.Now()) || b.Allows(b.OrgID, b.CreatorID, b.ExpiresAt) {
		t.Fatal("binding widened or expiry accepted")
	}
	for _, change := range []func(*BoundedRuntimeBinding){func(b *BoundedRuntimeBinding) { b.CreatorID = uuid.Nil }, func(b *BoundedRuntimeBinding) { b.MemoryMiB = 256 }, func(b *BoundedRuntimeBinding) { b.CPUs = 2 }, func(b *BoundedRuntimeBinding) { b.PIDs = 256 }, func(b *BoundedRuntimeBinding) { b.MaxTTLSeconds = 3601 }, func(b *BoundedRuntimeBinding) { b.ImageDigest = "latest" }, func(b *BoundedRuntimeBinding) { b.ExpiresAt = time.Time{} }} {
		copy := b
		change(&copy)
		if copy.Validate() == nil {
			t.Fatal("invalid bounded limits admitted")
		}
	}
	if _, err := NewAPIOrchestrator(nil, b, nil, nil, nil); !errors.Is(err, ErrDisabled) {
		t.Fatal("missing authority admitted")
	}
	if err := (*APIOrchestrator)(nil).Run(context.Background(), nil); !errors.Is(err, ErrDisabled) {
		t.Fatal("nil orchestrator active")
	}
}
func TestBoundedRuntimePostgresAdmissionReplayAndLifetimeQuota(t *testing.T) {
	f := newFixture(t)
	b := boundedTestBinding()
	b.OrgID, b.CreatorID, b.GatewayID = f.org, f.user, f.node
	seedBoundedTerminalDevice(t, f, b)
	if _, err := f.pool.Exec(f.ctx, `INSERT INTO sandbox_templates(id,org_id,name,image_digest,maximum_scope,memory_mib,max_ttl_seconds,enabled) VALUES($1,$2,'bounded',$3,'[]',128,3600,true)`, b.TemplateID, b.OrgID, b.ImageDigest); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.WithBoundedRuntime(b); err != nil {
		t.Fatal(err)
	}
	in := f.input("native-main")
	in.TemplateID = b.TemplateID
	in.Requested = []Scope{}
	if f.store.CreationAvailable(f.org, f.other) || f.store.CreationAvailable(uuid.New(), f.user) {
		t.Fatal("foreign availability")
	}
	if _, _, err := f.store.Create(f.ctx, f.org, f.other, in); !errors.Is(err, ErrDisabled) {
		t.Fatal("foreign creator admitted", err)
	}
	original := in
	in.TemplateID = f.template
	if _, _, err := f.store.Create(f.ctx, f.org, f.user, in); !errors.Is(err, ErrInvalid) {
		t.Fatal("unapproved template admitted", err)
	}
	in = original
	in.TTLSeconds = 3601
	if _, _, err := f.store.Create(f.ctx, f.org, f.user, in); !errors.Is(err, ErrInvalid) {
		t.Fatal("TTL expansion admitted", err)
	}
	in = original
	first, replay, err := f.store.Create(f.ctx, f.org, f.user, in)
	if err != nil || replay {
		t.Fatal("create failed", err)
	}
	var pinned, localGateway uuid.UUID
	if err = f.pool.QueryRow(f.ctx, `SELECT terminal_device_id,local_terminal_gateway_id FROM sandboxes WHERE id=$1`, first.Identity.ID).Scan(&pinned, &localGateway); err != nil || pinned != b.TerminalDeviceID || localGateway != b.GatewayID {
		t.Fatal("terminal device was not pinned", err)
	}
	if _, err = f.pool.Exec(f.ctx, `UPDATE sandboxes SET terminal_device_id=NULL WHERE id=$1`, first.Identity.ID); err == nil {
		t.Fatal("terminal pin was mutable")
	}
	if _, err = f.pool.Exec(f.ctx, `UPDATE sandboxes SET local_terminal_gateway_id=NULL WHERE id=$1`, first.Identity.ID); err == nil {
		t.Fatal("local gateway proof was mutable")
	}
	if _, err = f.pool.Exec(f.ctx, `UPDATE sandboxes SET requested_scope='[{"cidr":"10.0.0.0/8","protocol":"any","port_low":0,"port_high":0}]' WHERE id=$1`, first.Identity.ID); err == nil {
		t.Fatal("local-only record accepted outbound scope")
	}
	again, replay, err := f.store.Create(f.ctx, f.org, f.user, in)
	if err != nil || !replay || again.Identity.ID != first.Identity.ID {
		t.Fatal("idempotent replay changed identity", err)
	}
	if _, err = f.pool.Exec(f.ctx, `UPDATE sandboxes SET desired_state='deleted',observed_state='deleted' WHERE id=$1`, first.Identity.ID); err != nil {
		t.Fatal(err)
	}
	in.IdempotencyKey = "another"
	if _, _, err = f.store.Create(f.ctx, f.org, f.user, in); !errors.Is(err, ErrQuota) {
		t.Fatal("tombstone reopened launch budget", err)
	}
	f.store.boundedRuntime.ExpiresAt = time.Now().Add(-time.Second)
	if f.store.CreationAvailable(f.org, f.user) {
		t.Fatal("expired availability")
	}
	if _, _, err = f.store.Create(f.ctx, f.org, f.user, original); !errors.Is(err, ErrDisabled) {
		t.Fatal("expired binding admitted", err)
	}
}

func seedBoundedTerminalDevice(t *testing.T, f fixture, b BoundedRuntimeBinding) {
	t.Helper()
	if _, err := f.pool.Exec(f.ctx, `INSERT INTO devices(id,org_id,user_id,node_id,name,public_key,assigned_ip,kind) VALUES($1,$2,$3,$4,'verified terminal',$5,'10.99.0.2','human')`, b.TerminalDeviceID, f.org, f.user, f.node, b.TerminalDeviceID.String()); err != nil {
		t.Fatal(err)
	}
}

func TestInitialOperatorIntentCannotWidenBinding(t *testing.T) {
	b := boundedTestBinding()
	o := &APIOrchestrator{binding: b}
	key := publicTerminalKey(t)
	valid := CreateInput{TemplateID: b.TemplateID, Name: "approved", TTLSeconds: 3600, SSHPublicKeys: []string{key}}
	if err := o.ConfigureInitialCreate(&valid); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*CreateInput){func(in *CreateInput) { in.TemplateID = uuid.New() }, func(in *CreateInput) { in.TTLSeconds = 3601 }, func(in *CreateInput) { in.SSHPublicKeys = append(in.SSHPublicKeys, key) }, func(in *CreateInput) { in.Requested = []Scope{{CIDR: "10.0.0.0/8", Protocol: "any"}} }, func(in *CreateInput) { in.Name = "" }} {
		in := valid
		change(&in)
		if o.ConfigureInitialCreate(&in) == nil {
			t.Fatal("operator intent expanded allowed envelope")
		}
	}
}
