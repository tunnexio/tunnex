package sandboxes

import (
	"bytes"
	"context"
	"errors"
	appcrypto "github.com/tunnexio/tunnex/apps/api/internal/crypto"
	"testing"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/nodes"
)

type policyReaderFixture struct {
	org   uuid.UUID
	ids   []uuid.UUID
	calls int
}

func (r *policyReaderFixture) PolicyHealthForNodes(_ context.Context, org uuid.UUID, selected []sqlc.Node, _ ...nodes.SiteTopoBatch) map[uuid.UUID]nodes.PolicyHealth {
	r.org = org
	r.calls++
	r.ids = nil
	out := make(map[uuid.UUID]nodes.PolicyHealth, len(selected))
	for _, node := range selected {
		r.ids = append(r.ids, node.ID)
		out[node.ID] = nodes.PolicyHealth{Kind: nodes.KindHealthy, PushKnown: true, PushedHash: "finalized", AppliedHash: "finalized"}
	}
	return out
}

func TestPolicyAcknowledgementsPostgresOrganizationAndBound(t *testing.T) {
	f := newFixture(t)
	if _, err := f.pool.Exec(f.ctx, `UPDATE nodes SET status='active',policy_reported_at=now() WHERE id=$1`, f.node); err != nil {
		t.Fatal(err)
	}
	reader := &policyReaderFixture{}
	got, err := f.store.CurrentPolicyAcknowledgements(f.ctx, f.org, f.node, reader)
	if err != nil || len(got) != 1 || reader.org != f.org || len(reader.ids) != 1 || reader.ids[0] != f.node {
		t.Fatalf("canonical reader inputs: %v %v %+v", got, err, reader)
	}
	if _, err = f.store.CurrentPolicyAcknowledgements(f.ctx, uuid.New(), f.node, reader); !errors.Is(err, ErrDisabled) || reader.calls != 1 {
		t.Fatal("empty organization reached reader", err)
	}
	if _, err = f.store.CurrentPolicyAcknowledgements(f.ctx, f.org, f.node, nil); !errors.Is(err, ErrDisabled) {
		t.Fatal("missing canonical reader accepted", err)
	}
	// The existing gateway plus 100 more must fail before canonical computation,
	// instead of silently proving only the first 100 enforcement nodes.
	for range 100 {
		id := uuid.New()
		if _, err = f.pool.Exec(f.ctx, `INSERT INTO nodes(id,org_id,name,cert_serial,status,policy_reported_at) VALUES($1,$2,$3,$3,'active',now())`, id, f.org, id.String()); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = f.store.CurrentPolicyAcknowledgements(f.ctx, f.org, f.node, reader); !errors.Is(err, ErrDisabled) || reader.calls != 1 {
		t.Fatal("oversized enforcement set reached reader", err)
	}
}

func TestLocalTerminalAcknowledgementsExcludeUnrelatedButKeepPrimaryProof(t *testing.T) {
	f := newFixture(t)
	b := boundedTestBinding()
	b.OrgID, b.CreatorID, b.GatewayID = f.org, f.user, f.node
	seedBoundedTerminalDevice(t, f, b)
	if _, err := f.pool.Exec(f.ctx, `INSERT INTO sandbox_templates(id,org_id,name,image_digest,maximum_scope,memory_mib,max_ttl_seconds,enabled) VALUES($1,$2,'local terminal',$3,'[]',128,3600,true)`, b.TemplateID, b.OrgID, b.ImageDigest); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.WithBoundedRuntime(b); err != nil {
		t.Fatal(err)
	}
	in := f.input("local-ack")
	in.TemplateID = b.TemplateID
	in.Requested = []Scope{}
	out, _, err := f.store.Create(f.ctx, f.org, f.user, in)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.store.ReconcileQuarantinedStart(f.ctx, out.Identity.ID, &startProvider{}); err != nil {
		t.Fatal(err)
	}
	if _, err = f.pool.Exec(f.ctx, `UPDATE nodes SET endpoint='127.0.0.1:51820',wg_public_key='fixture',policy_reported_at=now() WHERE id=$1`, f.node); err != nil {
		t.Fatal(err)
	}
	sealer, _ := appcrypto.NewSealer(bytes.Repeat([]byte{7}, 32))
	handoff, err := f.store.PrepareLaunch(f.ctx, out.Identity.ID, f.node, sealer)
	if err != nil {
		t.Fatal(err)
	}
	target := PrivateNetworkTarget{OperationID: handoff.OperationID, OrgID: f.org, SandboxID: out.Identity.ID, GatewayID: f.node, Generation: handoff.Generation, RuntimeID: handoff.RuntimeID, SpecHash: handoff.SpecHash}
	unrelated := uuid.New()
	if _, err = f.pool.Exec(f.ctx, `INSERT INTO nodes(id,org_id,name,cert_serial,status,policy_reported_at) VALUES($1,$2,'unrelated','unrelated','active',now()-interval '1 hour')`, unrelated, f.org); err != nil {
		t.Fatal(err)
	}
	if _, err = f.store.IssueBootstrap(f.ctx, f.org, f.user, out.Identity.ID, unrelated); !errors.Is(err, ErrConflict) {
		t.Fatal("local record issued token for another gateway", err)
	}
	reader := &policyReaderFixture{}
	ack, err := f.store.CurrentSandboxPolicyAcknowledgements(f.ctx, target, reader)
	if err != nil || len(ack) != 1 || len(reader.ids) != 1 || reader.ids[0] != f.node {
		t.Fatalf("local gate required unrelated gateway: %+v %v %+v", ack, err, reader.ids)
	}
	if _, err = f.store.CurrentPolicyAcknowledgements(f.ctx, f.org, f.node, reader); !errors.Is(err, ErrDisabled) {
		t.Fatal("legacy gate ignored unrelated stale active gateway", err)
	}
	bad := target
	bad.SpecHash = "wrong"
	if _, err = f.store.CurrentSandboxPolicyAcknowledgements(f.ctx, bad, reader); !errors.Is(err, ErrDisabled) {
		t.Fatal("wrong operation identity admitted", err)
	}
	if _, err = f.pool.Exec(f.ctx, `UPDATE nodes SET policy_reported_at=now()-interval '1 hour' WHERE id=$1`, f.node); err != nil {
		t.Fatal(err)
	}
	if _, err = f.store.CurrentSandboxPolicyAcknowledgements(f.ctx, target, reader); !errors.Is(err, ErrDisabled) {
		t.Fatal("stale actual enforcement gateway admitted", err)
	}
	var status string
	if err = f.pool.QueryRow(f.ctx, `SELECT status FROM nodes WHERE id=$1`, unrelated).Scan(&status); err != nil || status != "active" {
		t.Fatal("unrelated gateway was changed", err)
	}
}
