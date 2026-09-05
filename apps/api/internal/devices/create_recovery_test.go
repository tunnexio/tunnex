package devices

import (
	"context"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/internal/nodepush"
	"github.com/tunnexio/tunnex/apps/api/internal/wgkey"
)

func recoveryPool(t *testing.T) (*pgxpool.Pool, context.Context) {
	t.Helper()
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, postureDSN(t))
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool, ctx
}

func clientKey(t *testing.T) string {
	t.Helper()
	_, publicKey, err := wgkey.Generate()
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	return publicKey
}

func createManagedHuman(t *testing.T, svc *Service, org, owner, node uuid.UUID, name, publicKey string) CreateResult {
	t.Helper()
	result, err := svc.Create(context.Background(), CreateInput{
		OrgID: org, ActorID: owner, OwnerID: owner, NodeID: node,
		Name: name, Platform: "darwin", PublicKey: publicKey, Provisioning: "managed",
	})
	if err != nil {
		t.Fatalf("create %s: %v", name, err)
	}
	return result
}

func auditCount(t *testing.T, pool *pgxpool.Pool, org uuid.UUID, action string) int {
	t.Helper()
	var count int
	if err := pool.QueryRow(context.Background(),
		"SELECT count(*) FROM audit_logs WHERE org_id=$1 AND action=$2", org, action,
	).Scan(&count); err != nil {
		t.Fatalf("count audit %s: %v", action, err)
	}
	return count
}

func publicKeyCount(t *testing.T, pool *pgxpool.Pool, org uuid.UUID, publicKey string) int {
	t.Helper()
	var count int
	if err := pool.QueryRow(context.Background(),
		"SELECT count(*) FROM devices WHERE org_id=$1 AND public_key=$2", org, publicKey,
	).Scan(&count); err != nil {
		t.Fatalf("count public key: %v", err)
	}
	return count
}

func TestManagedHumanSameKeyReplayReturnsExactIdentityWithoutGrowthEffects(t *testing.T) {
	pool, ctx := recoveryPool(t)
	org, owner, node := seedPostureOrg(t, pool, "off")
	hub := nodepush.New()
	svc := NewService(pool, hub, nil)
	pushes, unsubscribe := hub.Subscribe(node)
	defer unsubscribe()
	publicKey := clientKey(t)

	created := createManagedHuman(t, svc, org, owner, node, "first", publicKey)
	select {
	case <-pushes:
	default:
		t.Fatal("first create did not push the gateway")
	}

	// Name, selected gateway, and platform are request intent, not identity. A
	// response-loss retry must recover the exact already-issued row even when the
	// current selection has drifted to a now-invalid node.
	replayed, err := svc.Create(ctx, CreateInput{
		OrgID: org, ActorID: owner, OwnerID: owner, NodeID: uuid.New(),
		Name: "changed", Platform: "win32", PublicKey: publicKey, Provisioning: "managed",
	})
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if replayed.Device.ID != created.Device.ID || replayed.Device.NodeID != created.Device.NodeID ||
		replayed.Device.AssignedIp == nil || created.Device.AssignedIp == nil ||
		*replayed.Device.AssignedIp != *created.Device.AssignedIp {
		t.Fatalf("replay changed identity/allocation: created=%+v replayed=%+v", created.Device, replayed.Device)
	}
	if replayed.PrivateKeyOneTime != "" || replayed.Config != "" {
		t.Fatal("client-key replay must not return server-held key/config material")
	}
	select {
	case <-pushes:
		t.Fatal("same-key replay pushed the gateway")
	default:
	}
	if got := publicKeyCount(t, pool, org, publicKey); got != 1 {
		t.Fatalf("same-key row count = %d, want 1", got)
	}
	if got := auditCount(t, pool, org, "device.created"); got != 1 {
		t.Fatalf("create audits = %d, want 1", got)
	}
}

func TestManagedHumanSameKeyReplayRunsBeforeDeviceCap(t *testing.T) {
	pool, ctx := recoveryPool(t)
	org, owner, node := seedPostureOrg(t, pool, "off")
	if _, err := pool.Exec(ctx, "UPDATE organizations SET max_devices_per_user=1 WHERE id=$1", org); err != nil {
		t.Fatalf("set cap: %v", err)
	}
	svc := NewService(pool, nil, nil)
	publicKey := clientKey(t)
	created := createManagedHuman(t, svc, org, owner, node, "first", publicKey)
	replayed := createManagedHuman(t, svc, org, owner, node, "retry", publicKey)
	if replayed.Device.ID != created.Device.ID {
		t.Fatalf("cap replay ID = %s, want %s", replayed.Device.ID, created.Device.ID)
	}
	_, err := svc.Create(ctx, CreateInput{
		OrgID: org, ActorID: owner, OwnerID: owner, NodeID: node,
		Name: "new-key", PublicKey: clientKey(t), Provisioning: "managed",
	})
	if code(err) != "device_limit" {
		t.Fatalf("new identity at cap: want device_limit, got %v", err)
	}
}

func TestManagedHumanPendingSameKeyReplayDoesNotDuplicate(t *testing.T) {
	pool, _ := recoveryPool(t)
	org, owner, node := seedPostureOrg(t, pool, "on")
	svc := NewService(pool, nil, nil)
	svc.SetApprovalEnforced(true)
	publicKey := clientKey(t)
	created := createManagedHuman(t, svc, org, owner, node, "pending", publicKey)
	replayed := createManagedHuman(t, svc, org, owner, node, "pending-retry", publicKey)
	if created.Device.Status != "pending" || !created.PendingApproval ||
		replayed.Device.ID != created.Device.ID || !replayed.PendingApproval {
		t.Fatalf("pending replay mismatch: created=%+v replayed=%+v", created, replayed)
	}
	if got := publicKeyCount(t, pool, org, publicKey); got != 1 {
		t.Fatalf("pending same-key row count = %d, want 1", got)
	}
}

func TestManagedHumanSameKeyReplayRefusesForeignRetiredAndAmbiguousHistory(t *testing.T) {
	t.Run("foreign owner", func(t *testing.T) {
		pool, ctx := recoveryPool(t)
		org, owner, node := seedPostureOrg(t, pool, "off")
		svc := NewService(pool, nil, nil)
		publicKey := clientKey(t)
		createManagedHuman(t, svc, org, owner, node, "owner-a", publicKey)
		other := uuid.New()
		if _, err := pool.Exec(ctx, "INSERT INTO users (id,email,name,status) VALUES ($1,$2,'Other','active')", other, other.String()+"@t.local"); err != nil {
			t.Fatalf("other user: %v", err)
		}
		if _, err := pool.Exec(ctx, "INSERT INTO memberships (org_id,user_id,role) VALUES ($1,$2,'member')", org, other); err != nil {
			t.Fatalf("other membership: %v", err)
		}
		_, err := svc.Create(ctx, CreateInput{OrgID: org, ActorID: other, OwnerID: other, NodeID: node, Name: "owner-b", PublicKey: publicKey, Provisioning: "managed"})
		if code(err) != "device_key_recovery_conflict" {
			t.Fatalf("foreign replay: want device_key_recovery_conflict, got %v", err)
		}
	})

	t.Run("revoked and deleted", func(t *testing.T) {
		pool, ctx := recoveryPool(t)
		org, owner, node := seedPostureOrg(t, pool, "off")
		svc := NewService(pool, nil, nil)
		publicKey := clientKey(t)
		created := createManagedHuman(t, svc, org, owner, node, "retired", publicKey)
		if err := svc.Revoke(ctx, org, owner, created.Device.ID); err != nil {
			t.Fatalf("revoke: %v", err)
		}
		_, err := svc.Create(ctx, CreateInput{OrgID: org, ActorID: owner, OwnerID: owner, NodeID: node, Name: "retry-revoked", PublicKey: publicKey, Provisioning: "managed"})
		if code(err) != "device_key_recovery_conflict" {
			t.Fatalf("revoked replay: want device_key_recovery_conflict, got %v", err)
		}
		if err := svc.RemoveRevoked(ctx, org, owner, created.Device.ID); err != nil {
			t.Fatalf("remove: %v", err)
		}
		_, err = svc.Create(ctx, CreateInput{OrgID: org, ActorID: owner, OwnerID: owner, NodeID: node, Name: "retry-deleted", PublicKey: publicKey, Provisioning: "managed"})
		if code(err) != "device_key_recovery_conflict" {
			t.Fatalf("deleted replay: want device_key_recovery_conflict, got %v", err)
		}
	})

	t.Run("multiple pending rows", func(t *testing.T) {
		pool, ctx := recoveryPool(t)
		org, owner, node := seedPostureOrg(t, pool, "on")
		svc := NewService(pool, nil, nil)
		svc.SetApprovalEnforced(true)
		publicKey := clientKey(t)
		createManagedHuman(t, svc, org, owner, node, "pending-a", publicKey)
		secondID := uuid.New()
		secondIP := "10.0.0.250"
		if _, err := pool.Exec(ctx, `
			INSERT INTO devices (
				id, org_id, user_id, node_id, name, platform, public_key,
				assigned_ip, status, kind, transport, provisioning_mode,
				provisioned_ip, provisioned_node_id
			) VALUES ($1,$2,$3,$4,'pending-b','darwin',$5,$6,'pending','human','wireguard','managed',$6,$4)`,
			secondID, org, owner, node, publicKey, secondIP,
		); err != nil {
			t.Fatalf("seed duplicate pending history: %v", err)
		}
		_, err := svc.Create(ctx, CreateInput{OrgID: org, ActorID: owner, OwnerID: owner, NodeID: node, Name: "retry", PublicKey: publicKey, Provisioning: "managed"})
		if code(err) != "device_key_recovery_conflict" {
			t.Fatalf("ambiguous replay: want device_key_recovery_conflict, got %v", err)
		}
	})
}

func TestManagedHumanConcurrentSameKeyCreatesConvergeOnOneIdentity(t *testing.T) {
	pool, ctx := recoveryPool(t)
	org, owner, node := seedPostureOrg(t, pool, "off")
	svc := NewService(pool, nil, nil)
	publicKey := clientKey(t)
	start := make(chan struct{})
	results := make(chan CreateResult, 2)
	errs := make(chan error, 2)
	var workers sync.WaitGroup
	for i := 0; i < 2; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			result, err := svc.Create(ctx, CreateInput{
				OrgID: org, ActorID: owner, OwnerID: owner, NodeID: node,
				Name: "same-key", PublicKey: publicKey, Provisioning: "managed",
			})
			if err != nil {
				errs <- err
				return
			}
			results <- result
		}()
	}
	close(start)
	workers.Wait()
	close(results)
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent create: %v", err)
	}
	var ids []uuid.UUID
	for result := range results {
		ids = append(ids, result.Device.ID)
	}
	if len(ids) != 2 || ids[0] != ids[1] {
		t.Fatalf("concurrent IDs = %v, want two equal IDs", ids)
	}
	if got := publicKeyCount(t, pool, org, publicKey); got != 1 {
		t.Fatalf("concurrent same-key rows = %d, want 1", got)
	}
	if got := auditCount(t, pool, org, "device.created"); got != 1 {
		t.Fatalf("concurrent create audits = %d, want 1", got)
	}
}

func TestUpdateModeSameValueIsReadThroughWithoutAuditOrPush(t *testing.T) {
	pool, ctx := recoveryPool(t)
	org, owner, node := seedPostureOrg(t, pool, "off")
	hub := nodepush.New()
	svc := NewService(pool, hub, nil)
	publicKey := clientKey(t)
	created := createManagedHuman(t, svc, org, owner, node, "read-through", publicKey)
	pushes, unsubscribe := hub.Subscribe(node)
	defer unsubscribe()

	mode, err := svc.UpdateMode(ctx, owner, org, created.Device.ID, false)
	if err != nil {
		t.Fatalf("same-value mode: %v", err)
	}
	if mode.Device.ID != created.Device.ID || mode.Device.FullTunnel || mode.Config.Address == "" || mode.Config.Endpoint == "" {
		t.Fatalf("same-value read-through returned invalid facts: %+v", mode)
	}
	if got := auditCount(t, pool, org, "device.mode_changed"); got != 0 {
		t.Fatalf("same-value mode audits = %d, want 0", got)
	}
	select {
	case <-pushes:
		t.Fatal("same-value mode pushed the gateway")
	default:
	}
}

func TestManagedHumanKeyReplayEligibilityLeavesOtherCreatePathsUnchanged(t *testing.T) {
	base := CreateInput{PublicKey: clientKey(t)}
	tests := []struct {
		name string
		in   CreateInput
		want bool
	}{
		{name: "managed human", in: base, want: true},
		{name: "static", in: CreateInput{PublicKey: base.PublicKey, Provisioning: "static"}},
		{name: "agent", in: CreateInput{PublicKey: base.PublicKey, Kind: "agent"}},
		{name: "openvpn", in: CreateInput{PublicKey: base.PublicKey, Transport: "openvpn"}},
		{name: "bootstrap", in: CreateInput{PublicKey: base.PublicKey, BootstrapToken: "token"}},
		{name: "server generated", in: CreateInput{}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := managedHumanKeyReplayEligible(test.in); got != test.want {
				t.Fatalf("eligible = %v, want %v", got, test.want)
			}
		})
	}
}

func TestManagedHumanMalformedPublicKeyRefusesBeforeRecoveryQuery(t *testing.T) {
	// No query/pool is wired on purpose. Reaching either replay lookup would
	// panic; the deterministic validation response is the zero-query proof.
	svc := &Service{}
	_, err := svc.Create(context.Background(), CreateInput{
		Name: "desktop", PublicKey: "malformed", Provisioning: "managed",
	})
	if code(err) != "invalid_wg_key" {
		t.Fatalf("malformed managed key: want invalid_wg_key, got %v", err)
	}
}
