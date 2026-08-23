package db_test

import (
	"context"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
)

func TestBoundedGroupMemberCountsPostgres(t *testing.T) {
	adminDSN := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if adminDSN == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL for bounded group-count PostgreSQL proof")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	admin, err := pgxpool.New(ctx, adminDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	base, err := url.Parse(adminDSN)
	if err != nil {
		t.Fatal(err)
	}
	name := "tnx_group_counts_" + uuid.NewString()[:8]
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = admin.Exec(context.Background(), "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)") })
	dsn := *base
	dsn.Path = "/" + name
	if err := db.MigrateTo(dsn.String(), 109); err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.New(ctx, dsn.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)

	q := sqlc.New(pool)
	orgA, orgB := uuid.New(), uuid.New()
	ownerA, ownerB := uuid.New(), uuid.New()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	for _, org := range []uuid.UUID{orgA, orgB} {
		exec(`INSERT INTO organizations (id,name,slug) VALUES ($1,$2,$3)`, org, "count org "+org.String()[:8], "count-org-"+org.String()[:8])
	}
	for _, row := range []struct{ id, org uuid.UUID }{{ownerA, orgA}, {ownerB, orgB}} {
		exec(`INSERT INTO users (id,email,status) VALUES ($1,$2,'active')`, row.id, row.id.String()+"@count.test")
		exec(`INSERT INTO memberships (org_id,user_id,role) VALUES ($1,$2,'owner')`, row.org, row.id)
	}

	peopleZero, peopleMany, directory := uuid.New(), uuid.New(), uuid.New()
	exec(`INSERT INTO user_groups (id,org_id,name) VALUES ($1,$2,'zero')`, peopleZero, orgA)
	exec(`INSERT INTO user_groups (id,org_id,name) VALUES ($1,$2,'many')`, peopleMany, orgA)
	exec(`INSERT INTO user_groups (id,org_id,name,origin,idp_provider,idp_group_id) VALUES ($1,$2,'directory','idp_sync','microsoft','external-count-group')`, directory, orgA)
	activeUser, secondUser, deletedUser := uuid.New(), uuid.New(), uuid.New()
	for _, id := range []uuid.UUID{activeUser, secondUser, deletedUser} {
		exec(`INSERT INTO users (id,email,status,deleted_at) VALUES ($1,$2,'active',$3)`, id, id.String()+"@count.test", nil)
		exec(`INSERT INTO memberships (org_id,user_id,role) VALUES ($1,$2,'member')`, orgA, id)
	}
	exec(`UPDATE users SET deleted_at=now() WHERE id=$1`, deletedUser)
	for _, row := range []struct {
		group, user uuid.UUID
		origin      string
	}{
		{peopleMany, activeUser, "manual"}, {peopleMany, secondUser, "manual"}, {peopleMany, deletedUser, "manual"},
		{directory, activeUser, "idp_sync"}, {directory, deletedUser, "idp_sync"},
	} {
		exec(`INSERT INTO group_members (org_id,group_id,user_id,origin) VALUES ($1,$2,$3,$4)`, orgA, row.group, row.user, row.origin)
	}
	// Same-looking data in Org B proves the aggregation cannot bleed across orgs.
	exec(`INSERT INTO user_groups (org_id,name) VALUES ($1,'many')`, orgB)

	userGroups, err := q.ListUserGroupsByOrg(ctx, orgA)
	if err != nil {
		t.Fatal(err)
	}
	gotUsers := map[uuid.UUID]int64{}
	for _, group := range userGroups {
		gotUsers[group.ID] = group.MemberCount
	}
	for id, want := range map[uuid.UUID]int64{peopleZero: 0, peopleMany: 2, directory: 1} {
		if gotUsers[id] != want {
			t.Errorf("user group %s count=%d want=%d", id, gotUsers[id], want)
		}
	}

	node, agentZero, agentOneGroup, agentMany := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	exec(`INSERT INTO nodes (id,org_id,name,cert_serial) VALUES ($1,$2,'count-node',$3)`, node, orgA, "count-node-"+node.String())
	exec(`INSERT INTO agent_groups (id,org_id,name) VALUES ($1,$2,'agent-zero'),($3,$2,'agent-one'),($4,$2,'agent-many')`, agentZero, orgA, agentOneGroup, agentMany)
	agentOne, agentTwo, deletedAgent := uuid.New(), uuid.New(), uuid.New()
	for _, id := range []uuid.UUID{agentOne, agentTwo, deletedAgent} {
		exec(`INSERT INTO devices (id,org_id,user_id,node_id,name,public_key,assigned_ip,status,kind) VALUES ($1,$2,$3,$4,$5,$6,$7,'active','agent')`, id, orgA, ownerA, node, "agent-"+id.String()[:8], "key-"+id.String(), "10.250.0."+id.String()[:1])
		exec(`INSERT INTO agent_group_members (org_id,agent_group_id,device_id,created_by_user_id) VALUES ($1,$2,$3,$4)`, orgA, agentMany, id, ownerA)
	}
	exec(`INSERT INTO agent_group_members (org_id,agent_group_id,device_id,created_by_user_id) VALUES ($1,$2,$3,$4)`, orgA, agentOneGroup, agentOne, ownerA)
	exec(`UPDATE devices SET deleted_at=now() WHERE id=$1`, deletedAgent)
	agentGroups, err := q.ListAgentGroups(ctx, orgA)
	if err != nil {
		t.Fatal(err)
	}
	gotAgents := map[uuid.UUID]int64{}
	for _, group := range agentGroups {
		gotAgents[group.ID] = group.MemberCount
	}
	if gotAgents[agentZero] != 0 || gotAgents[agentOneGroup] != 1 || gotAgents[agentMany] != 2 {
		t.Errorf("agent counts zero=%d one=%d many=%d; want 0, 1 and 2", gotAgents[agentZero], gotAgents[agentOneGroup], gotAgents[agentMany])
	}
	if len(userGroups) != 3 {
		t.Errorf("org A list leaked or lost groups: got %d want 3", len(userGroups))
	}
}
