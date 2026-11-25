package serveraccess

import (
	"testing"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/testpostgres"
)

// SA-UX-2 S8: the caller sees only their own current access, with the latest expiry, direct or through a group.
func TestMyAccessIsTheCallersOwnCurrentAccessOnly(t *testing.T) {
	ctx, pool := testpostgres.New(t)
	svc := New(pool, nil, nil, true)
	org, me, other, gateway, server, removed, group := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	seed := func(sql string, args ...any) {
		t.Helper()
		if _, e := pool.Exec(ctx, sql, args...); e != nil {
			t.Fatal(e)
		}
	}
	seed(`INSERT INTO organizations(id,name,slug,pool_cidr) VALUES($1,'My access fixture',$2,'10.97.0.0/24')`, org, "my-access-"+org.String())
	for _, u := range []uuid.UUID{me, other} {
		seed(`INSERT INTO users(id,email,status,email_verified_at,app_auth_epoch) VALUES($1,$2,'active',now(),1)`, u, u.String()+"@example.invalid")
		seed(`INSERT INTO memberships(org_id,user_id,roles) VALUES($1,$2,ARRAY['member'])`, org, u)
	}
	seed(`INSERT INTO nodes(id,org_id,name,cert_serial,wg_public_key,endpoint,status,enrolled_kind,last_seen_at,cert_not_after) VALUES($1,$2,'gw','my-access-cert','my-access-key','gateway.invalid:51820','active','gateway',now(),now()+interval '1 hour')`, gateway, org)
	for _, s := range []uuid.UUID{server, removed} {
		seed(`INSERT INTO server_access_servers(id,org_id,gateway_id,name,private_ip,ssh_port,host_fingerprint,accounts,enabled) VALUES($1,$2,$3,$4,'10.1.2.3',2222,'SHA256:fixture',ARRAY['ubuntu','deploy','ops'],true)`, s, org, gateway, "srv-"+s.String())
	}
	seed(`UPDATE server_access_servers SET removed_at=now() WHERE id=$1`, removed)
	seed(`INSERT INTO user_groups(id,org_id,name) VALUES($1,$2,'ops')`, group, org)
	seed(`INSERT INTO group_members(org_id,group_id,user_id,origin) VALUES($1,$2,$3,'manual')`, org, group, me)
	grant := func(account string, user, grp *uuid.UUID, srv uuid.UUID, starts, expires string, enabled bool) {
		seed(`INSERT INTO server_access_grants(org_id,server_id,account,user_id,group_id,starts_at,expires_at,created_by,enabled) VALUES($1,$2,$3,$4,$5,now()+$6::interval,now()+$7::interval,$8,$9)`, org, srv, account, user, grp, starts, expires, other, enabled)
	}
	grant("ubuntu", &me, nil, server, "-1 hour", "1 hour", true)
	grant("ubuntu", &me, nil, server, "-1 hour", "3 hours", true) // latest expiry wins
	grant("ops", nil, &group, server, "-1 hour", "2 hours", true) // through a group
	grant("deploy", &other, nil, server, "-1 hour", "5 hours", true)
	grant("deploy", &me, nil, server, "-2 hours", "-1 hour", true) // expired
	grant("deploy", &me, nil, server, "1 hour", "5 hours", true)   // not started
	grant("deploy", &me, nil, server, "-1 hour", "5 hours", false) // disabled
	grant("ubuntu", &me, nil, removed, "-1 hour", "5 hours", true) // removed server
	rows, e := svc.myAccess(ctx, org, me)
	if e != nil {
		t.Fatal(e)
	}
	for _, r := range *rows {
		if r.ServerId != server {
			t.Fatalf("access on a foreign or removed server: %+v", r)
		}
	}
	if len(*rows) != 2 {
		t.Fatalf("want ubuntu and ops only, got %+v", *rows)
	}
	var ubuntu, ops bool
	for _, r := range *rows {
		var hours float64
		if e := pool.QueryRow(ctx, `SELECT extract(epoch FROM ($1::timestamptz - now()))/3600`, r.ExpiresAt).Scan(&hours); e != nil {
			t.Fatal(e)
		}
		switch r.Account {
		case "ubuntu":
			ubuntu = hours > 2.5 && hours <= 3
		case "ops":
			ops = hours > 1.5 && hours <= 2
		}
	}
	if !ubuntu || !ops {
		t.Fatalf("wrong expiries: %+v", *rows)
	}
	others, e := svc.myAccess(ctx, org, other)
	if e != nil || len(*others) != 1 || (*others)[0].Account != "deploy" {
		t.Fatalf("other user's view: %+v %v", others, e)
	}
}
