package main

import (
 "context"
 "encoding/json"
 "errors"
 "fmt"
 "net/url"
 "os"
 "time"

 "github.com/google/uuid"
 "github.com/jackc/pgx/v5"
 "github.com/jackc/pgx/v5/pgxpool"
 "github.com/tunnexio/tunnex/apps/api/internal/password"
)

func main() {
 if err:=seed();err!=nil { fmt.Fprintln(os.Stderr,"Owned UI fixture refused:",err);os.Exit(1) }
}
func seed() error {
 ctx,cancel:=context.WithTimeout(context.Background(),30*time.Second);defer cancel()
 u:=url.URL{Scheme:"postgres",User:url.UserPassword("bgplocal",os.Getenv("BGPLOCAL_DB_PASSWORD")),Host:"postgres:5432",Path:"/bgplocal",RawQuery:"sslmode=disable"}
 p,err:=pgxpool.New(ctx,u.String());if err!=nil{return errors.New("database configuration invalid")};defer p.Close()
 tx,err:=p.Begin(ctx);if err!=nil{return errors.New("owned database unavailable")};defer tx.Rollback(ctx)
 var db,user string
 if err=tx.QueryRow(ctx,"select current_database(),current_user").Scan(&db,&user);err!=nil||db!="bgplocal"||user!="bgplocal" {return errors.New("unexpected database")}
 var org,node uuid.UUID;var count int
 if err=tx.QueryRow(ctx,"select id from organizations where slug='first-organization' and name='IPsec BGP local qualification'").Scan(&org);err!=nil{return errors.New("owned bootstrap organization missing")}
 if err=tx.QueryRow(ctx,"select id from nodes where org_id=$1 and name='bgp-local-gateway' and status='active' and enrolled_kind='gateway'",org).Scan(&node);err!=nil{return errors.New("owned active gateway missing")}
 if err=tx.QueryRow(ctx,"select count(*) from organizations").Scan(&count);err!=nil||count!=1{return errors.New("unexpected organization inventory")}
 // Bootstrap identities are inspected only and never modified.
 for _,fixture:=range []struct{email,role,key string}{{"bgp-owner@example.test","owner","BGPLOCAL_UI_OWNER_PASSWORD"},{"bgp-member@example.test","member","BGPLOCAL_UI_MEMBER_PASSWORD"}} {
  plain:=os.Getenv(fixture.key);if len(plain)<32{return errors.New("private fixture input missing")}
  var id uuid.UUID;var hash *string;var verified,cpAdmin,wall bool;var status string
  err=tx.QueryRow(ctx,"select id,password_hash,email_verified_at is not null,cp_admin,must_change_password,status from users where email=$1",fixture.email).Scan(&id,&hash,&verified,&cpAdmin,&wall,&status)
  if errors.Is(err,pgx.ErrNoRows) {
   id=uuid.New();h,e:=password.Hash(plain);if e!=nil{return errors.New("normal password hash failed")}
   if _,err=tx.Exec(ctx,"insert into users(id,email,name,password_hash,email_verified_at,cp_admin,must_change_password) values($1,$2,$3,$4,now(),false,false)",id,fixture.email,"BGP UI "+fixture.role,h);err!=nil{return errors.New("fixture insert failed")}
   if _,err=tx.Exec(ctx,"insert into memberships(org_id,user_id,role)values($1,$2,$3)",org,id,fixture.role);err!=nil{return errors.New("fixture membership failed")}
  } else if err!=nil||hash==nil||!verified||cpAdmin||wall||status!="active" {return errors.New("existing fixture identity differs; refusing reset")} else {
   if _,err=password.Verify(plain,*hash);err!=nil{return errors.New("existing fixture credential differs; refusing reset")}
   var role string
   if err=tx.QueryRow(ctx,"select role from memberships where org_id=$1 and user_id=$2",org,id).Scan(&role);err!=nil||role!=fixture.role{return errors.New("existing fixture role differs")}
  }
 }
 if err=tx.Commit(ctx);err!=nil{return errors.New("fixture commit failed")}
 return json.NewEncoder(os.Stdout).Encode(map[string]string{"organization_id":org.String(),"gateway_id":node.String(),"result":"owned UI owner/member ready; normal Argon2id; no CP-admin or bootstrap change"})
}
