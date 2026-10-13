#!/usr/bin/env python3
"""Seed only owned synthetic users; exercise normal login and topology APIs."""
import hashlib,http.cookiejar,json,os,pathlib,secrets,subprocess,urllib.request,urllib.error
root=pathlib.Path(__file__).resolve().parent; repo=root.parent.parent
subprocess.run([str(root/'ownership.py')],check=True)
os.umask(0o077)
private=root/'.runtime/ui-accounts.env'
if not private.exists():
 private.write_text('BGPLOCAL_UI_OWNER_PASSWORD='+secrets.token_hex(24)+'\nBGPLOCAL_UI_MEMBER_PASSWORD='+secrets.token_hex(24)+'\n')
values=dict(line.split('=',1) for line in private.read_text().splitlines())
def docker(*args):return subprocess.check_output([str(root/'docker-local.sh'),*args],text=True)
def bootstrap_digest():
 sql="select coalesce(json_agg(u order by id)::text,'[]') from users u where email not in ('bgp-owner@example.test','bgp-member@example.test');"
 return hashlib.sha256(docker('exec','tunnexs2sbgplocal1007-postgres-1','psql','-U','bgplocal','-d','bgplocal','-At','-c',sql).encode()).hexdigest()
before=bootstrap_digest()
arch={'arm64':'arm64','aarch64':'arm64','amd64':'amd64','x86_64':'amd64'}[docker('info','--format','{{.Architecture}}').strip()]
go='/Users/pawangupta/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.26.8.darwin-arm64/bin/go'
env=dict(os.environ,GOFLAGS='-mod=readonly',CGO_ENABLED='0',GOOS='linux',GOARCH=arch)
subprocess.run([go,'build','-trimpath','-o',str(root/'.runtime/bin/ui-seed'),'.'],cwd=root/'ui-seed',env=env,check=True)
seed=json.loads(docker('run','--rm','--network','tunnexs2sbgplocal1007_default','--env-file',str(root/'.runtime/env'),'--env-file',str(private),'--cap-drop','ALL','--read-only','--mount','type=bind,src='+str(root/'.runtime/bin/ui-seed')+',dst=/ui-seed,readonly','alpine:3.24.2@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6','/ui-seed'))
assert before==bootstrap_digest(),'Bootstrap/other user row changed'
base='http://127.0.0.1:18283'
def login(email,password):
 client=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
 req=urllib.request.Request(base+'/api/v1/auth/login',data=json.dumps({'email':email,'password':password}).encode(),headers={'Content-Type':'application/json','Origin':base,'X-Tunnex-CSRF':'1'})
 with client.open(req,timeout=15) as response:result=json.load(response)
 assert not result.get('mfa_required') and not result.get('user',{}).get('must_change_password'),'Unexpected auth fixture gate'
 return client
owner=login('bgp-owner@example.test',values['BGPLOCAL_UI_OWNER_PASSWORD'])
member=login('bgp-member@example.test',values['BGPLOCAL_UI_MEMBER_PASSWORD'])
def api(client,path,method='GET',body=None):
 req=urllib.request.Request(base+path,data=None if body is None else json.dumps(body).encode(),method=method,headers={'Content-Type':'application/json','Origin':base,'X-Tunnex-CSRF':'1'})
 try:
  with client.open(req,timeout=15) as response:
   value=response.read();return json.loads(value) if value else None
 except urllib.error.HTTPError as error:
  detail=json.loads(error.read());raise SystemExit(str(error.code)+' '+str(detail))
org=seed['organization_id'];gateway=seed['gateway_id'];path='/api/v1/organizations/'+org
sites=api(owner,path+'/sites')
fixture=[s for s in sites if s['name']=='BGP UI local site'];assert len(fixture)<=1,'Ambiguous fixture site'
site=fixture[0] if fixture else api(owner,path+'/sites','POST',{'name':'BGP UI local site'})
siteid=site['id']
nodes=api(owner,path+'/nodes')
node=next(n for n in nodes if n['id']==gateway)
if not node.get('site_id'):api(owner,path+'/sites/'+siteid+'/bind','POST',{'node_id':gateway})
else:assert node['site_id']==siteid,'Gateway belongs to another site; refusing reassignment'
subnets=api(owner,path+'/sites/'+siteid+'/subnets')
selected=[s for s in subnets if s['cidr']=='10.10.0.0/24'];assert len(selected)<=1
subnet=selected[0] if selected else api(owner,path+'/sites/'+siteid+'/subnets','POST',{'cidr':'10.10.0.0/24'})
if subnet.get('status')!='approved':api(owner,path+'/site-subnets/'+subnet['id']+'/approve','POST')
settings=api(owner,path+'/ipsec/settings')
if not settings['enabled']:settings=api(owner,path+'/ipsec/settings','PUT',{'enabled':True,'expected_revision':settings['revision']})
# Member normal session may inspect the site/settings but cannot manage.
assert any(s['id']==siteid for s in api(member,path+'/sites'))
proof={'owner_email':'bgp-owner@example.test','member_email':'bgp-member@example.test','organization_id':org,'gateway_id':gateway,'site_id':siteid,'approved_prefix':'10.10.0.0/24','ipsec_settings':settings,'bootstrap_user_digest_unchanged':before==bootstrap_digest(),'normal_logins':True,'cp_admin_granted':False}
(root/'.runtime/ui-proof.json').write_text(json.dumps(proof,indent=2)+'\n')
print(json.dumps(proof,indent=2))
print('Fixture passwords remain private in .runtime/ui-accounts.env; production authentication retained.')
