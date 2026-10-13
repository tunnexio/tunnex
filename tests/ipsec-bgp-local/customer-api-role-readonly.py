#!/usr/bin/env python3
"""Normal-login role qualification; GETs plus nonpersisting invalid config-check only.
No accounts, invitations, passwords, provider or policy mutations. Source-only default.
"""
import argparse,hashlib,http.cookiejar,json,os,pathlib,stat,urllib.error,urllib.request,uuid
ROLES={'owner':True,'admin':True,'member':False,'ai-view':False,'ai-admin':False}
def qualify(api,org,provider,user,expected_role,foreign_org=None):
 assert expected_role in ROLES and all(str(uuid.UUID(v))==v for v in [org,provider,user]);root='/api/v1/organizations/'+org
 code,me=api('/api/v1/auth/me');assert code==200 and me['id']==user and me['email_verified'] and not me.get('must_change_password')
 code,members=api(root+'/members');assert code==200;mine=[v for v in members if v['user_id']==user];assert len(mine)==1 and mine[0]['status']=='active';roles=mine[0].get('roles')or[mine[0]['role']];assert roles==[expected_role],'Do not infer expected authority from mixed roles'
 reads={}
 for suffix in ['', '/configuration','/status']:
  code,value=api(root+'/ipsec/connections/'+provider+suffix);assert code==200;assert 'psk'not in json.dumps(value).lower();reads[suffix or'provider']=value
 # Empty object is ALWAYS invalid; this reaches only normal authorization/validation,
 # never provider creation, lease, persistence or activation.
 code,value=api(root+'/ipsec/configuration-check','POST',{});assert code==(400 if ROLES[expected_role]else 403);management_status=code
 if foreign_org:
  assert str(uuid.UUID(foreign_org))==foreign_org and foreign_org!=org
  code,value=api('/api/v1/organizations/'+foreign_org+'/ipsec/connections/'+provider);assert code==404
 return {'passed':True,'role':expected_role,'user_id':user,'org_id':org,'provider_id':provider,'normal_login':True,'read_authority':True,'management_check_status':management_status,'foreign_org_404':bool(foreign_org),'provider_writes':False,'account_writes':False,'ui_acceptance_pending':True,'projection':reads}
def private(path):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW);s=os.fstat(fd);assert stat.S_ISREG(s.st_mode)and s.st_uid==0 and stat.S_IMODE(s.st_mode)==0o600
 with os.fdopen(fd)as f:return json.load(f)
def main():
 p=argparse.ArgumentParser();p.add_argument('--bindings',type=pathlib.Path,required=True);p.add_argument('--out',type=pathlib.Path,required=True);p.add_argument('--execute',action='store_true');a=p.parse_args()
 if not a.execute:print(json.dumps({'source_only':True,'no_account_or_provider_writes':True}));return
 assert os.getuid()==0;os.umask(0o077);b=private(a.bindings);assert b['source_sha256']==hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest();parent=a.out.parent;assert parent.stat().st_uid==0 and stat.S_IMODE(parent.stat().st_mode)==0o700 and not parent.is_symlink();assert not a.out.exists();c=private(pathlib.Path(b['credentials_path']));base=c['base_url'];client=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
 def api(path,method='GET',body=None):
  req=urllib.request.Request(base+path,data=None if body is None else json.dumps(body).encode(),method=method,headers={'Content-Type':'application/json','Origin':base,'X-Tunnex-CSRF':'1'})
  try:r=client.open(req,timeout=20)
  except urllib.error.HTTPError as e:r=e
  with r:raw=r.read(262145);assert len(raw)<=262144;return r.code,json.loads(raw)if raw else None
 code,value=api('/api/v1/auth/login','POST',{'email':c['email'],'password':c['password']});assert code==200 and not value.get('mfa_required');result=qualify(api,b['org_id'],b['provider_id'],b['user_id'],b['role'],b.get('foreign_org_id'));fd=os.open(a.out,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'w')as f:json.dump(result,f,indent=2);f.flush();os.fsync(f.fileno())
 fd=os.open(parent,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd);print(json.dumps({'output':str(a.out),'role':b['role'],'no_account_or_provider_writes':True}))
if __name__=='__main__':main()
