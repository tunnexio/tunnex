#!/usr/bin/env python3
"""Normal SMTP-disabled NEW test identities; source-only default. Never reset users.
Unknown invitation/acceptance outcomes preserve duty; no mutating replay.
"""
import argparse,hashlib,http.cookiejar,json,os,pathlib,secrets,stat,urllib.error,urllib.request,uuid
ORG='01a1161a-906c-7074-9e80-dd318fc2c1eb';ROLES=['member','admin','ai-view']
def create(role,email,password,admin,public,new_login,save):
 assert role in ROLES and email.startswith('tunnex-customer-'+role+'-')and email.endswith('@example.test')
 def disabled():
  code,v=admin('/api/v1/admin/email-settings');assert code==200 and v['enabled']is False;return {'enabled':False,'revision':v['revision'],'source':v['source']}
 smtp=disabled();code,members=admin('/api/v1/organizations/'+ORG+'/members');assert code==200 and not any(v['email']==email for v in members);before={v['user_id']:v for v in members};save('before.json',{'smtp':smtp,'members':members})
 save('invite-pending.json',{'email':email,'role':role,'smtp_revision':smtp['revision']});assert disabled()==smtp
 code,inv=admin('/api/v1/organizations/'+ORG+'/invitations','POST',{'email':email,'role':role});save('invite-private-result.json',{'status':code,'body':inv});assert code==202 and inv.get('delivered')is False and inv.get('invite_token');assert disabled()==smtp
 save('accept-pending.json',{'email':email,'role':role,'normal_accept':True});code,value=public('/api/v1/auth/invitations/accept','POST',{'token':inv['invite_token'],'name':'Owned customer qualification '+role,'password':password});save('accept-result.json',{'status':code,'body':value});assert code==200
 code,me=new_login(email,password);assert code==200 and me['email']==email and me['email_verified']and not me.get('cp_admin')and not me.get('must_change_password')
 code,members=admin('/api/v1/organizations/'+ORG+'/members');assert code==200;mine=[v for v in members if v['email']==email];assert len(mine)==1 and mine[0]['user_id']==me['id']and mine[0]['status']=='active'and(mine[0].get('roles')or[mine[0]['role']])==[role];assert {v['user_id']:v for v in members if v['email']!=email}==before;assert disabled()==smtp
 result={'passed':True,'role':role,'user_id':me['id'],'email':email,'smtp_disabled_before_after':True,'normal_invite_accept_login':True,'cp_admin':False,'existing_members_preserved':True,'cleanup_pending':'Root normal deactivate exactNEW user after role/UI proof; private credential retained, no reset'};save('result.json',result);return result

def private(p):
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW);s=os.fstat(fd);assert s.st_uid==0 and stat.S_ISREG(s.st_mode)and stat.S_IMODE(s.st_mode)==0o600
 with os.fdopen(fd)as f:return json.load(f)
def main():
 p=argparse.ArgumentParser();p.add_argument('--role',choices=ROLES,required=True);p.add_argument('--out',type=pathlib.Path,required=True);p.add_argument('--release',type=pathlib.Path);p.add_argument('--credentials',type=pathlib.Path,default=pathlib.Path('/home/ubuntu/tunnex-bgp-lab/normal-api/credentials.json'));p.add_argument('--execute',action='store_true');a=p.parse_args()
 if not a.execute:print(json.dumps({'source_only':True,'new_identity_only':True,'smtp_must_be_disabled':True}));return
 assert os.getuid()==0 and private(a.release)=={'source_sha256':hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),'role':a.role,'org_id':ORG};os.umask(0o077);assert not a.out.exists();a.out.mkdir(mode=0o700)
 def save(name,v):
  fd=os.open(a.out/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
  with os.fdopen(fd,'w')as f:json.dump(v,f,indent=2);f.flush();os.fsync(f.fileno())
  fd=os.open(a.out,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)
 c=private(a.credentials);base=c['base_url'];assert base=='http://127.0.0.1:18383'
 def client():
  opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
  def api(path,method='GET',body=None):
   req=urllib.request.Request(base+path,data=None if body is None else json.dumps(body).encode(),method=method,headers={'Content-Type':'application/json','Origin':base,'X-Tunnex-CSRF':'1'})
   try:r=opener.open(req,timeout=25)
   except urllib.error.HTTPError as e:r=e
   with r:raw=r.read(262145);assert len(raw)<=262144;return r.code,json.loads(raw)if raw else None
  return api
 admin=client();public=client();code,v=admin('/api/v1/auth/login','POST',{'email':c['email'],'password':c['password']});assert code==200 and not v.get('mfa_required');code,me=admin('/api/v1/auth/me');assert code==200 and me['cp_admin']and me['email_verified']
 email='tunnex-customer-'+a.role+'-'+uuid.uuid4().hex+'@example.test';password='S'+secrets.token_hex(24);save('credentials-private.json',{'base_url':base,'email':email,'password':password,'org_id':ORG,'role':a.role})
 def login(email,pw):
  session=client();code,v=session('/api/v1/auth/login','POST',{'email':email,'password':pw});assert code==200 and not v.get('mfa_required');return session('/api/v1/auth/me')
 result=create(a.role,email,password,admin,public,login,save);print(json.dumps({'output':str(a.out),'role':result['role'],'user_id':result['user_id'],'passed':True,'cleanup_pending':True}))
if __name__=='__main__':main()
