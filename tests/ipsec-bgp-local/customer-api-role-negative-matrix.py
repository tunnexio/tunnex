#!/usr/bin/env python3
"""Source-only default. Synthetic normal-login role/absent-tenant denial matrix.
Never directs a write at live provider IDs or submits a valid create body.
"""
import argparse,hashlib,http.cookiejar,json,os,pathlib,stat,time,urllib.request,urllib.error
ORG='01a1161a-906c-7074-9e80-dd318fc2c1eb'
LIVE=['9d9f98e2-cd96-456d-b020-a5a79f688040','8856b1c4-ae98-418b-bfd5-664cde5210c3']
ABSENT='00000000-0000-4000-8000-000000000991';FOREIGN='00000000-0000-4000-8000-000000000992'
PRINCIPALS={'member':'01a11bdb-ee3f-7926-81b1-6251ea05090b','admin':'01a11bdb-f118-7161-999c-c58a71594adc','ai-view':'01a11bdb-f3c5-7d74-bf5b-6e3f27f2e0bd'}
CREDROOT=pathlib.Path('/home/ubuntu/tunnex-bgp-lab/customer-normal-principals-20261008-1')
def cases(role):
 root='/api/v1/organizations/'+(FOREIGN if role=='admin'else ORG)+'/ipsec'
 expected=404 if role=='admin'else 403
 return [(name,method,root+suffix,{} if method!='DELETE'else None,expected)for name,method,suffix in [('create','POST','/connections'),('configuration-check','POST','/configuration-check'),('enable-invalid','PUT','/connections/'+ABSENT+'/intent'),('rotate-invalid','POST','/connections/'+ABSENT+'/rotate-psks'),('delete-future-cas','DELETE','/connections/'+ABSENT)]]
def safe_request(path,method,body):
 if method in ['GET','HEAD']:return path.startswith('/api/v1/')
 if path=='/api/v1/auth/login':return method=='POST'
 return any((method,path,body)==(m,p,b)for role in PRINCIPALS for _,m,p,b,_ in cases(role))
def private(p):
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW);s=os.fstat(fd);assert stat.S_ISREG(s.st_mode)and s.st_uid==0 and stat.S_IMODE(s.st_mode)==0o600 and s.st_size<=65536
 with os.fdopen(fd)as f:return json.load(f)
def digest(value):return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()
def baseline(api):
 root='/api/v1/organizations/'+ORG;rows={}
 for provider in LIVE:
  for suffix in ['', '/configuration']:
   code,value=api(root+'/ipsec/connections/'+provider+suffix);assert code==200
   if not suffix:
    value={k:value[k]for k in ['id','org_id','site_id','gateway_node_id','name','profile_id','desired_intent','desired_revision','configuration_revision']if k in value}
    assert value['id']==provider and value['desired_intent']=='enabled'and value['desired_revision']==2
   rows[provider+suffix]=digest(value)
 for suffix in ['/resources','/policies','/sites','/members','/nodes','/ipsec/settings']:
  code,value=api(root+suffix);assert code==200
  if suffix=='/nodes':
   assert isinstance(value,list);value=[{k:r[k]for k in ['id','org_id','site_id','name','kind','revoked_at','disabled_at']if k in r}for r in value]
  rows[suffix]=digest(value)
 return rows

def main():
 ap=argparse.ArgumentParser();ap.add_argument('--release',type=pathlib.Path);ap.add_argument('--output',type=pathlib.Path);ap.add_argument('--execute',action='store_true');a=ap.parse_args()
 if not a.execute:print(json.dumps({'source_only':True,'negative_cases':15,'live_provider_write_targets':False,'real_other_tenant_claim':False}));return
 assert os.getuid()==0 and a.release and a.output;os.umask(0o077);release=private(a.release);assert release['root_reviewed']is True and release['source_sha256']==hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest()and release['org_id']==ORG
 parent=a.output.parent;assert not parent.is_symlink()and parent.stat().st_uid==0 and stat.S_IMODE(parent.stat().st_mode)==0o700
 fd=os.open(a.output,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600);report={'scope':'normal role authorization before malformed input and nonexistent-org isolation','cases':[],'started_at':time.time(),'live_provider_mutations':False,'account_mutations':False,'real_foreign_tenant_tested':False};deadline=time.monotonic()+180
 def persist():
  os.lseek(fd,0,os.SEEK_SET);os.ftruncate(fd,0);os.write(fd,json.dumps(report,indent=2).encode());os.fsync(fd)
 def client(role):
  c=private(CREDROOT/role/'credentials-private.json');assert c['org_id']==ORG and c['role']==role and c['base_url']=='http://127.0.0.1:18383'
  opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
  def api(path,method='GET',body=None):
   assert time.monotonic()<deadline and safe_request(path,method,body)
   req=urllib.request.Request(c['base_url']+path,data=None if body is None else json.dumps(body).encode(),method=method,headers={'Content-Type':'application/json','Origin':c['base_url'],'X-Tunnex-CSRF':'1','If-Match':'"9223372036854775806"'})
   try:r=opener.open(req,timeout=10)
   except urllib.error.HTTPError as e:r=e
   with r:raw=r.read(1048577);assert len(raw)<=1048576;return r.code,json.loads(raw)if raw else None
  code,value=api('/api/v1/auth/login','POST',{'email':c['email'],'password':c['password']});assert code==200 and not value.get('mfa_required')
  code,me=api('/api/v1/auth/me');assert code==200 and me['id']==PRINCIPALS[role]and me['email_verified']and not me.get('cp_admin',False)
  code,members=api('/api/v1/organizations/'+ORG+'/members');assert code==200;mine=[m for m in members if m['user_id']==PRINCIPALS[role]];assert len(mine)==1 and mine[0]['role']==role and mine[0]['status']=='active'
  return api
 admin=None
 try:
  admin=client('admin');report['before']=baseline(admin);persist()
  # Prove both deliberately impossible UUIDs have no normally readable objects.
  for path in ['/api/v1/organizations/'+ORG+'/ipsec/connections/'+ABSENT,'/api/v1/organizations/'+FOREIGN+'/ipsec/connections/'+LIVE[0]]:
   code,_=admin(path);assert code==404
  for role in ['member','ai-view','admin']:
   api=admin if role=='admin'else client(role)
   for name,method,path,body,expected in cases(role):
    code,_=api(path,method,body);report['cases'].append({'role':role,'name':name,'method':method,'path':path,'status':code,'expected':expected});persist();assert code==expected
  report['passed']=True
 except Exception as e:report['passed']=False;report['error_type']=type(e).__name__
 finally:
  try:
   if admin:report['after']=baseline(admin);report['baseline_unchanged']=report.get('before')==report['after'];assert report['baseline_unchanged']
  except Exception as e:report['passed']=False;report['preservation_error_type']=type(e).__name__
  persist();os.close(fd);d=os.open(parent,os.O_DIRECTORY);os.fsync(d);os.close(d)
 print(json.dumps({'output':str(a.output),'passed':report.get('passed',False),'no_secrets_logged':True}));assert report.get('passed')is True
if __name__=='__main__':main()
