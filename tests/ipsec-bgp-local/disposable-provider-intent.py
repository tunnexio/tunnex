#!/usr/bin/env python3
"""Change only an independently recorded local disposable provider intent through normal authenticated API."""
import argparse,datetime,http.cookiejar,json,os,pathlib,stat,urllib.request,urllib.error
os.umask(0o077)
p=argparse.ArgumentParser();p.add_argument('--private-config',type=pathlib.Path,required=True);p.add_argument('--state',type=pathlib.Path,required=True);p.add_argument('intent',choices=['enabled','disabled']);a=p.parse_args()
r=pathlib.Path(__file__).resolve().parent/'.runtime'
c=json.loads(a.private_config.read_text());s=json.loads(a.state.read_text())
assert stat.S_IMODE(a.private_config.stat().st_mode)==0o600 and stat.S_IMODE(a.state.stat().st_mode)==0o600
assert c['base_url']=='http://127.0.0.1:18283' and c['fixture_name'] in ['BGP limit qualification','Static regression qualification']
assert s['identity']=={k:c[k] for k in ['organization_id','gateway_id','fixture_name','local_prefix','target_prefix']}
assert s['connection_id']!='4ae1e806-d6ed-4791-8137-cff6871dbd4e'
b=c['base_url'];cl=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
def api(path,method='GET',body=None,headers=None):
 req=urllib.request.Request(b+path,method=method,data=None if body is None else json.dumps(body).encode(),headers={'Content-Type':'application/json','Origin':b,'X-Tunnex-CSRF':'1',**(headers or {})})
 try:
  with cl.open(req,timeout=20)as res:return json.loads(res.read())
 except urllib.error.HTTPError as e:raise SystemExit('Normal API intent refusal HTTP'+str(e.code))
login=api('/api/v1/auth/login','POST',{'email':c['email'],'password':c['password']});assert not login.get('mfa_required')
path='/api/v1/organizations/'+c['organization_id']+'/ipsec/connections/'+s['connection_id']
old=api(path);assert old['name']==c.get('provider_connection_name',c['fixture_name']) and old['site_id']==c['site_id'] and old['gateway_node_id']==c['gateway_id'] and not old['deleted_at']
new=old if old['desired_intent']==a.intent else api(path+'/intent','PUT',{'intent':a.intent},{'If-Match':'"'+str(old['desired_revision'])+'"'})
assert new['id']==old['id'] and new['desired_intent']==a.intent
s['desired_revision']=new['desired_revision'];s['last_intent']=a.intent
a.state.with_suffix('.next').write_text(json.dumps(s,indent=2)+'\n');a.state.with_suffix('.next').replace(a.state)
proof={'time':datetime.datetime.now(datetime.timezone.utc).isoformat(),'connection_id':old['id'],'old_revision':old['desired_revision'],'new_revision':new['desired_revision'],'intent':a.intent,'normal_authenticated_api':True}
a.state.with_name(a.state.stem+'-intent-'+a.intent+'.json').write_text(json.dumps(proof,indent=2)+'\n');print(json.dumps(proof))
