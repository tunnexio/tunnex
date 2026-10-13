#!/usr/bin/env python3
"""Read-only normal-auth entitlement and opaque persisted-key equality proof."""
import argparse,datetime,http.cookiejar,json,os,pathlib,stat,subprocess,urllib.request
os.umask(0o077)
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=pathlib.Path,required=True);a=p.parse_args()
root=pathlib.Path(__file__).resolve().parent;private=root/'.runtime/integrated-local-api.json'
assert stat.S_IMODE(private.stat().st_mode)==0o600
config=json.loads(private.read_text());base=config['base_url'].rstrip('/')
client=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
def api(path,body=None):
 request=urllib.request.Request(base+path,data=None if body is None else json.dumps(body).encode(),headers={'Content-Type':'application/json','Origin':base,'X-Tunnex-CSRF':'1'})
 with client.open(request,timeout=15) as response:return json.loads(response.read())
login=api('/api/v1/auth/login',{'email':config['email'],'password':config['password']});assert not login.get('mfa_required') and not login.get('user',{}).get('must_change_password')
license=api('/api/v1/license')
query="select json_build_object('persisted',true,'opaque_key_equality_tag',md5(value),'updated_at',updated_at) from system_settings where key='license_key';"
raw=subprocess.check_output([str(root/'docker-local.sh'),'exec','tunnexs2sbgplocal1007-postgres-1','psql','-U','bgplocal','-d','bgplocal','-At','-c',query],text=True).strip()
result={'captured_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'read_only':True,'entitlement':{k:license[k] for k in ('tier','state','features') if k in license},'persistence':json.loads(raw) if raw else {'persisted':False},'license_key_recorded':False}
a.output.write_text(json.dumps(result,indent=2)+'\n');a.output.chmod(0o600)
print(json.dumps({'tier':result['entitlement'].get('tier'),'state':result['entitlement'].get('state'),'persisted':result['persistence']['persisted'],'license_key_recorded':False}))
