#!/usr/bin/env python3
"""Root-executed single normal CAS enable, on cloud13 only; no grant or probe."""
import argparse,http.cookiejar,json,os,pathlib,urllib.request,uuid
ap=argparse.ArgumentParser();ap.add_argument('--execute',action='store_true');a=ap.parse_args()
p=pathlib.Path('/home/ubuntu/tunnex-bgp-lab/normal-api');org='01a1161a-906c-7074-9e80-dd318fc2c1eb';connection='8856b1c4-ae98-418b-bfd5-664cde5210c3';vgw='9d9f98e2-cd96-456d-b020-a5a79f688040'
if not a.execute:print(json.dumps({'execute':False,'connection_id':connection,'expected_revision':1,'expected_intent':'disabled','condition':'original VGW desired disabled; root completed restart gate; no other active delivery'}));raise SystemExit
os.umask(0o077);c=json.load(open(p/'credentials.json'));b=c['base_url'];cl=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
def api(path,method='GET',body=None,headers={}):
 h={'Content-Type':'application/json','Origin':b,'X-Tunnex-CSRF':'1',**headers}
 with cl.open(urllib.request.Request(b+path,method=method,data=None if body is None else json.dumps(body).encode(),headers=h),timeout=20) as r:
  raw=r.read();return json.loads(raw) if raw else None
login=api('/api/v1/auth/login','POST',{'email':c['email'],'password':c['password']});assert not login.get('mfa_required')
root='/api/v1/organizations/'+org+'/ipsec/connections';old=api(root+'/'+connection);original=api(root+'/'+vgw)
assert old['id']==connection and old['desired_revision']==1 and old['desired_intent']=='disabled' and not old.get('deleted_at')
assert original['desired_intent']=='disabled' and not original.get('deleted_at')
proof=json.load(open(p/'tgw-disabled-provider-proof.json'));assert old['gateway_node_id']==proof['gateway_node_id'] and old['site_id']==proof['site_id']
def save(name,v):
 with open(p/name,'x') as f:json.dump(v,f);f.flush();os.fsync(f.fileno())
 fd=os.open(p,os.O_RDONLY);os.fsync(fd);os.close(fd)
save('tgw-enable-pending.json',{'connection_id':connection,'before':old,'original_vgw_before':original,'method':'PUT','if_match':'"1"','body':{'intent':'enabled'}})
# A network failure retains pending. Do not run again; resolve only exact GET outcome.
r=api(root+'/'+connection+'/intent','PUT',{'intent':'enabled'},{'If-Match':'"1"'});assert r['id']==connection and r['desired_intent']=='enabled' and r['desired_revision']==2
save('tgw-enable-result.json',r);print(json.dumps({'connection_id':connection,'desired_revision':2,'desired_intent':'enabled','grant_performed':False,'packet_probe_performed':False}))
