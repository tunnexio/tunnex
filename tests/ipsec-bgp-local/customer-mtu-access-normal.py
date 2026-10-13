#!/usr/bin/env python3
"""Normal VGW customer TCP8081-only resource/grant/withdraw; root executes on cloud13 after review."""
import argparse,http.cookiejar,json,os,pathlib,urllib.request,uuid
ap=argparse.ArgumentParser();ap.add_argument('action',choices=['resource','grant','withdraw']);ap.add_argument('--execute',action='store_true');a=ap.parse_args()
p=pathlib.Path('/home/ubuntu/tunnex-bgp-lab/normal-api');org='01a1161a-906c-7074-9e80-dd318fc2c1eb';site='01a119e8-fb58-72d9-bbd2-8de0fe7bfd1e';connection='9d9f98e2-cd96-456d-b020-a5a79f688040';vgw='9d9f98e2-cd96-456d-b020-a5a79f688040'
if not a.execute:print(json.dumps({'source_only':True,'action':a.action,'resource':'10.85.1.10/32 TCP8081','source_site':site,'preserve_vgw':vgw}));raise SystemExit
os.umask(0o077);c=json.load(open(p/'credentials.json'));b=c['base_url'];cl=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
def api(path,m='GET',v=None):
 with cl.open(urllib.request.Request(b+path,method=m,data=None if v is None else json.dumps(v).encode(),headers={'Content-Type':'application/json','Origin':b,'X-Tunnex-CSRF':'1'}),timeout=20) as r:
  raw=r.read();return json.loads(raw) if raw else None
def save(n,v):
 with open(p/n,'x') as f:json.dump(v,f);f.flush();os.fsync(f.fileno())
 fd=os.open(p,os.O_RDONLY);os.fsync(fd);os.close(fd)
l=api('/api/v1/auth/login','POST',{'email':c['email'],'password':c['password']});assert not l.get('mfa_required')
root='/api/v1/organizations/'+org
def stable_provider(v):
 return {k:v.get(k) for k in ['id','site_id','gateway_node_id','desired_intent','desired_revision','configuration_revision','local_prefixes','remote_prefixes','provider','deleted_at']}
before_vgw=stable_provider(api(root+'/ipsec/connections/'+vgw));before_rules=api(root+'/policies');provider=api(root+'/ipsec/connections/'+connection);assert not provider.get('deleted_at') and provider['site_id']==site
assert api(root+'/zero-trust-mode')['mode']=='enforcing'
name='VGW customer MTU acceptance 20261008 TCP8081'
if a.action=='resource':
 assert not [r for r in api(root+'/resources') if r['name']==name]
 body={'name':name,'cidr':'10.85.1.10/32','protocol':'tcp','port_low':8081,'port_high':8081};save('customer-mtu-resource-pending.json',{'body':body,'vgw':before_vgw,'rules':before_rules})
 r=api(root+'/resources','POST',body);assert r['cidr']==body['cidr'] and r['protocol']=='tcp' and r['port_low']==r['port_high']==8081;save('customer-mtu-resource-result.json',r)
elif a.action=='grant':
 assert provider['desired_intent']=='enabled'
 r=json.load(open(p/'customer-mtu-resource-result.json'));assert r['name']==name and r['cidr']=='10.85.1.10/32'
 assert not [x for x in before_rules if x.get('dst_resource_id')==r['id']]
 body={'src_kind':'site','src_site_id':site,'dst_kind':'resource','dst_resource_id':r['id']};save('customer-mtu-grant-pending.json',{'body':body,'vgw':before_vgw,'rules':before_rules})
 grant=api(root+'/policies','POST',body);assert grant['src_site_id']==site and grant['dst_resource_id']==r['id'];save('customer-mtu-grant-result.json',grant)
else:
 g=json.load(open(p/'customer-mtu-grant-result.json'));r=json.load(open(p/'customer-mtu-resource-result.json'));actual=[x for x in before_rules if x['id']==g['id']];assert len(actual)==1 and actual[0]['src_site_id']==site and actual[0]['dst_resource_id']==r['id']
 save('customer-mtu-withdraw-pending.json',{'id':g['id'],'vgw':before_vgw,'rules':before_rules});api(root+'/policies/'+g['id'],'DELETE');save('customer-mtu-withdraw-result.json',{'absent':not any(x['id']==g['id'] for x in api(root+'/policies'))})
after_vgw=stable_provider(api(root+'/ipsec/connections/'+vgw));assert after_vgw==before_vgw
after_rules=api(root+'/policies');assert all(x in after_rules for x in before_rules if a.action!='withdraw' or x['id']!=g['id'])
save('customer-mtu-'+a.action+'-preservation.json',{'vgw_unchanged':True,'foreign_rules_unchanged':True});print(json.dumps({'action':a.action,'vgw_unchanged':True,'packet_probe_performed':False}))
