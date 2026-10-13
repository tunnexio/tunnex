#!/usr/bin/env python3
"""Source-only by default; normal TCP8081 /32 acceptance authority only."""
import argparse,http.cookiejar,ipaddress,json,os,pathlib,urllib.request
ORG='01a1161a-906c-7074-9e80-dd318fc2c1eb'
SITE='01a119e8-fb58-72d9-bbd2-8de0fe7bfd1e'
PROVIDER='9d9f98e2-cd96-456d-b020-a5a79f688040'
SOURCE='10.84.2.10/32'
NAME='VGW customer MTU acceptance 20261008 TCP8081 v3'
BODY={'name':NAME,'cidr':'10.85.1.10/32','protocol':'tcp','port_low':8081,'port_high':8081}
PREFIX='customer-mtu-v3-'
EXPECTED_CONFIGURATION={'configuration': {'bgp': {'local_asn': 65000, 'maximum_prefixes': 1, 'remote_asn': 64512, 'router_id': '10.84.2.1'}, 'customer_outside_address': '13.63.169.255', 'local_prefixes': ['10.84.2.0/24'], 'mode': 'ipv4-bgp', 'remote_prefixes': ['10.85.0.0/16'], 'tunnels': [{'cloud_inside_address': '169.254.16.81', 'customer_inside_address': '169.254.16.82', 'inside_cidr': '169.254.16.80/30', 'outside_address': '13.50.7.159'}, {'cloud_inside_address': '169.254.98.189', 'customer_inside_address': '169.254.98.190', 'inside_cidr': '169.254.98.188/30', 'outside_address': '51.20.220.141'}]}, 'configuration_revision': 1, 'profile_id': 'aws-bgp-ipv4-v1'}
def validate_configuration(v):
 assert v==EXPECTED_CONFIGURATION,'Configuration profile, revision or network differs from approved current VGW'
 return v
def stable(v):
 return {k:v.get(k)for k in ['id','org_id','site_id','gateway_node_id','desired_intent','desired_revision','deleted_at']}
def resource(v):
 assert all(v.get(k)==x for k,x in BODY.items()) and isinstance(v.get('id'),str)
 return v

def execute(action,api,save,load):
 root='/api/v1/organizations/'+ORG
 provider=api(root+'/ipsec/connections/'+PROVIDER)
 assert provider['id']==PROVIDER and provider['site_id']==SITE and not provider.get('deleted_at')
 assert ipaddress.ip_network(SOURCE).subnet_of(ipaddress.ip_network('10.84.2.0/24'))
 assert provider['org_id']==ORG and provider['gateway_node_id']=='01a1161a-9529-7478-b62f-a27f25222aa0' and provider['desired_revision']==2
 configuration=validate_configuration(api(root+'/ipsec/connections/'+PROVIDER+'/configuration'))
 assert api(root+'/zero-trust-mode')['mode']=='enforcing'
 before=stable(provider);rules=api(root+'/policies');resources=api(root+'/resources')
 if action=='resource':
  assert not any(v['name']==NAME for v in resources)
  save(PREFIX+'resource-pending.json',{'body':BODY,'provider':before,'configuration':configuration,'rules':rules,'resources':resources})
  made=resource(api(root+'/resources','POST',BODY));save(PREFIX+'resource-result.json',made)
 elif action=='grant':
  assert provider['desired_intent']=='enabled'
  r=resource(load(PREFIX+'resource-result.json'));actual=[v for v in resources if v['id']==r['id']];assert len(actual)==1 and resource(actual[0])==r
  assert not any(v.get('dst_resource_id')==r['id']for v in rules)
  body={'src_kind':'cidr','src_cidr':SOURCE,'dst_kind':'resource','dst_resource_id':r['id']}
  save(PREFIX+'grant-pending.json',{'body':body,'provider':before,'configuration':configuration,'rules':rules})
  g=api(root+'/policies','POST',body);assert all(g.get(k)==v for k,v in body.items()) and not g.get('src_site_id') and not g.get('src_group_id') and not g.get('src_user_id')
  save(PREFIX+'grant-result.json',g)
 elif action=='withdraw':
  r=resource(load(PREFIX+'resource-result.json'));g=load(PREFIX+'grant-result.json')
  actual=[v for v in rules if v['id']==g['id']];assert len(actual)==1 and actual[0]==g and g['src_kind']=='cidr' and g['src_cidr']==SOURCE and g['dst_resource_id']==r['id']
  save(PREFIX+'withdraw-pending.json',{'id':g['id'],'provider':before,'configuration':configuration,'rules':rules})
  api(root+'/policies/'+g['id'],'DELETE')
  assert not any(v['id']==g['id']for v in api(root+'/policies')),'Policy deletion not observed; retain pending, do not repeat mutation'
  save(PREFIX+'withdraw-result.json',{'id':g['id'],'absent':True})
 elif action=='cleanup-resource':
  r=resource(load(PREFIX+'resource-result.json'));g=load(PREFIX+'grant-result.json');withdraw=load(PREFIX+'withdraw-result.json')
  assert withdraw=={'id':g['id'],'absent':True}
  assert not any(v['id']==g['id']or v.get('dst_resource_id')==r['id']for v in rules),'Resource referenced by policy'
  actual=[v for v in resources if v['id']==r['id']];assert len(actual)==1 and resource(actual[0])==r
  save(PREFIX+'cleanup-resource-pending.json',{'resource':r,'provider':before,'configuration':configuration,'rules':rules,'resources':resources})
  # API additionally refuses live access-request and immutable template references.
  api(root+'/resources/'+r['id'],'DELETE')
  assert not any(v['id']==r['id']for v in api(root+'/resources')),'Resource deletion not observed; retain pending'
  save(PREFIX+'cleanup-resource-result.json',{'id':r['id'],'absent':True})
 else:raise AssertionError('Unsupported action')
 assert stable(api(root+'/ipsec/connections/'+PROVIDER))==before
 assert validate_configuration(api(root+'/ipsec/connections/'+PROVIDER+'/configuration'))==configuration
 after=api(root+'/policies');assert all(v in after for v in rules if action!='withdraw' or v['id']!=g['id'])
 after_resources=api(root+'/resources');assert all(v in after_resources for v in resources if action!='cleanup-resource' or v['id']!=r['id'])
 save(PREFIX+action+'-preservation.json',{'provider_unchanged':True,'configuration_unchanged':True,'foreign_rules_unchanged':True,'foreign_resources_unchanged':True,'packet_probe_performed':False})
def main():
 p=argparse.ArgumentParser();p.add_argument('action',choices=['resource','grant','withdraw','cleanup-resource']);p.add_argument('--execute',action='store_true');a=p.parse_args()
 if not a.execute:print(json.dumps({'source_only':True,'action':a.action,'resource':BODY,'source_cidr':SOURCE,'provider':PROVIDER}));return
 os.umask(0o077);directory=pathlib.Path('/home/ubuntu/tunnex-bgp-lab/normal-api');c=json.loads((directory/'credentials.json').read_text());base=c['base_url']
 client=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
 def api(path,method='GET',body=None):
  with client.open(urllib.request.Request(base+path,method=method,data=None if body is None else json.dumps(body).encode(),headers={'Content-Type':'application/json','Origin':base,'X-Tunnex-CSRF':'1'}),timeout=20)as response:
   raw=response.read();return json.loads(raw)if raw else None
 def save(name,value):
  with(directory/name).open('x')as stream:json.dump(value,stream);stream.flush();os.fsync(stream.fileno())
  fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)
 def load(name):return json.loads((directory/name).read_text())
 login=api('/api/v1/auth/login','POST',{'email':c['email'],'password':c['password']});assert not login.get('mfa_required')
 execute(a.action,api,save,load);print(json.dumps({'action':a.action,'source_cidr':SOURCE,'packet_probe_performed':False}))
if __name__=='__main__':main()
