#!/usr/bin/env python3
"""Source-only default. One normal disabled POST, never enable/update/delete/replay."""
import argparse,copy,hashlib,http.cookiejar,ipaddress,json,os,pathlib,stat,urllib.error,urllib.request,uuid
ORG='01a1161a-906c-7074-9e80-dd318fc2c1eb';ROOT='/api/v1/organizations/'+ORG
SITE='01a119e8-fb58-72d9-bbd2-8de0fe7bfd1e';GW='01a1161a-9529-7478-b62f-a27f25222aa0'
PINS={'vgw':('bf5d22f4-cc70-4a17-9fdb-5f81e99c773d','56d2f0657244d155b58917ed73965293571693ead322fa6b09cecde305ae521f',['3.67.173.125','52.58.98.231'],['169.254.124.0/30','169.254.124.4/30'],'10.87.1.0/24'),'tgw':('444a7390-57cc-43c1-b300-321be7ed149f','9594de54302ba27d7e4426317dc2c335d90c25275879423610c1c2b936a2b723',['3.65.241.160','63.189.108.24'],['169.254.124.8/30','169.254.124.12/30'],'10.87.2.0/24')}
def private(path):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW);s=os.fstat(fd);assert stat.S_ISREG(s.st_mode)and s.st_uid==0 and stat.S_IMODE(s.st_mode)==0o600
 with os.fdopen(fd,'rb')as f:raw=f.read(1048577)
 assert len(raw)<=1048576;return json.loads(raw),hashlib.sha256(raw).hexdigest()
def validate(body,profile,digest):
 id,sha,outside,inside,remote=PINS[profile];assert digest==sha and body['id']==id and body['site_id']==SITE and body['gateway_node_id']==GW and body['name']=='Customer static '+profile+' central owned'
 assert set(body)=={'id','name','site_id','gateway_node_id','tunnel_ids','configuration'} and len(body['tunnel_ids'])==2 and len(set([id,*body['tunnel_ids']]))==3 and all(str(uuid.UUID(x))==x for x in body['tunnel_ids'])
 c=body['configuration'];assert set(c)=={'mode','customer_outside_address','local_prefixes','remote_prefixes','tunnels'} and c['mode']=='ipv4-static'and c['customer_outside_address']=='13.63.169.255'and c['local_prefixes']==['10.84.2.0/24']and c['remote_prefixes']==[remote]and len(c['tunnels'])==2
 for i,t in enumerate(c['tunnels']):
  n=ipaddress.ip_network(inside[i]);assert set(t)=={'outside_address','inside_cidr','cloud_inside_address','customer_inside_address','psk'}and t['outside_address']==outside[i]and t['inside_cidr']==inside[i]and t['cloud_inside_address']==str(n.network_address+1)and t['customer_inside_address']==str(n.network_address+2)and isinstance(t['psk'],str)and 8<=len(t['psk'])<=64
 return body

def expected(body):
 c=copy.deepcopy(body['configuration'])
 for t in c['tunnels']:t.pop('psk')
 return {'configuration':c,'configuration_revision':1,'profile_id':'aws-static-ipv4-v1'}
def stable(v):return {k:v.get(k)for k in ['id','org_id','site_id','gateway_node_id','name','desired_intent','desired_revision','deleted_at','finalized_at']}
def flow(body,api,save,load,resume=False):
 id=body['id'];path=ROOT+'/ipsec/connections/'+id;wanted=expected(body)
 def page():
  code,v=api(ROOT+'/ipsec/connections?limit=100');assert code==200 and v.get('next_cursor')is None;return {x['id']:stable(x)for x in v['items']}
 def observe():
  code,v=api(path);assert code==200 and stable(v)=={'id':id,'org_id':ORG,'site_id':SITE,'gateway_node_id':GW,'name':body['name'],'desired_intent':'disabled','desired_revision':1,'deleted_at':None,'finalized_at':None}
  code,c=api(path+'/configuration');assert code==200 and c==wanted;code,status=api(path+'/status');assert code==200 and len(status['tunnels'])==2 and [t['id']for t in status['tunnels']]==body['tunnel_ids'] and [t['slot']for t in status['tunnels']]==[1,2] and all(t['selected']is False and t['status']in ['unknown','down']for t in status['tunnels']) and status.get('bgp')is None;return stable(v),c,status
 if resume:
  p=load('create-pending.json');assert p['id']==id and p['configuration']==wanted;v,c,s=observe();assert {k:x for k,x in page().items()if k!=id}==p['foreign']
  for x in p['foreign']:
   code,current=api(ROOT+'/ipsec/connections/'+x+'/configuration');assert code==200 and current==load('foreign-config-'+x+'.json')
  save('get-only-reconciled.json',{'passed':True,'provider':v,'configuration':c,'status':s,'get_only':True});return
 code,me=api('/api/v1/auth/me');assert code==200 and me['email_verified']and not me.get('must_change_password');code,m=api(ROOT+'/members');assert code==200;mine=[x for x in m if x['user_id']==me['id']];assert len(mine)==1 and mine[0]['status']=='active'and (mine[0].get('roles')or[mine[0]['role']])in [['owner'],['admin']]
 foreign=page();assert id not in foreign
 for x in foreign:
  code,c=api(ROOT+'/ipsec/connections/'+x+'/configuration');assert code==200;save('foreign-config-'+x+'.json',c)
 code,v=api(ROOT+'/ipsec/configuration-check','POST',body['configuration']);save('configuration-check.json',{'status':code,'valid':v.get('valid')});assert code==200 and v=={'valid':True};assert page()==foreign
 save('create-pending.json',{'id':id,'configuration':wanted,'foreign':foreign,'one_post_only':True})
 code,v=api(ROOT+'/ipsec/connections','POST',body);save('create-response.json',{'status':code,'id':v.get('id')if isinstance(v,dict)else None,'error_code':v.get('error_code')if isinstance(v,dict)else None});assert code==201
 v,c,s=observe();assert {k:x for k,x in page().items()if k!=id}==foreign
 for x in foreign:
  code,current=api(ROOT+'/ipsec/connections/'+x+'/configuration');assert code==200 and current==load('foreign-config-'+x+'.json')
 save('result.json',{'passed':True,'provider':v,'configuration':c,'status':s,'foreign_preserved':True,'normal_disabled_only':True,'enabled':False,'private_psks_printed':False})
def main():
 p=argparse.ArgumentParser();p.add_argument('--profile',choices=PINS,required=True);p.add_argument('--payload',type=pathlib.Path,required=True);p.add_argument('--credentials',type=pathlib.Path,required=True);p.add_argument('--release',type=pathlib.Path);p.add_argument('--out',type=pathlib.Path,required=True);p.add_argument('--execute',action='store_true');p.add_argument('--resume-get-only',action='store_true');a=p.parse_args()
 if not a.execute:print(json.dumps({'source_only':True,'profile':a.profile,'disabled_only':True}));return
 assert os.getuid()==0;os.umask(0o077);b,d=private(a.payload);validate(b,a.profile,d);r,_=private(a.release);assert r=={'source_sha256':hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),'profile':a.profile,'payload_sha256':d,'provider_id':b['id'],'disabled_only':True}
 parent=a.out.parent;assert not parent.is_symlink()and parent.stat().st_uid==0 and stat.S_IMODE(parent.stat().st_mode)==0o700
 if a.resume_get_only:assert a.out.is_dir()and not a.out.is_symlink()and a.out.stat().st_uid==0 and stat.S_IMODE(a.out.stat().st_mode)==0o700
 else:a.out.mkdir(mode=0o700)
 def save(name,v):
  fd=os.open(a.out/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
  with os.fdopen(fd,'w')as f:json.dump(v,f);f.flush();os.fsync(f.fileno())
  fd=os.open(a.out,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)
 def load(name):return private(a.out/name)[0]
 c,_=private(a.credentials);base=c['base_url'];assert base=='http://127.0.0.1:18383';client=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
 def api(path,method='GET',body=None):
  q=urllib.request.Request(base+path,data=None if body is None else json.dumps(body).encode(),method=method,headers={'Content-Type':'application/json','Origin':base,'X-Tunnex-CSRF':'1'})
  try:resp=client.open(q,timeout=25)
  except urllib.error.HTTPError as e:resp=e
  with resp:raw=resp.read(262145);assert len(raw)<=262144;return resp.code,json.loads(raw)if raw else None
 code,v=api('/api/v1/auth/login','POST',{'email':c['email'],'password':c['password']});assert code==200 and not v.get('mfa_required');flow(b,api,save,load,a.resume_get_only);print(json.dumps({'output':str(a.out),'provider_id':b['id'],'disabled_only':True}))
if __name__=='__main__':main()
