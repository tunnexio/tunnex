#!/usr/bin/env python3
"""Normal API only; disposable disabled C01/C03/C04. Source-only default.
No enable, credential reset, DB writes, agent authority or source upload.
"""
import argparse,copy,hashlib,http.cookiejar,json,os,pathlib,stat,urllib.error,urllib.request,uuid
ORG='01a1161a-906c-7074-9e80-dd318fc2c1eb';ROOT='/api/v1/organizations/'+ORG
LIVE={'9d9f98e2-cd96-456d-b020-a5a79f688040','8856b1c4-ae98-418b-bfd5-664cde5210c3'}
def private(path):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW);s=os.fstat(fd);assert stat.S_ISREG(s.st_mode)and s.st_uid==0 and stat.S_IMODE(s.st_mode)==0o600
 with os.fdopen(fd)as f:return json.load(f)
def public_configuration(body):
 c=copy.deepcopy(body['configuration'])
 for t in c['tunnels']:t.pop('psk',None)
 return {'configuration':c,'configuration_revision':1,'profile_id':'aws-bgp-ipv4-v1'if c['mode']=='ipv4-bgp'else'aws-static-ipv4-v1'}
def binding(fixture):
 assert set(fixture)=={'body','owned_config_source_sha256','expected_org','expected_site','expected_gateway'};assert fixture['expected_org']==ORG
 body=fixture['body'];assert body['id']not in LIVE and str(uuid.UUID(body['id']))==body['id'];assert body['site_id']==fixture['expected_site']and body['gateway_node_id']==fixture['expected_gateway'];assert body['name'].startswith('Customer API disabled fixture ')
 assert len(body['tunnel_ids'])==2 and len(set([body['id'],*body['tunnel_ids']]))==3 and all(str(uuid.UUID(v))==v for v in body['tunnel_ids']);assert body['configuration']['mode']in ['ipv4-static','ipv4-bgp'];assert len(body['configuration']['tunnels'])==2
 digest=fixture['owned_config_source_sha256'];assert len(digest)==64 and all(c in '0123456789abcdef'for c in digest);return body
def stable(v):return {k:v.get(k)for k in ['id','org_id','site_id','gateway_node_id','name','desired_intent','desired_revision','deleted_at','finalized_at']}
def negatives(c):
 values=[]
 for name,edit in [('unknownmode',lambda v:v.update(mode='secret-marker')),('defaultremote',lambda v:v.update(remote_prefixes=['0.0.0.0/0'])),('badpsk',lambda v:v['tunnels'][0].update(psk='secret-marker')),('count',lambda v:v.update(tunnels=v['tunnels'][:1])),('unknownfield',lambda v:v.update(unknown='secret-marker'))]:
  v=copy.deepcopy(c);edit(v);values.append((name,v))
 if c['mode']=='ipv4-bgp':
  for key,value in [('local_asn',0),('remote_asn',0),('router_id','127.0.0.1'),('maximum_prefixes',0),('maximum_prefixes',65)]:v=copy.deepcopy(c);v['bgp'][key]=value;values.append(('bgp-'+key+'-'+str(value),v))
 return values
def execute(fixture,api,save,load,resume=False):
 body=binding(fixture);id=body['id'];path=ROOT+'/ipsec/connections/'+id;expected=public_configuration(body)
 def observe():
  code,v,headers=api(path);assert code==200 and v['id']==id and v['org_id']==ORG and v['desired_intent']=='disabled'and v['desired_revision']==1 and v['site_id']==body['site_id']and v['gateway_node_id']==body['gateway_node_id'];assert not v.get('deleted_at');code,c,_=api(path+'/configuration');assert code==200 and c==expected;return stable(v),c
 if resume:
  pending=load('create-pending.json');assert pending['body_sha256']==hashlib.sha256(json.dumps(body,sort_keys=True).encode()).hexdigest();v,c=observe();save('create-reconciled.json',{'provider':v,'configuration':c,'get_only':True});return
 code,page,_=api(ROOT+'/ipsec/connections?limit=100');assert code==200 and page.get('next_cursor')is None;assert not any(v['id']==id for v in page['items']);before={v['id']:stable(v)for v in page['items']}
 code,check,_=api(ROOT+'/ipsec/configuration-check','POST',body['configuration']);save('configuration-check.json',{'status':code,'valid':check.get('valid')});assert code==200 and check=={'valid':True}
 for name,c in negatives(body['configuration']):
  code,error,_=api(ROOT+'/ipsec/configuration-check','POST',c);save('invalid-'+name+'.json',{'status':code,'error':error});assert code==400 and 'secret-marker'not in json.dumps(error)
 code,page,_=api(ROOT+'/ipsec/connections?limit=100');assert code==200 and {v['id']:stable(v)for v in page['items']}==before
 save('create-pending.json',{'id':id,'tunnel_ids':body['tunnel_ids'],'body_sha256':hashlib.sha256(json.dumps(body,sort_keys=True).encode()).hexdigest(),'owned_config_source_sha256':fixture['owned_config_source_sha256'],'expected_disabled':True})
 code,value,headers=api(ROOT+'/ipsec/connections','POST',body);save('create-response.json',{'status':code,'body':value,'etag':headers.get('ETag')});assert code==201;v,c=observe();save('created-readback.json',{'provider':v,'configuration':c})
 # Retry ONLY the exact frozen disabled create after independently confirmed201.
 save('retry-pending.json',{'id':id,'body_sha256':hashlib.sha256(json.dumps(body,sort_keys=True).encode()).hexdigest()});code,value,_=api(ROOT+'/ipsec/connections','POST',body);save('retry-response.json',{'status':code,'body':value});assert code==409;assert observe()==(v,c)
 for label,header,wanted in [('mismatch','"2"',409),('malformed','2',400)]:
  save('cas-'+label+'-pending.json',{'id':id,'if_match':header,'intent':'disabled'});code,value,_=api(path+'/intent','PUT',{'intent':'disabled'},{'If-Match':header});save('cas-'+label+'-response.json',{'status':code,'body':value});assert code==wanted;assert observe()==(v,c)
 code,page,_=api(ROOT+'/ipsec/connections?limit=100');assert code==200 and {x['id']:stable(x)for x in page['items']if x['id']!=id}==before
 save('result.json',{'passed':True,'cases':['C01 normal disabledcreate/readback','C03 validation/redaction','C04 frozenretry/CASmismatch'],'id':id,'provider_disabled':True,'live_providers_preserved':True,'enabled_or_rotated':False,'cleanup_pending':'Root normalDELETE exactfixtureCAS1 afterreview; no implicitcleanup/replay'})
def main():
 p=argparse.ArgumentParser();p.add_argument('--fixture',type=pathlib.Path,required=True);p.add_argument('--out',type=pathlib.Path,required=True);p.add_argument('--credentials',type=pathlib.Path,default=pathlib.Path('/home/ubuntu/tunnex-bgp-lab/normal-api/credentials.json'));p.add_argument('--release',type=pathlib.Path);p.add_argument('--resume-create-get-only',action='store_true');p.add_argument('--execute',action='store_true');a=p.parse_args()
 if not a.execute:print(json.dumps({'source_only':True,'normal_api':True,'disabled_fixture_only':True,'cases':['C01','C03','C04']}));return
 assert os.getuid()==0 and a.release and private(a.release)['source_sha256']==hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest();os.umask(0o077);assert private(a.release)['fixture_sha256']==hashlib.sha256(a.fixture.read_bytes()).hexdigest();fixture=private(a.fixture);binding(fixture)
 if a.resume_create_get_only:assert a.out.is_dir()and not a.out.is_symlink()and stat.S_IMODE(a.out.stat().st_mode)==0o700
 else:assert not a.out.exists();a.out.mkdir(mode=0o700)
 def save(name,value):
  fd=os.open(a.out/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
  with os.fdopen(fd,'w')as f:json.dump(value,f,indent=2);f.flush();os.fsync(f.fileno())
  d=os.open(a.out,os.O_RDONLY|os.O_DIRECTORY);os.fsync(d);os.close(d)
 def load(name):return private(a.out/name)
 c=private(a.credentials);base=c['base_url'];client=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
 def api(path,method='GET',body=None,extra={}):
  request=urllib.request.Request(base+path,data=None if body is None else json.dumps(body).encode(),method=method,headers={'Content-Type':'application/json','Origin':base,'X-Tunnex-CSRF':'1',**extra})
  try:
   with client.open(request,timeout=25)as r:raw=r.read(262145);assert len(raw)<=262144;return r.status,json.loads(raw)if raw else None,dict(r.headers)
  except urllib.error.HTTPError as r:
   raw=r.read(262145);assert len(raw)<=262144;return r.code,json.loads(raw)if raw else None,dict(r.headers)
 code,login,_=api('/api/v1/auth/login','POST',{'email':c['email'],'password':c['password']});assert code==200 and not login.get('mfa_required');execute(fixture,api,save,load,a.resume_create_get_only);print(json.dumps({'output':str(a.out),'disabled_fixture_only':True,'private_inputs_not_printed':True}))
if __name__=='__main__':main()
