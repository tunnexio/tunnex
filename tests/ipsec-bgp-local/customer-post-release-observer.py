#!/usr/bin/env python3
"""Read-only post-release customer worker audit. Run on owned gateway13 via16.
No release, journal writes, kernel mutations, faults or application probes.
"""
import argparse,hashlib,http.cookiejar,json,os,pathlib,re,stat,subprocess,time,urllib.request
ap=argparse.ArgumentParser();ap.add_argument('--container',required=True);ap.add_argument('--namespace',required=True);ap.add_argument('--node-sha256',required=True);ap.add_argument('--output',type=pathlib.Path,required=True);a=ap.parse_args()
assert os.geteuid()==0 and re.fullmatch('[0-9a-f]{64}',a.container) and re.fullmatch('net:\\[[0-9]+\\]',a.namespace) and re.fullmatch('[0-9a-f]{64}',a.node_sha256)
assert a.output.parent==pathlib.Path('/home/ubuntu/tunnex-bgp-lab') and a.output.name.startswith('customer-post-release-')
def run(argv):
 r=subprocess.run(argv,capture_output=True,text=True,timeout=8)
 assert r.returncode==0,(argv[:3],r.stderr[:256]);assert len(r.stdout.encode())<=1048576;return r.stdout
cid=a.container
def ex(*argv):return run(['docker','exec',cid,*argv])
def identity():
 d=json.loads(run(['docker','inspect',cid]))[0];assert d['State']['Running'] and d['Config']['Labels'].get('tunnex.lab')=='tunnex-bgp-20261007' and d['Image']=='sha256:868b425d65ef30b6f0c221c834e8925079d658281e89380ead59a929021c50a2'
 ns=ex('readlink','/proc/1/ns/net').strip();node=ex('sha256sum','/proc/1/exe').split()[0];assert ns==a.namespace and node==a.node_sha256
 return {'cid':cid,'image':d['Image'],'host_pid':d['State']['Pid'],'namespace':ns,'node_sha256':node,'startticks':ex('cat','/proc/1/stat').rsplit(')',1)[1].split()[19],'cert_sha256':ex('sha256sum','/state/cert.pem').split()[0],'api_sha256':run(['sha256sum',str(pathlib.Path(next(m['Source'] for m in d['Mounts'] if m['Destination']=='/binaries'))/'tunnex-api')]).split()[0]}
# Output reservation happens before reads; failures preserve a private attempt.
os.umask(0o077);fd=os.open(a.output,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600);result={'started':time.time(),'observer_sha256':hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),'scope':'read-only native/normal API projection, no packet gate'}
try:
 result['before']=identity();assert result['before']['cert_sha256']=='eef07a8865a43de26d8dafbc26e26327cf9d850adc3fd65112baf776d452ea8d' and result['before']['api_sha256']=='30de107bd8d56d83f18e6bd327c9beab866c16c6d455624543d5bfbe54f76c90';result['processes']=ex('ps','-eo','pid,comm');result['routes']=json.loads(ex('ip','-j','-4','route','show','table','all'));result['links']=json.loads(ex('ip','-j','-d','link','show'));result['nft']=json.loads(ex('nft','-j','list','table','inet','tunnex_ipsec'))
 result['sas']=ex('env','STRONGSWAN_CONF=/run/tunnex-ipsec/strongswan.conf','/opt/tunnex-ipsec/sbin/swanctl','--list-sas','--uri','unix:///run/tunnex-ipsec/charon.vici')
 p=pathlib.Path('/home/ubuntu/tunnex-bgp-lab/normal-api/credentials.json');st=p.lstat();assert stat.S_ISREG(st.st_mode) and st.st_uid==0 and stat.S_IMODE(st.st_mode)==0o600
 c=json.loads(p.read_text());base=c['base_url'];cl=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
 def api(path,body=None):
  req=urllib.request.Request(base+path,data=None if body is None else json.dumps(body).encode(),headers={'Content-Type':'application/json','Origin':base,'X-Tunnex-CSRF':'1'})
  with cl.open(req,timeout=10) as response:return json.loads(response.read(1048577))
 login=api('/api/v1/auth/login',{'email':c['email'],'password':c['password']});assert not login.get('mfa_required')
 root='/api/v1/organizations/01a1161a-906c-7074-9e80-dd318fc2c1eb';connection=root+'/ipsec/connections/9d9f98e2-cd96-456d-b020-a5a79f688040'
 v=api(connection);result['provider']={k:v.get(k) for k in ['id','desired_revision','desired_intent','gateway_node_id','site_id']};result['status']=api(connection+'/status');result['eligibility']=api(root+'/ipsec/eligibility?site_id=01a119e8-fb58-72d9-bbd2-8de0fe7bfd1e&gateway_node_id=01a1161a-9529-7478-b62f-a27f25222aa0')
 result['after']=identity();assert result['before']==result['after'];result['completed']=True
except BaseException as error:result['completed']=False;result['error_type']=type(error).__name__;raise
finally:
 with os.fdopen(fd,'w') as f:json.dump(result,f);f.flush();os.fsync(f.fileno())
 directory=os.open(a.output.parent,os.O_RDONLY|os.O_DIRECTORY);os.fsync(directory);os.close(directory)
print(json.dumps({'receipt':str(a.output),'completed':result['completed'],'provider':result.get('provider'),'status':result.get('status'),'eligibility':result.get('eligibility')}))
