#!/usr/bin/env python3
"""Reviewed peer-only native observer wrapper; opt-in execution, no cloud or policy writes."""
import argparse
from datetime import datetime,timezone
import hashlib
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import uuid
s=importlib.util.spec_from_file_location('prepare',Path(__file__).with_name('prepare-max-prefix-observer.py'));p=importlib.util.module_from_spec(s);s.loader.exec_module(p)
STAGE='preflight'
ROOT=Path('/home/ubuntu/tunnex-azure-lab')
PRIVATE=ROOT/'tests/azure-s2s-local/.runtime'
SOURCE=ROOT/'reviewed-max-prefix-observer-v3-54-50f92a3f'
EXPECTED_STARTED='2026-10-10T22:33:37.620918269Z'
PROOF_SHA='d6ebe190917e77423dbb1199a5286c6d01894d9b6d2667e1e3fc4ec6771d906f'
STOP_SHA='92a80b5758cbcac11bb0c14f56787ee47eb58a1210b2c119b8304ac2196ddf79'
MACHINE='43945b1283804c5c840685c4c9082b0a'

def command(args,timeout=15):
 return subprocess.run(args,check=True,capture_output=True,timeout=timeout).stdout

def read_owned(path,owner):
 path=Path(path)
 historical={PRIVATE/'azure-genuine-reboot-proof.json':PROOF_SHA,PRIVATE/'azure-stopped-journal.json':STOP_SHA}
 parent_owner=1000 if owner==0 and path in historical else owner
 if not path.is_absolute() or path.resolve()!=path:raise ValueError('private path')
 parent=path.parent.stat()
 if parent.st_uid!=parent_owner or stat.S_IMODE(parent.st_mode)!=0o700:raise ValueError('private parent')
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  st=os.fstat(fd)
  if st.st_uid!=owner or stat.S_IMODE(st.st_mode)!=0o600 or not stat.S_ISREG(st.st_mode) or st.st_size>10485760:raise ValueError('private file')
  with os.fdopen(fd,'rb',closefd=False) as stream:raw=stream.read(10485761)
  after=os.fstat(fd)
  if len(raw)!=st.st_size or (st.st_dev,st.st_ino,st.st_size,st.st_mtime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns):raise ValueError('file changed')
  if path in historical and hashlib.sha256(raw).hexdigest()!=historical[path]:raise ValueError('historical hash')
  return raw
 finally:os.close(fd)

def save(path,raw):
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())

def identity():
 values=json.loads(command(['docker','inspect',p.CONTAINER]))
 if len(values)!=1:raise ValueError('container')
 d=values[0];state=d['State']
 if d['Id']!=p.CONTAINER or d['Name']!='/tunnex-azure-cloud-gateway' or d['Config']['Labels'].get('tunnex.owner')!='azure-s2s-01a12505' or d['Image']!='sha256:'+p.IMAGE or state['StartedAt']!=EXPECTED_STARTED or not state['Running'] or type(state['Pid'])!=int or state['Pid']<1:raise ValueError('identity')
 pid=state['Pid'];ns=os.stat('/proc/'+str(pid)+'/ns/net')
 node=command(['docker','exec','-u0',p.CONTAINER,'sha256sum','/proc/1/exe']).decode().split()[0]
 if node!=p.NODE:raise ValueError('node hash')
 proc=Path('/proc/'+str(pid)+'/stat').read_text();ticks=proc[proc.rfind(')')+1:].split()[19]
 return {'pid':pid,'started':state['StartedAt'],'ticks':ticks,'namespace_device':ns.st_dev,'namespace_inode':ns.st_ino,'node':node}

def read_normal(state,purpose):
 output=PRIVATE/('maxproof-normal-'+str(uuid.uuid4())+'.json')
 command(['sudo','-u','ubuntu','python3',str(SOURCE/'tests/azure-s2s-local/qualify-max-prefix-api.py'),'restore-read','--private-root',str(PRIVATE),'--state',str(state),'--purpose',purpose,'--output',str(output)],timeout=25)
 receipt=json.loads(read_owned(output,1000))
 # Normal API's typed receipt omits full network fields. Re-read the real immutable configuration as its owner,
 # compare the complete public configuration with saved original+purpose, and emit only a digest.
 check="""import importlib.util,json,sys,copy,hashlib
from pathlib import Path
source,state,receipt=sys.argv[1:];spec=importlib.util.spec_from_file_location('owned_max',Path(source)/'tests/azure-s2s-local/qualify-max-prefix-api.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
st=json.loads(m.secure.read(Path(state)));r=json.loads(m.secure.read(Path(receipt)));root=Path(state).parent
setup=json.loads(m.secure.read(root/'api-setup.json'))
if st['setup']!=setup:raise ValueError('saved setup changed')
accounts=json.loads(m.secure.read(root/'ui-accounts.json'))
accounts=accounts.get('accounts',list(accounts.values())) if isinstance(accounts,dict) else accounts
owners=[a for a in accounts if a.get('email')=='browser-owner@azure-s2s.local']
if len(owners)!=1:raise ValueError('owner')
c=m.api.Client();c.call('POST','/api/v1/auth/login',{'email':owners[0]['email'],'password':owners[0]['password']})
current=c.call('GET','/api/v1/organizations/'+setup['org_id']+'/ipsec/connections/'+r['normal_connection']['id']+'/configuration')
# Prior original during initial cleanup still has original limit8; target uses saved purpose.
target=st.get('target',{}).get('id')==r['normal_connection']['id']
purpose=st['purpose'] if target else ('limit' if st['purpose']=='baseline' and 'original_prior' in st else 'baseline')
expected=m.configuration(st['original_configuration'],purpose);expected.pop('profile_id')
if current['profile_id']!=m.PROFILE or current['configuration']!=expected or current['configuration_revision']!=r['normal_connection']['configuration_revision']:raise ValueError('immutable configuration changed')
print(hashlib.sha256(json.dumps(current,sort_keys=True,separators=(',',':')).encode()).hexdigest())
"""
 digest=command(['sudo','-u','ubuntu','python3','-c',check,str(SOURCE),str(state),str(output)],timeout=25).decode().strip()
 if len(digest)!=64 or any(v not in '0123456789abcdef' for v in digest):raise ValueError('configuration digest')
 receipt['immutable_configuration_sha256']=digest
 return receipt

def authority_equal(a,b):
 keys=('id','profile_id','desired_revision','configuration_revision','maximum_prefixes','remote_prefixes','desired_intent')
 return all(a['normal_connection'].get(k)==b['normal_connection'].get(k) for k in keys) and a.get('policy_count')==b.get('policy_count')==0 and (a.get('immutable_configuration_sha256') is None or a.get('immutable_configuration_sha256')==b.get('immutable_configuration_sha256'))

def extract(raw,returncode,binding):
 lines=[line[len(b'AZURE_MAX_PREFIX_NATIVE_PROOF '):] for line in raw.splitlines() if line.startswith(b'AZURE_MAX_PREFIX_NATIVE_PROOF ')]
 if returncode!=0 or b'--- SKIP:' in raw or len(lines)!=1 or b'--- PASS: TestAzureOwnedMaxPrefixNativeProof' not in raw:raise ValueError('observer result')
 value=json.loads(lines[0]);kind={'baseline':'owned_max_prefix_baseline','absence':'owned_native_cleanup_absence','post-limit':'owned_max_prefix_shutdown_observation'}[binding['mode']]
 if value.get('version')!=1 or value.get('kind')!=kind:raise ValueError('receipt kind')
 for key in ('org_id','site_id','gateway_id','connection_id','desired_revision','configuration_revision'):
  if value.get(key)!=binding[key]:raise ValueError('receipt binding')
 if not 0<=(datetime.now(timezone.utc)-p.timestamp(value['observed_at'])).total_seconds()<=60:raise ValueError('fresh observer')
 return lines[0]+b'\n'

def run(args):
 global STAGE
 if any(not __import__('re').fullmatch('[0-9a-f]{64}',v) for v in (p.CONTAINER,p.IMAGE,p.NODE)):raise ValueError('v3 identity unbound')
 if os.geteuid()!=0 or socket.gethostname()!='tunnex-peer':raise ValueError('owned peer root')
 if args.state.parent!=PRIVATE or args.normal.parent!=PRIVATE:raise ValueError('existing private input location')
 lock=os.open(PRIVATE/'maxproof-observer.lock',os.O_WRONLY|os.O_CREAT|os.O_NOFOLLOW,0o600)
 lockstat=os.fstat(lock)
 if lockstat.st_uid!=0 or stat.S_IMODE(lockstat.st_mode)!=0o600 or not stat.S_ISREG(lockstat.st_mode):raise ValueError('observer lock')
 fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
 normal=json.loads(read_owned(args.normal,1000));immutable=json.loads(read_owned(args.state,1000))
 if immutable['purpose'] not in ('limit','baseline'):raise ValueError('purpose')
 if hashlib.sha256(read_owned(args.binary,0)).hexdigest()!=p.OBSERVER:raise ValueError('binary')
 STAGE='identity_before';before=identity()
 STAGE='normal_before';fresh=read_normal(args.state,immutable['purpose'])
 if not authority_equal(normal,fresh):raise ValueError('normal changed')
 STAGE='journal_binding'
 # Full actual host journal is read, never reduced or rewritten. Python only derives selection; Go validates checksum/all history.
 rawjournal=read_owned(ROOT/'gateway-state/ipsec/journal.json',0);journal=json.loads(rawjournal)['Payload']
 n=fresh['normal_connection'];entries=[e for e in journal['Entries'] if e['Allocation']['ConnectionID']==n['id'] and e['Engines'][0]['Binding']['ConfigurationRevision']==n['configuration_revision']]
 if not entries:raise ValueError('journal target')
 entry=max(entries,key=lambda e:e['Engines'][0]['Binding']['DesiredRevision'])
 revision=entry['CleanupDesiredRevision'] if args.mode=='absence' else entry['Engines'][0]['Binding']['DesiredRevision']
 b={**{k:immutable['setup'][k] for k in ('org_id','site_id','gateway_id')},'connection_id':n['id'],'desired_revision':revision,'configuration_revision':entry['Engines'][0]['Binding']['ConfigurationRevision'],'maximum_prefixes':n['maximum_prefixes'],**{k:before[k] for k in ('namespace_device','namespace_inode')}}
 if journal['OwnerID']!=b['gateway_id'] or entry['SiteID']!=b['site_id'] or entry['Engines'][0]['Binding']['OrgID']!=b['org_id']:raise ValueError('journal ownership')
 STAGE='historical_pins';proof=PRIVATE/'azure-genuine-reboot-proof.json';stopped=PRIVATE/'azure-stopped-journal.json'
 proof_raw=read_owned(proof,0);stop_raw=read_owned(stopped,0)
 if hashlib.sha256(proof_raw).hexdigest()!=PROOF_SHA or hashlib.sha256(stop_raw).hexdigest()!=STOP_SHA:raise ValueError('historical hashes')
 historical=json.loads(proof_raw);machine=Path('/etc/machine-id').read_text().strip();boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
 if machine!=MACHINE or historical['MachineID']!=machine or historical['NewBootID']!=boot:raise ValueError('host reboot')
 b['historical_boot']={'proof_sha256':PROOF_SHA,'stopped_journal_sha256':STOP_SHA,'root_attested_host_machine_id':machine}
 attestation={'observed_at':datetime.now(timezone.utc).isoformat(),'container_id':p.CONTAINER,'image_sha256':p.IMAGE,'node_executable_sha256':p.NODE,'binding':b,'journal_cleanup_desired_revision':entry['CleanupDesiredRevision']}
 binding=p.build(fresh,attestation,immutable,args.mode,datetime.now(timezone.utc))
 if fresh.get('policy_count')!=0:raise ValueError('empty policies')
 STAGE='private_install'
 q=PRIVATE/('maxproof-window-'+str(uuid.uuid4()));q.mkdir(mode=0o700)
 file=q/'binding.json';save(file,json.dumps(binding,sort_keys=True).encode()+b'\n')
 target='/run/tunnex-qualification';helper=target+'/max-prefix-observer-a55.test'
 command(['docker','exec','-u0',p.CONTAINER,'install','-d','-m700',target])
 for source,name in ((args.binary,'max-prefix-observer-a55.test'),(file,'max-prefix-binding.json'),(proof,'historical-reboot-proof.json'),(stopped,'historical-stopped-journal.json')):
  command(['docker','cp',str(source),p.CONTAINER+':'+target+'/'+name])
 command(['docker','exec','-u0',p.CONTAINER,'chmod','600',target+'/max-prefix-binding.json',target+'/historical-reboot-proof.json',target+'/historical-stopped-journal.json'])
 command(['docker','exec','-u0',p.CONTAINER,'chmod','700',helper])
 if command(['docker','exec','-u0',p.CONTAINER,'sha256sum',helper]).decode().split()[0]!=p.OBSERVER:raise ValueError('installed binary')
 STAGE='pre_observer_bracket'
 latest=read_normal(args.state,immutable['purpose'])
 if identity()!=before or not authority_equal(fresh,latest):raise ValueError('bracket')
 if p.build(latest,attestation,immutable,args.mode,datetime.now(timezone.utc))!=binding:raise ValueError('current observer binding')
 if not 0<=(datetime.now(timezone.utc)-p.timestamp(normal['observed_at'])).total_seconds()<=60:raise ValueError('expired input')
 STAGE='observer'
 result=subprocess.run(['docker','exec','-u0','-e','TUNNEX_AZURE_MAX_PREFIX_NATIVE_PROOF=1',p.CONTAINER,helper,'-test.run=^TestAzureOwnedMaxPrefixNativeProof$','-test.count=1','-test.v','-test.timeout=30s'],capture_output=True,timeout=35)
 raw=result.stdout+result.stderr;save(q/'observer-private.log',raw)
 STAGE='post_observer_bracket'
 latest=read_normal(args.state,immutable['purpose'])
 if identity()!=before or not authority_equal(fresh,latest):raise ValueError('bracket')
 if p.build(latest,attestation,immutable,args.mode,datetime.now(timezone.utc))!=binding:raise ValueError('current observer binding')
 STAGE='receipt_extract';receipt=extract(raw,result.returncode,binding);save(q/'native-receipt.json',receipt)
 print(json.dumps({'version':1,'category':'independent_observation_written','mode':args.mode,'private_run_id':q.name,'receipt_sha256':hashlib.sha256(receipt).hexdigest()}))

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--normal',type=Path,required=True);p.add_argument('--state',type=Path,required=True);p.add_argument('--binary',type=Path,required=True);p.add_argument('--mode',choices=('baseline','absence','post-limit'),required=True);args=p.parse_args()
 os.umask(0o077)
 try:run(args)
 except (ValueError,KeyError,TypeError,OSError,subprocess.SubprocessError):print(json.dumps({'version':1,'category':'observer_wrapper_refused','stage':STAGE}));raise SystemExit(1)
if __name__=='__main__':main()
