"""LOCAL source-only controlled CHILD rekey driver. No source upload or policy writes.
Requires root-reviewed current worker/CHILD and read-only stream/CP probe pins.
Exactly one selected-child rekey invocation; unknown outcomes never replayed.
"""
import argparse,hashlib,json,os,pathlib,re,shlex,stat,subprocess,time
IMAGE='sha256:868b425d65ef30b6f0c221c834e8925079d658281e89380ead59a929021c50a2'
KEY='/home/ubuntu/tunnex-bgp-20261007/lab-key'
def sha(b):return hashlib.sha256(b).hexdigest()
def read_private(path):
 st=path.lstat();assert stat.S_ISREG(st.st_mode)and st.st_uid==os.getuid()and stat.S_IMODE(st.st_mode)==0o600 and not path.is_symlink();return path.read_bytes()
def parse_vici(raw):
 assert len(raw.encode())<=65536
 tokens=re.findall(r'[^\s{}]+|[{}]',raw);position=0
 # Only the exact empty command reply may follow all list-sa events.
 if tokens[-4:]==['list-sas','reply','{','}']:tokens=tokens[:-4]
 def block(depth):
  nonlocal position
  assert depth<=8
  result={}
  while position<len(tokens) and tokens[position]!='}':
   token=tokens[position];position+=1
   if '='in token:
    key,value=token.split('=',1);assert key and value and key not in result
    result[key]=value
   else:
    assert token not in result and position<len(tokens) and tokens[position]=='{'
    position+=1;result[token]=block(depth+1)
  assert position<len(tokens) and tokens[position]=='}';position+=1
  return result
 events=[]
 while position<len(tokens):
  assert tokens[position:position+3]==['list-sa','event','{'];position+=3
  event=block(0);assert len(event)==1;events.append(event)
 assert events and len(events)<=256
 return events

def selected_child(raw,p):
 parents=[]
 for event in parse_vici(raw):
  if p['name'] in event:parents.append(event[p['name']])
 assert len(parents)==1
 parent=parents[0]
 assert parent['state']=='ESTABLISHED' and parent['local-host']==p['local'] and parent['remote-host']==p['remote']
 children=parent['child-sas'];assert isinstance(children,dict) and len(children)==1
 values=next(iter(children.values()));assert isinstance(values,dict) and values['name']==p['name']
 assert all(isinstance(v,str) for v in values.values())
 assert values['uniqueid']==str(p['unique_id'])and values['reqid']==str(p['reqid'])and values['state']=='INSTALLED'
 assert values['spi-in']==p['spi_in']and values['spi-out']==p['spi_out']
 assert int(values['if-id-in'],16)==p['ifid']and int(values['if-id-out'],16)==p['ifid']
 assert values['mode']=='TUNNEL' and values['protocol']=='ESP' and values['encr-alg']=='AES_CBC' and values['encr-keysize']=='256' and values['integ-alg']=='HMAC_SHA2_256_128'
 assert values['local-ts']=='[0.0.0.0/0]'and values['remote-ts']=='[0.0.0.0/0]'
 return values

def candidate(pin):
 assert pin['node_sha256']=='296065d03c4e1f6b69f27708ab9a33d09f77004817bb5f57c10d622c3f30e75c'
 assert pin['source_sha256']=='4674c202643ef54f7239bd1c54af7fd78248b446e743da61b3ef229efc91ec1e'
 raw=read_private(pathlib.Path(pin['build_receipt_path']))
 assert sha(raw)==pin['build_receipt_sha256']=='6ac029070ad8ccf9174b9744c7291c1834798a5bebadb114b90c444cc30ab6e6'
 receipt=json.loads(raw)
 assert receipt['binary_sha256']==pin['node_sha256'] and receipt['source_snapshot_sha256']==pin['source_sha256']
 assert receipt['source_before_after_equal'] is True and receipt['unit_suites_passed'] is True
 assert receipt['prior_node_sha256']=='ede42c5e74bea33a90a97d4fa91a4bcaa530b1b7f353c3e83b74404687a79d0d'
 assert receipt['GOOS']=='linux' and receipt['GOARCH']=='amd64' and receipt['CGO_ENABLED']=='0'


def main():
 parser=argparse.ArgumentParser();parser.add_argument('--pins',type=pathlib.Path,required=True);parser.add_argument('--pins-sha',required=True);parser.add_argument('--output',type=pathlib.Path,required=True);parser.add_argument('--execute',action='store_true');a=parser.parse_args()
 if not a.execute:print('Source-only; no remote reads/rekey/socket actions');return
 os.umask(0o077);raw=read_private(a.pins);assert sha(raw)==a.pins_sha;pin=json.loads(raw)
 candidate(pin)
 assert pin['root_reviewed']and pin['read_only_probes'] and pin['current_worker_restoration_accepted']
 cid=pin['container'];ns=pin['namespace'];node=pin['node_sha256'];cert=pin['certificate_sha256'];child=pin['selected_child']
 assert re.fullmatch('[0-9a-f]{64}',cid)and re.fullmatch(r'net:\[[1-9][0-9]*\]',ns)and all(re.fullmatch('[0-9a-f]{64}',x)for x in (node,cert))
 assert cid=='35a889a1a6b7e521084715f51a2fb6f8537b581647f8c7ebfa9b61e258df6605' and ns=='net:[4026532946]'
 assert cert=='eef07a8865a43de26d8dafbc26e26327cf9d850adc3fd65112baf776d452ea8d'
 assert child['slot']in (1,2)and 0<child['unique_id']<2**32 and 0<child['reqid']<2**32 and 0<child['ifid']<2**32
 assert re.fullmatch(r'tnx-ipsec-[0-9a-f-]+-d[0-9]+-c[0-9]+-s[12]',child['name'])
 assert pin['duration_seconds']==90 and pin['target_interval_seconds']==0.2
 a.output.mkdir(mode=0o700,parents=False,exist_ok=False)
 deadline=time.monotonic()+180
 def remaining(limit):
  value=deadline-time.monotonic();assert value>0,'Hard observation wall expired';return min(limit,value)
 def save(name,obj):
  with (a.output/name).open('x')as f:json.dump(obj,f);f.flush();os.fsync(f.fileno())
  fd=os.open(a.output,os.O_DIRECTORY);os.fsync(fd);os.close(fd)
 def remote(argv):
  command=shlex.join(['sudo','-n',*argv]);inner=shlex.join(['ssh','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-i',KEY,'ubuntu@13.63.169.255',command]);start=time.time_ns()
  try:
   r=subprocess.run(['ssh','-o','BatchMode=yes','ubuntu@16.170.207.192',inner],capture_output=True,text=True,timeout=remaining(8))
   assert len(r.stdout.encode())<=1048576
   return {'started_ns':start,'finished_ns':time.time_ns(),'exit':r.returncode,'stdout':r.stdout,'stderr':r.stderr[:512]}
  except subprocess.TimeoutExpired:return {'started_ns':start,'finished_ns':time.time_ns(),'exit':None,'unknown_outcome':True}
 def ex(*argv):return remote(['docker','exec',cid,*argv])
 def check(result):assert result['exit']==0,result;return result['stdout']
 def identity():
  m=json.loads(check(remote(['docker','inspect','--format','{"Id":{{json .Id}},"Image":{{json .Image}},"State":{{json .State}},"Config":{"Labels":{{json .Config.Labels}}}}',cid])));assert m['Id']==cid and m['Image']==IMAGE and m['State']['Running']and m['Config']['Labels'].get('tunnex.lab')=='tunnex-bgp-20261007'
  assert check(ex('readlink','/proc/1/ns/net')).strip()==ns
  h=check(ex('sha256sum','/proc/1/exe','/state/cert.pem')).splitlines();assert [r.split()[0]for r in h]==[node,cert]
  assert m['State']['Pid']==3115397 and m['State']['StartedAt']=='2026-10-08T14:46:54.478240323Z'
  assert check(ex('cat','/proc/1/stat')).rsplit(')',1)[1].split()[19]=='9961117'
  return {'pid':m['State']['Pid'],'started':m['State']['StartedAt'],'namespace':ns,'hashes':[node,cert],'startticks':check(ex('cat','/proc/1/stat')).rsplit(')',1)[1].split()[19]}
 def probe(name):
  p=pin[name];path=pathlib.Path(p['source']);assert sha(path.read_bytes())==p['source_sha256'] and not path.is_symlink()
  assert p['argv'][0]in ('python3','/opt/homebrew/bin/python3')and p['argv'][1]==str(path)
  r=subprocess.run(p['argv'],capture_output=True,text=True,timeout=remaining(15));assert r.returncode==0;value=json.loads(r.stdout);assert value['read_only']and value['container']==cid and value['namespace']==ns
  return value
 def sample():
  return {'started_ns':time.time_ns(),'vici':ex('env','STRONGSWAN_CONF=/run/tunnex-ipsec/strongswan.conf','/opt/tunnex-ipsec/sbin/swanctl','--list-sas','--raw','--uri','unix:///run/tunnex-ipsec/charon.vici'),'xfrm':ex('ip','-s','xfrm','state','list','nokeys'),'nft':ex('nft','-j','list','table','inet','tunnex_ipsec'),'routes':ex('ip','-j','-4','route','show','table','all'),'cp_authority':probe('cp_probe'),'stream':probe('stream_probe'),'finished_ns':time.time_ns()}
 before=identity();save('identity-before.json',before)
 initial=sample();selected_child(check(initial['vici']),child)
 assert initial['cp_authority']['fresh_authority']and initial['stream']['same_socket']and initial['stream']['progressing_blocks']>=15
 assert initial['cp_authority']['selected_slot']==child['slot'];save('baseline.json',initial)
 assert identity()==before
 late_cp=probe('cp_probe');late_stream=probe('stream_probe');assert late_cp['fresh_authority'] and late_cp['selected_slot']==child['slot'] and late_stream['same_socket'] and late_stream['progressing_blocks']>=15
 assert all(late_cp[k]==pin['cp_binding'][k] for k in ('provider_id','delivery_id','desired_revision'))
 selected_child(check(ex('env','STRONGSWAN_CONF=/run/tunnex-ipsec/strongswan.conf','/opt/tunnex-ipsec/sbin/swanctl','--list-sas','--raw','--uri','unix:///run/tunnex-ipsec/charon.vici')),child)
 save('late-pre-trigger.json',{'cp':late_cp,'stream':late_stream,'at_ns':time.time_ns()})
 assert identity()==before
 save('rekey-intent.json',{'child':child,'container':cid,'namespace':ns,'pins_sha256':a.pins_sha,'before':before,'at_ns':time.time_ns()})
 outcome=ex('env','STRONGSWAN_CONF=/run/tunnex-ipsec/strongswan.conf','/opt/tunnex-ipsec/sbin/swanctl','--rekey','--child-id',str(child['unique_id']),'--uri','unix:///run/tunnex-ipsec/charon.vici');save('rekey-outcome.json',outcome)
 # Unknown or refused initiation remains an attempt, not a replay instruction.
 start=time.monotonic();index=0
 while time.monotonic()-start<90:
  assert identity()==before;save('sample-%04d.json'%index,sample());index+=1;time.sleep(.2)
 save('identity-after.json',identity());assert identity()==before
 save('observation-complete.json',{'samples':index,'rekey_exit':outcome['exit'],'acceptance':'pending independent exact CHILD/state/lease/socket/hash/timing reconciliation','no_replay':True,'no_policy_writes':True})
if __name__=='__main__':main()
