"""Local reviewed orchestrator: real stream, one host-native sampler, one CHILD rekey.
Default source-only. No authority callback or direct PermitLease nonce claim.
Existing stream must already be running with root-pinned fixture identity.
"""
import argparse,importlib.util,pathlib,json,hashlib,os,shlex,subprocess,time
P=pathlib.Path(__file__).resolve().parent
CID='35a889a1a6b7e521084715f51a2fb6f8537b581647f8c7ebfa9b61e258df6605'
KEY='/home/ubuntu/tunnex-bgp-20261007/lab-key'
def module(name,file):
 spec=importlib.util.spec_from_file_location(name,P/file);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
wire=module('wire','customer-cloud-rekey-observe-v3.py');growth=module('growth','customer-stream-growth-observer.py')
def save(out,name,obj):growth.jsonsave(out,name,obj)
def gateway(command):
 inner=shlex.join(['ssh','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-i',KEY,'ubuntu@13.63.169.255',command])
 return ['ssh','-o','BatchMode=yes','ubuntu@16.170.207.192',inner]
def read(command):
 r=subprocess.run(gateway(command),capture_output=True,text=True,timeout=15);assert r.returncode==0 and len(r.stdout.encode())<=2097152;return r.stdout
IDENTITY="sudo -n docker inspect --format '{{.Id}} {{.Image}} {{.State.Pid}} {{.State.StartedAt}}' "+CID+"; sudo -n docker exec "+CID+" readlink /proc/1/ns/net; sudo -n docker exec "+CID+" sha256sum /proc/1/exe /state/cert.pem"
def identity(raw):
 rows=raw.splitlines();assert len(rows)==4 and rows[0].split()==[CID,'sha256:868b425d65ef30b6f0c221c834e8925079d658281e89380ead59a929021c50a2','3115397','2026-10-08T14:46:54.478240323Z']
 assert rows[1]=='net:[4026532946]' and rows[2].split()==['296065d03c4e1f6b69f27708ab9a33d09f77004817bb5f57c10d622c3f30e75c','/proc/1/exe']and rows[3].split()==['eef07a8865a43de26d8dafbc26e26327cf9d850adc3fd65112baf776d452ea8d','/state/cert.pem']
def progress(raw,owner):
 text=raw.decode();last=text.rfind('__END__')
 if last<0:return None
 value=growth.parse((text[:last+len('__END__')]+'\n').encode(),owner);rows=value['samples']
 positive=sum(b['bytes']>a['bytes'] for a,b in zip(rows,rows[1:]));assert all(r['listener_startticks']==owner['listener']['startticks']and len(r['client_ports'])==1 for r in rows)
 return value if positive>=15 else None

def main():
 ap=argparse.ArgumentParser();ap.add_argument('--pins',type=pathlib.Path,required=True);ap.add_argument('--pins-sha',required=True);ap.add_argument('--output',type=pathlib.Path,required=True);ap.add_argument('--execute',action='store_true');a=ap.parse_args()
 if not a.execute:print('{"source_only":true,"direct_permit_nonce_available":false,"cadence_claim":"actual native timestamps only"}');return
 os.umask(0o077);raw=wire.read_private(a.pins);assert wire.sha(raw)==a.pins_sha;q=json.loads(raw);wire.candidate(q)
 assert q['root_reviewed']is True and q['container']==CID and q['namespace']=='net:[4026532946]' and q['existing_stream_root_reviewed']is True
 a.output.mkdir(mode=0o700,exist_ok=False);save(a.output,'intent.json',{'pins_sha':a.pins_sha,'rekey_not_yet_attempted':True,'direct_permit_nonce_available':False})
 owner=growth.ownership(json.loads(growth.private(pathlib.Path(q['stream_run'])/'baseline.json')),json.loads(growth.private(pathlib.Path(q['stream_run'])/'stream-listener.json')))
 original=read(IDENTITY);identity(original);save(a.output,'identity-before.json',original)
 # One target SSH observation remains open for the complete 180-sample stream window.
 stream_file=(a.output/'stream-raw.txt').open('xb');stream_err=(a.output/'stream-stderr.txt').open('xb')
 stream=subprocess.Popen(growth.ssh(growth.command(owner,180)),stdout=stream_file,stderr=stream_err)
 native=None
 try:
  deadline=time.monotonic()+50;ready=None
  while time.monotonic()<deadline:
   assert stream.poll()is None,'Existing stream observation ended before rekey'
   ready=progress((a.output/'stream-raw.txt').read_bytes(),owner)
   if ready:break
   time.sleep(1)
  assert ready is not None,'15 actual same-socket progressing samples not observed';save(a.output,'stream-pre-trigger.json',ready)
  child=q['selected_child'];assert child['slot']in(1,2)and type(child['unique_id'])is int and 0<child['unique_id']<2**32
  # Exact reviewed sampler file/pins are prerequisite; no unapproved source upload.
  directory='/home/ubuntu/tunnex-bgp-lab/rekey-cycle7'
  assert q['native_source']==directory+'/customer-rekey-native-sampler-v2.py' and q['public_source']==directory+'/customer-rekey-public-status-probe-v2.py'
  assert q['native_source_sha256']=='c585537a9fdad604cc107fa2257806363d45cdb512cc224115b812db12e41531' and q['public_source_sha256']=='ff6bcb7ece05daec16f80d019f8ebbfeba501d3dc8ed9149b23eaf109eb98db4'
  for kind in ['native','public']:
   got=read('sudo -n sha256sum '+shlex.quote(q[kind+'_source'])).split()[0];assert got==q[kind+'_source_sha256']
  public=lambda:json.loads(read('sudo -n python3 '+shlex.quote(q['public_source'])+' --execute'))
  before=public();assert before['container']==CID;save(a.output,'public-before.json',before)
  assert all(x['desired_revision']==2 and x['desired_intent']=='enabled' for x in before['connections'])
  assert q['native_pins']==directory+'/native-pins.json' and q['native_output'].startswith(directory+'/native-') and pathlib.Path(q['native_output']).parent==pathlib.Path(directory)
  native_cmd=shlex.join(['sudo','-n','python3',q['native_source'],'--execute','--pins',q['native_pins'],'--pins-sha',q['native_pins_sha256'],'--output',q['native_output']])
  native_log=(a.output/'native-stdout.txt').open('xb');native_err=(a.output/'native-stderr.txt').open('xb');native=subprocess.Popen(gateway(native_cmd),stdout=native_log,stderr=native_err)
  # A genuine first native sample must exist before trigger, rather than a launch-delay assumption.
  for attempt in range(15):
   if read('if sudo -n test -f '+shlex.quote(q['native_output']+'/sample-0000.json')+'; then printf ready; else printf waiting; fi').strip()=='ready':break
   time.sleep(1)
  else:raise AssertionError('Native sampler has no first durable sample')
  vici='sudo -n docker exec -e STRONGSWAN_CONF=/run/tunnex-ipsec/strongswan.conf '+CID+' /opt/tunnex-ipsec/sbin/swanctl '
  child_raw=read(vici+'--list-sas --raw --uri unix:///run/tunnex-ipsec/charon.vici');wire.selected_child(child_raw,child);save(a.output,'child-before.json',child_raw)
  assert read(IDENTITY)==original and stream.poll()is None
  # O_EXCL durable intent precedes exactly one mutation; any uncertain outcome is not replayed.
  save(a.output,'rekey-intent.json',{'child':child,'container':CID,'namespace':q['namespace'],'at_ns':time.time_ns(),'direct_permit_nonce_available':False})
  try:
   r=subprocess.run(gateway(vici+'--rekey --child-id '+str(child['unique_id'])+' --uri unix:///run/tunnex-ipsec/charon.vici'),capture_output=True,text=True,timeout=15)
   outcome={'exit':r.returncode,'stdout':r.stdout,'stderr':r.stderr,'unknown_outcome':False}
  except subprocess.TimeoutExpired as e:outcome={'exit':None,'unknown_outcome':True,'stdout':(e.stdout or b'').decode(),'stderr':(e.stderr or b'').decode()}
  save(a.output,'rekey-outcome.json',outcome)
  public_rows=[];sample_deadline=time.monotonic()+115
  while native.poll()is None:
   assert time.monotonic()<sample_deadline,'Native sampler wall bound exceeded'
   t=time.time_ns();status=public();public_rows.append({'start_ns':t,'end_ns':time.time_ns(),'status':status});save(a.output,'public-%04d.json'%len(public_rows),public_rows[-1]);time.sleep(2)
  assert native.returncode==0;stream.wait(timeout=220);stream_file.flush();assert stream.returncode==0
  complete=growth.parse((a.output/'stream-raw.txt').read_bytes(),owner);save(a.output,'stream-complete.json',complete)
  assert read(IDENTITY)==original;save(a.output,'complete.json',{'scope':'real existing TCP observation and native overlap; acceptance pending final producer/receiver hash and actual sampled windows','one_rekey_attempt':True,'no_replay':True,'direct_permit_nonce_available':False,'no_policy_or_timer_changes':True})
 finally:
  # Terminate only local SSH observers on failure, never remote gateway/stream processes.
  for proc in [native,stream]:
   if proc is not None and proc.poll()is None:proc.terminate();proc.wait(timeout=5)
  stream_file.close();stream_err.close()
if __name__=='__main__':main()
