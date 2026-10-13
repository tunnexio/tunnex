"""ROOT-only current-state native/guard/payload qualification. No lifecycle mutations. API generation acceptance is outside this checker."""
import pathlib,hashlib,json,subprocess,os,sys,time,uuid,runpy,argparse,stat,math
D=pathlib.Path('/private/tmp/provider-selected-5121-source-prep-20261012-v1/actual-measured-callbacks-v1')
ALLOCATION=D/'actual-allocation-v2.jsonl';ALLOCATION_SHA='4a054778497e4fbc9977bbd770b9dcc3a89b6ba2139ea555b12cd9f11a5111a8'
API=D/'actual-api-v1.jsonl';API_SHA='UNBOUND'
PINS={'native': ('/private/tmp/provider-selected-5121-source-prep-20261012-v1/actual-measured-callbacks-v1/read-native-fqdn-binding.bound-v1.py', '580a9d40302b941613f41cd8ba640c151e6a297e0588467951bc30f60c08a1c0'), 'cap': ('/private/tmp/provider-selected-5121-source-prep-20261012-v1/actual-measured-callbacks-v1/observer-capture/capture.bound-v1.py', '56ac6fc65f6488bd952360cec568adfeee55eed97e01c4f3ba2574dc564439f1'), 'settle': ('/private/tmp/gcp-grant-transition-readiness-20261012/v3/strict-settle-transition-v3.py', '9be9325405021779111e637fc608b1198a7ab466c0900df2e91614df5cc9e327'), 'ha': ('/private/tmp/provider-selected-5121-source-prep-20261012-v1/actual-five-model-build-v1/gcp-ha-guard-observer', '74da5ce1e67b672a0cfbac27b0e5252b417677a5910e3c44d46726851e4517b8'), 'classic': ('/private/tmp/provider-selected-5121-source-prep-20261012-v1/actual-five-model-build-v1/gcp-classic-enabled7-guard', '842afe8c144c9bd77a8154ab88784b07e35376fe7d6ceb621d5dcd6bca937323'), 'ha_dns': ('/private/tmp/provider-selected-5121-source-prep-20261012-v1/actual-five-model-build-v1/gcp-ha-dns-guard-observer', '5e086094436e6d1307952006a581073d519d267f2bb046d5c72c4d1ae8f78b03'), 'classic_dns': ('/private/tmp/provider-selected-5121-source-prep-20261012-v1/actual-five-model-build-v1/gcp-classic-dns-guard-observer', 'b09a2e1d1204b868d3c666d118d217bee63810fd3e18cead9dc81db8323aeb1c'), 'packet': ('/private/tmp/gcp-final-observers-9c3ab006-20261011/deploy/ipsec/gcp-cloud-packet-check.py', 'b459a936a7d2b1899cdda72e311a217ea60b771dd97a649291ecb63a82a8bf49')}
PINS['transition']=('/private/tmp/provider-classic-transition-build-prep-20261012-v1/actual-build-v3/gcp-classic-transition-observer','b85cd1d25d1ae63ececad5ec65843d5905d9431f55c6366cfe7ab111fc0a9ba4')
PINS['contract']=('/private/tmp/gcp-grant-transition-readiness-20261012/v3/transition_contract.py','51827d04cb7e78ec48ae4450f975ba5427930a7be8f5214c1ee525df8b2c4162')
PINS['marked']=('/private/tmp/provider-selected-5121-source-prep-20261012-v1/actual-five-model-build-v1/gcp-fqdn-marked-selected-guard-observer','f8dcc329d726bde5666f36ae8fad62681f133236436dde7d23b5d81ba935cd22')
PINS['provenance']=('/private/tmp/gcp-selected-application-acceptance-20261011/read-selected-runtime-provenance-v1.py','7f364ae71c3d2cf0d33088611035670e1aed1c2e39bf51d9ba7ffe691d32d7de')

def shared_clock():
 return time.clock_gettime(time.CLOCK_MONOTONIC)

def digest(b):return hashlib.sha256(b).hexdigest()
def checked(p,h):
 p=pathlib.Path(p);b=p.read_bytes()
 if digest(b)!=h:raise ValueError('reviewed source or receipt drift')
 return b
def checked_private(p,h):
 p=pathlib.Path(p);parent=p.parent.lstat();st=p.lstat()
 if not stat.S_ISDIR(parent.st_mode)or parent.st_uid!=os.getuid()or stat.S_IMODE(parent.st_mode)!=0o700 or not stat.S_ISREG(st.st_mode)or st.st_uid!=os.getuid()or stat.S_IMODE(st.st_mode)!=0o600 or st.st_nlink!=1 or st.st_size>2097152:raise ValueError('private confirmed receipt')
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
 with os.fdopen(fd,'rb')as f:
  held=os.fstat(f.fileno())
  if (held.st_dev,held.st_ino,held.st_mode,held.st_uid,held.st_nlink,held.st_size)!=(st.st_dev,st.st_ino,st.st_mode,st.st_uid,st.st_nlink,st.st_size):raise ValueError('private held receipt drift')
  raw=f.read(2097153);after=os.fstat(f.fileno());named=p.lstat()
  if (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns)!=(held.st_dev,held.st_ino,held.st_size,held.st_mtime_ns,held.st_ctime_ns)or (named.st_dev,named.st_ino,named.st_mode,named.st_uid,named.st_nlink,named.st_size,named.st_mtime_ns,named.st_ctime_ns)!=(after.st_dev,after.st_ino,after.st_mode,after.st_uid,after.st_nlink,after.st_size,after.st_mtime_ns,after.st_ctime_ns):raise ValueError('private receipt changed')
 if len(raw)>2097152 or digest(raw)!=h:raise ValueError('private receipt hash drift')
 return raw
def complete_native(rows):
 done=[r for r in rows if r.get('completed')is True]
 if len(done)!=1 or done[0]['observation'].get('completed')is not True:raise ValueError('native qualification refused')
 return done[0]['observation']
def run(out,phase,state_path,state_sha,selected_protocol,runner=subprocess.run,clock=shared_clock,payload=None,outer_deadline=None,transition_context=None):
 state=json.loads(checked(state_path,state_sha));ids=lambda kind:sorted(v['id']for v in state.get(kind,{}).values())
 if phase not in ('allow','deny') or selected_protocol not in ('tcp','udp'):raise ValueError('selected phase')
 if set(state.get('resources',{}))!={'tcp','udp'} or set(state.get('grants',{}))!=({selected_protocol} if phase=='allow' else set()):raise ValueError('exact selected state cardinality')
 if PINS['marked'][1]=='UNBOUND':raise ValueError('selected observer artifact UNBOUND; no transport')
 if payload is not None and (phase!='allow' or not callable(payload)):raise ValueError('allow-only callable payload')
 if outer_deadline is not None and (type(outer_deadline) not in (int,float) or not math.isfinite(outer_deadline) or outer_deadline<=clock()):raise ValueError('original outer deadline')
 if sys.flags.optimize:raise ValueError('optimized invocation refused')
 for p,h in PINS.values():checked(p,h)
 checked(ALLOCATION,ALLOCATION_SHA)
 contract=runpy.run_path(PINS['contract'][0])
 if transition_context is not None:
  contract['mutation_context'](transition_context,state,state_sha,phase,selected_protocol,checked_private)
  cm=transition_context['confirmed_monotonic'];ce=transition_context['fixture_end_monotonic']
  if type(cm)not in(int,float)or type(ce)not in(int,float)or not math.isfinite(cm)or not math.isfinite(ce)or outer_deadline!=ce or not 0<=clock()-cm<80 or clock()>=ce:raise ValueError('same original fixture mutation window')
 # This checker deliberately makes no normal API generation acceptance claim.
 out.mkdir(mode=0o700,exist_ok=False);started=clock();deadline=min(started+240,outer_deadline if outer_deadline is not None else float("inf"));counter=0;nonce=uuid.uuid4().hex
 def save(name,v):
  fd=os.open(out/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
  with os.fdopen(fd,'wb')as f:f.write((json.dumps(v,sort_keys=True)+'\n').encode());f.flush();os.fsync(f.fileno())
 def call(stage,args,budget,input=None):
  nonlocal counter
  counter+=1;stem=f'{counter:03d}-{stage}';remaining=deadline-clock()
  if remaining<=0:raise TimeoutError('aggregate qualification deadline')
  result=None;error=None
  with open_private(out/(stem+'.stdout'))as sf,open_private(out/(stem+'.stderr'))as ef:
   try:result=runner(args,input=input,stdout=sf,stderr=ef,timeout=min(budget,remaining))
   except BaseException as e:error=e
   finally:sf.flush();ef.flush();os.fsync(sf.fileno());os.fsync(ef.fileno())
  raw=(out/(stem+'.stdout')).read_bytes();save(stem+'.json',{'completed':error is None and result.returncode==0,'returncode':None if result is None else result.returncode,'error_type':None if error is None else type(error).__name__,'stdout_sha256':digest(raw),'stderr_sha256':digest((out/(stem+'.stderr')).read_bytes())})
  if error:raise error
  if clock()>=deadline:raise TimeoutError('late aggregate result')
  return result.returncode,raw
 def native(stage):
  receipt=out/(stage+'.jsonl');rc,_=call(stage,[sys.executable,PINS['native'][0],'--receipt',str(receipt),'--allocation',str(ALLOCATION),'--allocation-sha256',ALLOCATION_SHA],75)
  if rc:raise ValueError('native reader refused')
  return complete_native([json.loads(l)for l in receipt.read_bytes().splitlines()])
 def guard(stage,native_observation):
  settle=runpy.run_path(PINS['settle'][0]);attempt=0
  def capture(remaining):
   nonlocal attempt
   attempt+=1;name=f'poststart-{nonce}-{stage}-{attempt}.json';rc,_=call(stage+'-cap',[sys.executable,PINS['cap'][0],name],remaining)
   raw=(pathlib.Path('/private/tmp/provider-gcp-cloud-expiry-observer-5121dc33-actual-measured-callbacks-v1')/name).read_bytes()
   return rc,raw
  def verify(raw,end):
   # All eight existing baseline assertions consume this same capture and deadline.
   ha_proofs={}
   for profile in ('ha','ha_dns','classic','classic_dns'):
    for protocol in ('tcp','udp'):
     args=[PINS[profile][0],'-expect','allow','-protocol',protocol]
     if profile in ('ha','ha_dns'):args+=['-selected-index','6','-healthy-indices','6,7']
     elif profile=='classic_dns':args+=['-selected-index','20','-healthy-indices','20']
     remaining=end-clock()
     if remaining<=0:raise TimeoutError('full baseline guard deadline')
     rc,b=call(stage+'-'+profile+'-'+protocol,args,remaining,input=raw)
     v=json.loads(b)
     if rc or v.get('completed')is not True:
      if profile not in ('classic','classic_dns') or transition_context is None:raise ValueError('full baseline guard refusal')
      remaining=end-clock()
      if remaining<=0:raise TimeoutError('zero-authority proof deadline')
      zero_rc,zero_raw=call(stage+'-classic-transition',[PINS['transition'][0],'-expect','transition-pending','-protocol',selected_protocol],remaining,input=raw)
      if zero_rc:raise ValueError('unknown Classic refusal')
      pending=contract['pending'](raw,native_observation,contract['decode'](zero_raw),ha_proofs,phase,selected_protocol)
      raise settle['KnownPendingCapture'](pending)
     if profile in ('ha','ha_dns'):ha_proofs[profile+'_'+protocol]=v
   for profile in ('marked',):
    for protocol in (selected_protocol, 'udp' if selected_protocol=='tcp' else 'tcp'):
     args=[PINS[profile][0],'-expect',phase if protocol==selected_protocol else 'deny','-protocol',protocol,'-selected-protocol',selected_protocol]
     if profile in ('ha','ha_dns'):args+=['-selected-index','6','-healthy-indices','6,7']
     elif profile=='classic_dns':args+=['-selected-index','20','-healthy-indices','20']
     remaining=end-clock()
     if remaining<=0:raise TimeoutError('full guard verification deadline')
     rc,b=call(stage+'-'+profile+'-'+protocol,args,remaining,input=raw)
     v=json.loads(b)
     if rc or v.get('completed')is not True:raise ValueError('full production guard refusal')
  settle['settle_capture'](capture,verify,lambda v:save(stage+'-pending-'+str(attempt)+'.json',v),clock=clock,outer_deadline=deadline)
 def provenance(stage,observation):
  p=observation['journal_projection'];b=p['current_binding'];dest=out/stage
  args=[sys.executable,PINS['provenance'][0],'--phase','read','--out',str(dest),'--org','01a124e7-60c7-78ca-aa85-d3a5025d9764','--site','01a12500-95ae-7728-b901-54f20df98cc1','--node','01a125fa-32f3-762b-83d4-d368447bf6ed','--connection','b79d7eda-fafe-41cf-af2c-4115d4ef32c6','--certificate-fingerprint','f758855b91f3a60b75ee609a0c858c8db278e3fadad8a2fc233fd8df3efe0ade','--expected-started-at','2026-10-11T14:20:04.743298331Z','--delivery',p['current_delivery_id'],'--desired-revision',str(b['DesiredRevision']),'--state',str(state_path),'--state-sha256',state_sha,'--selected-protocol',selected_protocol]
  rc,raw=call(stage,args,30);v=json.loads(raw)
  if rc or v.get('completed')is not True or v.get('accepted')is not True or v.get('mutations')!=0:raise ValueError('production provenance refused')
 first=None;last=None;failure=None;after_errors=[];payload_passed=False
 try:
  first=native('native-before');guard('guard-before',first)
  if phase=='allow':provenance('provenance-before',first)
  if payload is not None:
   if clock()>=deadline:raise TimeoutError('payload original deadline')
   packet=payload();save('payload.json',packet)
   if clock()>=deadline:raise TimeoutError('late payload original deadline')
   if not isinstance(packet,dict) or packet.get('completed')is not True or packet.get('accepted')is not True or packet.get('case')!='allow':raise ValueError('payload refused')
   payload_passed=True
 except BaseException as e:failure=e
 finally:
  # Independent after observations retain separate refusal evidence, even if packets failed.
  if first is not None:
   try:last=native('native-after')
   except BaseException as e:after_errors.append({'stage':'native-after','error_type':type(e).__name__})
   try:
    guard('guard-after',last if last is not None else first)
    if phase=='allow' and last is not None:provenance('provenance-after',last)
   except BaseException as e:after_errors.append({'stage':'guard-after','error_type':type(e).__name__})
  if first is not None and last is not None and (first['identity']!=last['identity']or first['journal_projection']!=last['journal_projection']):after_errors.append({'stage':'native-continuity','error_type':'ValueError'})
 if failure is not None or after_errors:
  save('result.json',{'completed':False,'error_type':type(failure).__name__ if failure else 'AfterObservationRefused','after_errors':after_errors,'packet_bracketed':False,'scope':'bounded observations; all private partial evidence preserved'})
  if failure is not None:raise failure
  raise ValueError('independent after observation refused')
 result={'completed':True,'scope':'full native and production marked FQDN tuple observations; compiled provenance separately qualified; no active runtime64 equality; packet proof only when packet_bracketed true','source':first['identity']['source_commit'],'container':first['identity']['container_id'],'accepted':True,'native_marked_tuple_qualified':phase=='allow','compiled_provenance_qualified':phase=='allow','fqdn_authority_qualified':phase=='allow','native_runtime_hash_equality_asserted':False,'exact_policy_ids':ids('grants'),'exact_resource_ids':ids('resources'),'selected_resource_ids':[state['resources'][selected_protocol]['id']],'selected_protocol':selected_protocol,'simultaneous_pair_qualified':False,'api_generation_qualified':False,'packet_bracketed':payload_passed,'elapsed_seconds':clock()-started}
 save('result.json',result);return result

def open_private(p):return os.fdopen(os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600),'wb')
if __name__=='__main__':
 a=argparse.ArgumentParser();a.add_argument('--outer-deadline',type=float);a.add_argument('--transition-context');a.add_argument('--transition-context-sha256');a.add_argument('--evidence-dir',required=True);a.add_argument('--phase',choices=['deny','allow'],required=True);a.add_argument('--state',required=True);a.add_argument('--state-sha256',required=True);a.add_argument('--selected-protocol',choices=['tcp','udp'],required=True);args=a.parse_args()
 try:
  if bool(args.transition_context)!=bool(args.transition_context_sha256):raise ValueError('complete confirmed transition input')
  transition=json.loads(checked_private(args.transition_context,args.transition_context_sha256))if args.transition_context else None
  print(json.dumps(run(pathlib.Path(args.evidence_dir),args.phase,pathlib.Path(args.state),args.state_sha256,args.selected_protocol,outer_deadline=args.outer_deadline,transition_context=transition)))
 except BaseException as e:print(json.dumps({'completed':False,'error_type':type(e).__name__}));raise SystemExit(1)
