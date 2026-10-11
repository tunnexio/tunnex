"""ROOT-only concrete FQDN application composition; actual ec diagnostic source/unchanged API ACK/guard bindings are frozen.
No I/O on import. Two owned resource histories are retained, never described as disabled.
"""
import argparse,hashlib,json,os,pathlib,stat,subprocess,sys,time,types
D=pathlib.Path('/private/tmp/gcp-fqdn-only-acceptance-prep-20261011')
PINS={
 'api':('/private/tmp/gcp-selected-application-acceptance-20261011/provider-api-selected-v1.py', 'f73dec6c5c1608253a735b7dbfcb694ff3208ae9a28fa635b38ba1026bac234b'),
 'core':('/private/tmp/gcp-selected-application-acceptance-20261011/provider-core-selected-v1.py', '002d735bcc94fa7a69f5369646865590e8ced43b348dc95263b218c885e67928'),
 'holder':('/private/tmp/gcp-selected-application-acceptance-20261011/ui-selected-target-holder-v2.py', '1f6623bed1069913a18b6d399efc26a798c0d7642fd6f04af917664b8482a063'),
 'packet':('/private/tmp/gcp-selected-application-acceptance-20261011/ui-run-selected-lan-packet-v1.py', '7ea5efc57f74180eda3cba730001cc7cc7c01e41c2d406ef8de2305a69cb5c77'),
 'firewall':('run-fqdn-app-firewall-phase-v5.py','cf1d0664d1a24cd3f3707e39ef4ebe4af3c9ff8fccbb985720b71cb7a0bbbe0b')}
# ROOT supplies a NEW immutable derivative after actual serving identity + ACK.
ACK_PATH='/private/tmp/provider-ack-second-observation-diagnostic-v8-20261011/root-read-owned-api-ack-v8-bound-v1.py';ACK_SHA='127a22db0d7d1a1c9a3e850bdb4af50f6ce8f13428faab716ca2d1cdacd88dc2';ACK_STARTED='2026-10-11T14:20:04.743298331Z'
GUARD_PATH='/private/tmp/gcp-udp-sa-diagnostic-v9-20261012/check-selected-transition-v9.py';GUARD_SHA='8ceec04d1ef85f655682ea54f7a6d10643f45dd0bb4212a4d928cc84d078d745'
ORG='01a124e7-60c7-78ca-aa85-d3a5025d9764';NODE='01a125fa-32f3-762b-83d4-d368447bf6ed'
CERT='f758855b91f3a60b75ee609a0c858c8db278e3fadad8a2fc233fd8df3efe0ade'
def shared_clock():
 return time.clock_gettime(time.CLOCK_MONOTONIC)

def checked(path,digest):
 raw=path.read_bytes()
 if hashlib.sha256(raw).hexdigest()!=digest:raise ValueError('exact reviewed source')
 return raw

def load(name):
 path,digest=PINS[name];p=D/path;raw=checked(p,digest);m=types.ModuleType(name);m.__file__=str(p);exec(compile(raw,str(p),'exec'),m.__dict__);return m

def write(path,value):
 with os.fdopen(os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600),'w')as f:
  json.dump(value,f);f.write('\n');f.flush();os.fsync(f.fileno())

def read(path):
 raw=path.read_bytes()
 if len(raw)>2097152:raise ValueError('bounded public receipt')
 return json.loads(raw)

class Callbacks:
 def __init__(self,out,baseline,cookie,selected_protocol,state,state_path):
  if selected_protocol not in ('tcp','udp'):raise ValueError('selected protocol')
  self.selected_protocol=selected_protocol;self.retained_resource_ids=sorted(r['id']for r in state['resources'].values())
  self.out=out;self.baseline_path=baseline;self.cookie=cookie;self.counter=0;self.state=state;self.state_path=state_path;self.unknown_api=False;self.unknown_owned=[];self.fw_result=None;self.fw_unknown=False;self.listener=None;self.allow_observed=False;self.nonce=os.urandom(16).hex();self.end=shared_clock()+80;self.cleanup=False;self.read_until=None;self.application_until=None;self.confirmed_transition=None
 def path(self,label):
  self.counter+=1;return self.out/('%03d-%s'%(self.counter,label))
 def command(self,argv,phase,timeout=30):
  root=self.path(phase);root.mkdir(mode=0o700);receipt={'completed':False,'phase':phase,'replay_forbidden':True}
  limit=timeout if self.cleanup else min(timeout,self.end-shared_clock())
  if self.read_until is not None:limit=min(limit,self.read_until-shared_clock())
  if limit<=0:raise TimeoutError('fixture deadline')
  try:
   with open(root/'stdout','xb')as sf,open(root/'stderr','xb')as ef:
    os.chmod(sf.name,0o600);os.chmod(ef.name,0o600)
    try:
     rc=subprocess.run(argv,stdout=sf,stderr=ef,timeout=limit).returncode
     receipt['returncode']=rc
    finally:
     sf.flush();ef.flush();os.fsync(sf.fileno());os.fsync(ef.fileno())
   if rc:raise ValueError('leaf refused')
   receipt['completed']=True
   return root
  except BaseException as e:receipt['error_type']=type(e).__name__;raise
  finally:write(root/'invocation.json',receipt)
 def api(self,phase,protocol=None,min_fresh_seconds=None):
  if self.unknown_api:raise ValueError('unknown API mutation retained; no replay')
  root=self.path('api-'+phase);argv=[sys.executable,str(D/PINS['api'][0]),'--phase',phase,'--baseline',self.baseline_path,'--cookie-file',self.cookie,'--out',str(root),'--selected-protocol',self.selected_protocol]
  if self.state_path:argv+=['--state',str(self.state_path),'--state-sha256',hashlib.sha256(self.state_path.read_bytes()).hexdigest()]
  if min_fresh_seconds is not None:argv+=['--min-fresh-seconds',str(min_fresh_seconds)]
  mutation=phase in ('create-resource','create-grant','delete-grant')
  if mutation:argv+=['--apply','--protocol',protocol]
  try:
   self.command(argv,'api-command-'+phase,timeout=90);result=read(root/'result.json')
   if result.get('completed')is not True or result.get('baseline_preserved')is not True:raise ValueError('whole API state rejected')
   self.state_path=root/'state.json';self.state=read(self.state_path)
   if phase in ('create-grant','delete-grant'):
    if result.get('mutation_attempted')is not True or type(result.get('mutations'))is not int or result['mutations']!=1:raise ValueError('owned confirmed transition')
    response=read(root/'mutation-response.json');attempt=read(root/'attempted.json')
    gid=self.state['grants'][protocol]['id']if phase=='create-grant'else attempt['path'].split('/')[-1]
    context={'phase':phase,'protocol':protocol,'grant_id':gid,'state_sha256':hashlib.sha256(self.state_path.read_bytes()).hexdigest(),'confirmed_monotonic':shared_clock(),'fixture_end_monotonic':self.end}
    for name,file in (('result','result.json'),('attempt','attempted.json'),('response','mutation-response.json')):
     path=root/file;context[name+'_path']=str(path);context[name+'_sha256']=hashlib.sha256(path.read_bytes()).hexdigest()
    self.confirmed_transition=context
   return result
  except BaseException:
   if mutation and (root/'attempted.json').exists():
    self.unknown_api=True
    # Preserve exact returned public ID if available; never adopt incomplete state.
    if (root/'mutation-response.json').exists():
     response=read(root/'mutation-response.json');body=response.get('body')
     if isinstance(body,dict)and isinstance(body.get('id'),str):self.unknown_owned.append({'phase':phase,'protocol':protocol,'id':body['id']})
   raise
 def baseline(self):
  self.api('verify');self.fresh_generation();self.firewall('prepare')
 def ack_once(self):
  self.api('verify');root=self.path('ack');root.mkdir(mode=0o700)
  self.command([sys.executable,ACK_PATH,'--phase','read','--out',str(root/'read'),'--org',ORG,'--node',NODE,'--certificate-fingerprint',CERT,'--expected-started-at',ACK_STARTED],'ack-command')
  v=read(root/'read'/'result.json')
  if v.get('mutations')!=0:raise ValueError('read-only ACK observation required')
  if v.get('completed')is True and v.get('accepted')is True:return 'accepted'
  if v.get('completed')is False and v.get('accepted')is False and v.get('pending')is True and v.get('reason_code')=='known_fresh_policy_hash_convergence' and v.get('source_brackets_verified')is True:return 'pending'
  raise ValueError('unqualified ACK refusal')
 def wait_read(self,reader,budget,absolute_until=None):
  until=min(self.end,shared_clock()+budget,absolute_until if absolute_until is not None else float("inf"))
  if shared_clock()>=until:raise TimeoutError("qualification read bound before transport")
  self.read_until=until
  try:
   while True:
    status=reader();now=shared_clock()
    if now>=until:raise TimeoutError('qualification read bound')
    if status=='accepted':return
    if status!='pending':raise ValueError('unknown qualification state')
    time.sleep(min(.2,until-now))
  finally:self.read_until=None
 def ack(self):self.wait_read(self.ack_once,5)
 def firewall(self,phase):
  receipt=self.path('firewall-'+phase).with_suffix('.jsonl');argv=[sys.executable,str(D/PINS['firewall'][0]),'--phase',phase,'--receipt',str(receipt)]
  if phase in ('create','delete'):argv+=['--apply','--exclusive-root-writer']
  if phase=='delete':argv+=['--predecessor-remote-result',self.fw_result]
  try:
   self.command(argv,'firewall-command-'+phase,timeout=135);rows=[json.loads(line)for line in receipt.read_text().splitlines()];v=rows[-1]
   if v.get('completed')is not True or v.get('observation',{}).get('completed')is not True:raise ValueError('exact firewall outcome')
   if phase=='create':self.fw_result=v['remote_root']+'/result.json'
   if phase=='delete':self.fw_result=None
   return v
  except BaseException:
   if phase=='create':
    self.fw_unknown=True
    if receipt.exists():
     rows=[json.loads(line)for line in receipt.read_text().splitlines()];remote=rows[0].get('remote_root')
     if remote:
      # GET-only reconciliation is evidence, never deletion authority.
      self.command([sys.executable,str(D/PINS['firewall'][0]),'--phase','reconcile','--receipt',str(self.path('firewall-reconcile').with_suffix('.jsonl')),'--predecessor-remote-root',remote],'firewall-reconcile-command',timeout=135)
   raise
 def start_target(self):
  self.firewall('create')
  try:self.listener=load('holder').start(self.nonce,self.selected_protocol)
  except BaseException as error:
   self.listener=getattr(error,'owned_holder',None)
   write(self.path('target-start-refused').with_suffix('.json'),{'completed':False,'error_type':type(error).__name__,'cleanup_verified':self.listener is not None and self.listener.restoration_verified is True,'target_cleanup_unknown':self.listener is not None and self.listener.restoration_verified is not True})
   raise
  write(self.path('target-ready').with_suffix('.json'),self.listener.ready);return self.listener.ready
 def stop_target(self,listener):
  v=self.listener.stop();write(self.path('target-stop').with_suffix('.json'),v)
  load('holder').validate_counts(v,self.selected_protocol,self.allow_observed)
 def native(self,phase):
  if not self.unknown_api:self.api('verify')
  mode='allow'if phase in ('before-allow','after-allow')else 'deny'
  root=self.path('native-'+phase);root.mkdir(mode=0o700)
  args=[sys.executable,GUARD_PATH,'--phase',mode,'--selected-protocol',self.selected_protocol,'--state',str(self.state_path),'--state-sha256',hashlib.sha256(self.state_path.read_bytes()).hexdigest(),'--evidence-dir',str(root/'proof')]
  if not self.cleanup:args+=['--outer-deadline',str(self.end)]
  # No baseline, after-deny or cleanup/final observer gets a transition retry.
  if phase=='after-withdrawal' and not self.cleanup:
   if self.confirmed_transition is None or self.confirmed_transition['phase']!='delete-grant':raise ValueError('confirmed own revoke before readiness')
   context_path=root/'transition-context.json';write(context_path,self.confirmed_transition)
   args+=['--transition-context',str(context_path),'--transition-context-sha256',hashlib.sha256(context_path.read_bytes()).hexdigest()]
  self.command(args,'native-command-'+phase)
  v=read(root/'proof'/'result.json')
  if v.get('completed')is not True or v.get('accepted')is not True:raise ValueError('full native/production guard required')
  if mode=='allow'and(v.get('fqdn_authority_qualified')is not True or v.get('native_marked_tuple_qualified')is not True or v.get('compiled_provenance_qualified')is not True or v.get('native_runtime_hash_equality_asserted')is not False or sorted(v.get('exact_resource_ids',[]))!=sorted(r['id']for r in self.state['resources'].values())or v.get('selected_resource_ids')!=[self.state['resources'][self.selected_protocol]['id']]or sorted(v.get('exact_policy_ids',[]))!=sorted(r['id']for r in self.state['grants'].values())):raise ValueError('actual FQDN-only provenance')
 def prove_application(self):
  if self.confirmed_transition is None or self.confirmed_transition['phase']!='create-grant':raise ValueError('confirmed own grant before readiness')
  self.api('verify')
  raw=checked(pathlib.Path(GUARD_PATH),GUARD_SHA)
  observer=types.ModuleType('marked_payload');observer.__file__=GUARD_PATH
  exec(compile(raw,GUARD_PATH,'exec'),observer.__dict__)
  root=self.path('native-application');root.mkdir(mode=0o700)
  try:
   v=observer.run(root/'proof','allow',self.state_path,hashlib.sha256(self.state_path.read_bytes()).hexdigest(),selected_protocol=self.selected_protocol,payload=lambda:self.query('allow'),outer_deadline=self.end,transition_context=self.confirmed_transition)
  finally:self.api('verify')
  if v.get('completed')is not True or v.get('accepted')is not True or v.get('packet_bracketed')is not True:raise ValueError('bracketed actual application proof required')
  if v.get('fqdn_authority_qualified')is not True or v.get('native_marked_tuple_qualified')is not True or v.get('compiled_provenance_qualified')is not True or v.get('native_runtime_hash_equality_asserted')is not False or sorted(v.get('exact_resource_ids',[]))!=sorted(r['id']for r in self.state['resources'].values())or v.get('selected_resource_ids')!=[self.state['resources'][self.selected_protocol]['id']]or sorted(v.get('exact_policy_ids',[]))!=sorted(r['id']for r in self.state['grants'].values()):raise ValueError('actual FQDN-only provenance')
 def query(self,case):
  if self.listener.process.poll()is not None:raise ValueError('target not alive before packet')
  receipt=self.path('packet-'+case).with_suffix('.json')
  self.command([sys.executable,str(D/PINS['packet'][0]),'--case',case,'--protocol',self.selected_protocol,'--nonce',self.nonce,'--receipt',str(receipt)],'packet-command-'+case)
  v=read(receipt);ob=v.get('observation',{})
  if v.get('completed')is not True or v.get('accepted')is not True or ob.get('selected_protocol')!=self.selected_protocol:raise ValueError('actual selected LAN query')
  if case=='allow':self.allow_observed=True
  return ob
 def create_resource(self,protocol):
  if protocol!=self.selected_protocol:raise ValueError('selected resource only')
  self.api('verify');return self.state['resources'][protocol]['id']
 def create_grant(self,rid):
  protocol=next(k for k,v in self.state['resources'].items()if v['id']==rid);self.api('create-grant',protocol);return self.state['grants'][protocol]['id']
 def delete_grant(self,gid):
  protocol=next(k for k,v in self.state['grants'].items()if v['id']==gid);self.api('delete-grant',protocol);return {'completed':True,'deleted_id':gid}
 def reconcile_grant(self,gid):
  # Unknown DELETE retained for ROOT exact-ID GET reconciliation, never replayed.
  return {'completed':False,'absent':False,'id':gid,'unknown_api_outcome':self.unknown_api}
 def generation_once(self):
  v=self.api('generation')
  if v.get('generation_accepted')is True:return 'accepted'
  if v.get('generation_pending_qualified')is True:return 'pending'
  raise ValueError('generation refusal terminal')
 def fresh_generation(self):self.wait_read(self.generation_once,20)
 def begin_application(self):
  if self.application_until is not None:raise ValueError('application readiness window already started')
  self.application_until=min(self.end,shared_clock()+20)
  def prepare():
   v=self.api('generation',min_fresh_seconds=24)
   if v.get('generation_accepted')is True:
    identities=v.get('generation_identities')
    if not isinstance(identities,dict)or set(identities)!={self.selected_protocol}:raise ValueError('complete pre-grant identities')
    self.pre_api_generation_identities=identities
    return 'accepted'
   if v.get('generation_pending_qualified')is True:return 'pending'
   raise ValueError('pre-grant generation refusal terminal')
  self.wait_read(prepare,20,self.application_until)
  # Grant writes and ACK consume the original shared window, never a new window.
  self.read_until=self.application_until
 def application_ready(self):
  if self.application_until is None:raise ValueError('pre-grant readiness required')
  identities=getattr(self,'pre_api_generation_identities',None)
  if not isinstance(identities,dict)or set(identities)!={self.selected_protocol}:raise ValueError('complete pre-grant identities')
  before=self.api('generation',min_fresh_seconds=19)
  if before.get('generation_accepted')is not True or before.get('generation_identities')!=identities:raise ValueError('pre-ACK generation changed or insufficient')
  helper_path=pathlib.Path('/private/tmp/ui-ack-generation-budget-source-20261012-v1/ui_ack_generation_budget_v1.py')
  helper_raw=checked(helper_path,'01c24ee531b3cd6f8058424dabd940dbd1112d40788b9bd50344acc2f26cba3a')
  helper=types.ModuleType('ack_same_generation');exec(compile(helper_raw,str(helper_path),'exec'),helper.__dict__)
  helper.wait_ack_same_generation(self.wait_read,self.ack_once,identities[self.selected_protocol],self.application_until,self.end,shared_clock,time.time,lambda v:write(self.path('ack-readiness-budget').with_suffix('.json'),v))
  # One post-ACK read only: waiting cannot increase this same generation's life.
  self.read_until=self.application_until
  after=self.api('generation',min_fresh_seconds=19)
  if after.get('generation_accepted')is not True:raise ValueError('post-ACK freshness required immediately')
  if identities!=after.get('generation_identities'):raise ValueError('generation changed across grant and ACK')
 def end_application(self):self.read_until=None
 def begin_cleanup(self):self.cleanup=True;self.read_until=None
 def final(self,phase,resources,grants):
  self.cleanup=True
  if phase=='final-native':
   try:
    if self.fw_result:self.firewall('delete')
   finally:
    self.native('final')
    if self.listener is not None and self.listener.restoration_verified is not True:raise ValueError('target cleanup unknown retained; no STOP replay')
  else:
   self.api('retain-resource')
   if grants or self.state['grants']or sorted(resources)!=sorted(r['id']for r in self.state['resources'].values())or self.unknown_api or self.fw_unknown:raise ValueError('no authority/unknown cleanup')

PRE=pathlib.Path('/private/tmp/gcp-fqdn-only-acceptance-prep-20261011/live/actual-app-ec-api-a2e-ackv8-reuse-v3')
STATE=PRE/'125-api-retain-resource/state.json'
STATE_SHA='d5bbbe1b7ef1117b334a72e49f8fbbf7a37957accb99294cf2db6613be5306e7'
RESULT_SHA='6ced0b2af3ae2876b0236bb2f4aac238712ffd6df9842b9f3c582dfe1c416af7'
VALIDATOR=D/'ui-run_fqdn_application_reuse_latest16_ec_api_a2e_ackv8_v1.py'
VALIDATOR_SHA='41564834a836ee3db8ec9ccb45a1435cf6a75984d1fdd2fc0af46a8fc43d0dc9'
KNOWN_TCP_ROOT=pathlib.Path('/private/tmp/gcp-grant-transition-readiness-20261012/v5/actual-selected-tcp-v5-1')
KNOWN_TCP_PINS={'result.json': 'e8cb3eb519b025b548d3699179dac4e1e56177148a575fed2fcc537476e4ce4a', '096-api-retain-resource/state.json': 'd5bbbe1b7ef1117b334a72e49f8fbbf7a37957accb99294cf2db6613be5306e7', '096-api-retain-resource/result.json': 'eb5a0381d1eef8af314322d8391574f54c6947fcebc7508ba174cf12763ca83c', '064-native-application/proof/result.json': 'e3ad0110d1a720facf6809592a5f12a8e14cdc69b0eec5054aebf162c46f0549', '081-native-after-withdrawal/proof/result.json': '80b8d504e5ab49c85ec37f304b5040e92b8309ed30cb8b8b0e48a31fd6aefb2a', '087-native-after-deny/proof/result.json': 'aabf8c1627c82d885ee07cc09ad98b09bd4f2b64023a2425f39661f816fe2e7a', '094-native-final/proof/result.json': '184d0b0d83643a65e1f862e831589e85a8f6bb242b6667dda4e9312cd5d9984a', '094-native-final/proof/native-before.jsonl': '41a26b92505f0dad0f16a2c5187dbefa86c41eb83f61791cc01303fb4c68deba', '094-native-final/proof/native-after.jsonl': '41a26b92505f0dad0f16a2c5187dbefa86c41eb83f61791cc01303fb4c68deba'}
KNOWN_TCP_IDENTITY={'boot_id': '9617762e-19db-4a21-bdee-909dfb31e501', 'container_id': '5ed2a7643f2756b58c2920e7f9f74cf68078c5a794cc128e8a6a112684ce283e', 'image_id': 'sha256:b8f7ccba5b01cc9dd8ca0337c780c69d72e8037fcd5f16adfe98c53af4285ded', 'namespace': 'net:[4026531840]', 'node_sha256': 'cbfabf16f1561f8dfb9d01cc49fad92a8ef2a8fed98dcd96b3e48a5533370bde', 'pid': 3703875, 'pid_start_ticks': 10383458, 'source_commit': '5121dc3374656449dd53dab9abd248216d5d5581', 'started_at': '2026-10-11T19:00:23.223646733Z'}
def exact_v5_tcp_cleanup(selected,result_path,expected,state_path,reader):
 if selected!='udp' or result_path!=KNOWN_TCP_ROOT/'result.json' or expected!=KNOWN_TCP_PINS['result.json'] or state_path!=KNOWN_TCP_ROOT/'096-api-retain-resource/state.json':raise ValueError('exact UDP continuation only')
 documents={}
 for rel,pin in KNOWN_TCP_PINS.items():
  raw=reader.private(KNOWN_TCP_ROOT/rel)
  if hashlib.sha256(raw).hexdigest()!=pin:raise ValueError('accepted TCP evidence pin')
  documents[rel]=json.loads(raw.decode().splitlines()[-1]) if rel.endswith('.jsonl') else json.loads(raw)
 r=documents['result.json']
 if r.get('completed')is not True or r.get('accepted')is not True or r.get('selected_protocol')!='tcp' or r.get('source_sha256')!='0a1f3a095684dbc19bf23ce612884698bb85d2aaa2dd001810a65bcb9f51b4fb' or r.get('simultaneous_pair_asserted')is not False or r.get('cleanup_errors')!=[] or r.get('owned_grants_removed')is not True or r.get('resource_create_replayed')is not False:raise ValueError('accepted TCP cleanup contract')
 for key in ('unknown_api_outcome','unknown_firewall_outcome','target_cleanup_unknown'):
  if r.get(key)is not False:raise ValueError('TCP unknown cleanup')
 for rel in ('064-native-application/proof/result.json','081-native-after-withdrawal/proof/result.json','087-native-after-deny/proof/result.json','094-native-final/proof/result.json'):
  p=documents[rel]
  if p.get('completed')is not True or p.get('accepted')is not True or p.get('source')!=KNOWN_TCP_IDENTITY['source_commit'] or p.get('container')!=KNOWN_TCP_IDENTITY['container_id'] or p.get('simultaneous_pair_qualified')is not False or p.get('native_runtime_hash_equality_asserted')is not False:raise ValueError('current source TCP native contract')
 if documents['064-native-application/proof/result.json'].get('packet_bracketed')is not True:raise ValueError('accepted TCP payload bracket')
 for rel in ('094-native-final/proof/native-before.jsonl','094-native-final/proof/native-after.jsonl'):
  p=documents[rel]
  if p.get('completed')is not True or p.get('observation',{}).get('identity')!=KNOWN_TCP_IDENTITY:raise ValueError('exact serving native identity')
 p=documents['096-api-retain-resource/result.json']
 if p.get('completed')is not True or p.get('baseline_preserved')is not True or p.get('mutations')!=0:raise ValueError('retained normal baseline')
 return True

def predecessor(selected,previous_result=None,previous_sha=None,previous_state=None):
 api=load('api');reader=api.load(api.API,api.API_SHA)
 state_path=pathlib.Path(previous_state)if previous_state else STATE
 raw=reader.private(state_path)
 if hashlib.sha256(raw).hexdigest()!=STATE_SHA:raise ValueError('exact retained histories')
 state=json.loads(raw)
 result_path=pathlib.Path(previous_result)if previous_result else PRE/'result.json'
 raw_result=reader.private(result_path)
 expected=previous_sha if previous_result else RESULT_SHA
 if not expected or hashlib.sha256(raw_result).hexdigest()!=expected:raise ValueError('protected predecessor result hash')
 result=json.loads(raw_result)
 if previous_result:
  # A separately accepted other protocol is cleanup provenance only; never relabel its acceptance.
  if result.get('source_sha256')=='0a1f3a095684dbc19bf23ce612884698bb85d2aaa2dd001810a65bcb9f51b4fb':exact_v5_tcp_cleanup(selected,result_path,expected,state_path,reader)
  else:
   if result.get('accepted')is not True or result.get('selected_protocol') not in ('tcp','udp')or result['selected_protocol']==selected or result.get('source_sha256')!=hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest()or result.get('simultaneous_pair_asserted')is not False:raise ValueError('exact accepted other-protocol predecessor')
  validation_view=dict(result);validation_view['accepted']=False
 else:validation_view=result
 module=types.ModuleType('prior_validator');module.__file__=str(VALIDATOR);exec(compile(checked(VALIDATOR,VALIDATOR_SHA),str(VALIDATOR),'exec'),module.__dict__)
 module.validate(validation_view,state,api.load(D/'api_plan_v2.py',api.PLAN_SHA))
 return state,state_path

def main():
 p=argparse.ArgumentParser();p.add_argument('--out',required=True);p.add_argument('--baseline',required=True);p.add_argument('--cookie-file',required=True);p.add_argument('--selected-protocol',choices=['tcp','udp'],required=True);p.add_argument('--accepted-predecessor');p.add_argument('--accepted-predecessor-sha256');p.add_argument('--accepted-state');p.add_argument('--apply',action='store_true');x=p.parse_args()
 if any('UNBOUND'in v for v in (GUARD_PATH,GUARD_SHA)):raise ValueError('selected proof artifacts unbound before transport')
 if bool(x.accepted_predecessor)!=bool(x.accepted_predecessor_sha256)or bool(x.accepted_predecessor)!=bool(x.accepted_state):raise ValueError('complete accepted predecessor arguments')
 if not x.apply:raise ValueError('explicit ROOT fixture')
 state,state_path=predecessor(x.selected_protocol,x.accepted_predecessor,x.accepted_predecessor_sha256,x.accepted_state)
 for path,h in PINS.values():checked(D/path,h)
 checked(pathlib.Path(ACK_PATH),ACK_SHA);checked(pathlib.Path(GUARD_PATH),GUARD_SHA)
 out=pathlib.Path(x.out);st=out.parent.lstat()
 if not stat.S_ISDIR(st.st_mode)or st.st_uid!=os.getuid()or stat.S_IMODE(st.st_mode)!=0o700:raise ValueError('private parent')
 out.mkdir(mode=0o700,exist_ok=False);cb=Callbacks(out,x.baseline,x.cookie_file,x.selected_protocol,state,state_path);result=load('core').run(cb)
 result.update(retained_resource_ids=cb.retained_resource_ids,target_cleanup_unknown=cb.listener is not None and cb.listener.restoration_verified is not True,unknown_api_outcome=cb.unknown_api,unknown_returned_objects=cb.unknown_owned,unknown_firewall_outcome=cb.fw_unknown,resources_retained_with_history=True,resources_disabled=False,resource_create_replayed=False,source_sha256=hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),retained_state_path=str(cb.state_path))
 result['accepted']=result['accepted']and not cb.unknown_api and not cb.fw_unknown
 write(out/'result.json',result);raise SystemExit(0 if result['accepted']else 1)
if __name__=='__main__':main()
