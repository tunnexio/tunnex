"""Real checker control flow with substituted I/O; no transport or live qualification."""
import pathlib,types,json,tempfile,unittest,runpy,hashlib
D=pathlib.Path(__file__).parent;PathParent=pathlib.Path('/private/tmp/gcp-grant-transition-readiness-20261012/v3')
P=D/'check-selected-transition-v5.py';n=types.ModuleType('checker');exec(compile(P.read_text(),str(P),'exec'),n.__dict__)
contract=runpy.run_path(str(PathParent/'transition_contract.py'));settle=runpy.run_path(str(PathParent/'strict-settle-transition-v3.py'))
RAW=pathlib.Path('/private/tmp/provider-gcp-cloud-expiry-observer-5121dc33-actual-measured-callbacks-v1/poststart-8cdf4b98b51a437fb7cb7626b0ac3696-guard-before-1.json').read_bytes()
CAP=json.loads(RAW);SHA=hashlib.sha256(RAW).hexdigest()
class Bracket(unittest.TestCase):
 def simulate(self,zero_refused=False,ha_refused=False,after_refused=False,context=True,packet_refused=False):
  calls=[];clock=[0.];pending_count=[0];classic_before=[0]
  obs={'completed':True,'identity':contract['IDENTITY'],'journal_projection':{'current_binding':{'DesiredRevision':7},'current_delivery_id':'delivery'}}
  state={'resources':{'tcp':{'id':'tcpresource'},'udp':{'id':'udpresource'}},'grants':{'tcp':{'id':'tcprule'}}}
  def checked(*a):return json.dumps(state).encode()
  def runner(args,**kw):
   if '--receipt'in args:
    stage=pathlib.Path(args[args.index('--receipt')+1]).stem;calls.append(stage)
    pathlib.Path(args[args.index('--receipt')+1]).write_text(json.dumps({'completed':True,'observation':obs})+'\n')
    kw['stdout'].write(b'{}');return types.SimpleNamespace(returncode=0)
   if '--out'in args:
    stage=pathlib.Path(args[args.index('--out')+1]).name;calls.append(stage)
    kw['stdout'].write(json.dumps({'completed':True,'accepted':True,'mutations':0}).encode());return types.SimpleNamespace(returncode=0)
   profile=next(k for k in ('ha','classic','ha_dns','classic_dns','marked','transition')if n.PINS[k][0]==args[0]);protocol=args[args.index('-protocol')+1]
   stage=('guard-after'if 'native-after'in calls else'guard-before')+'-'+profile+'-'+protocol;calls.append(stage)
   value={'completed':True,'capture_sha256':SHA,'observation':{'source':contract['IDENTITY']['source_commit'],'expect':'allow','protocol':protocol,'readback':'positive','guard_revision':CAP['expected_guard']['Revision'],'guard_digest':CAP['expected_guard']['Digest']}}
   rc=0
   if profile=='classic'and 'native-after'not in calls:
    classic_before[0]+=1
    if classic_before[0]==1:rc=1;value={'completed':False}
   if profile=='transition':
    rc=1 if zero_refused else 0
    value={'completed':not zero_refused,'capture_sha256':SHA,'source':contract['IDENTITY']['source_commit'],'guard_transition_qualified':True,'packet_authority':False}
   if ha_refused and profile=='ha':rc=1;value={'completed':False}
   if after_refused and profile=='marked'and 'native-after'in calls:rc=1;value={'completed':False}
   kw['stdout'].write(json.dumps(value).encode());return types.SimpleNamespace(returncode=rc)
  original_checked=n.checked;original_runpath=n.runpy.run_path
  # Mutation contract has its own independent schema tests; substitute it only here.
  def load(path):
   if path==n.PINS['contract'][0]:return dict(contract,mutation_context=lambda *a:None)
   def observe(capture,verify,record,**kw):
    def capture_model(remaining):calls.append('capture');return 0,RAW
    def save(v):pending_count[0]+=1;calls.append('pending');record(v)
    return settle['settle_capture'](capture_model,verify,save,clock=kw['clock'],outer_deadline=kw.get('outer_deadline'),sleep=lambda seconds:clock.__setitem__(0,clock[0]+seconds))
   return {'settle_capture':observe,'KnownPendingCapture':settle['KnownPendingCapture']}
  n.checked=checked;n.runpy.run_path=load
  def payload():
   calls.append('payload');return {'completed':True,'accepted':not packet_refused,'case':'allow'}
  try:
   with tempfile.TemporaryDirectory()as d:
    out=pathlib.Path(d)/'proof'
    ctx={'confirmed_monotonic':0.,'fixture_end_monotonic':80.}if context else None
    try:r=n.run(out,'allow',pathlib.Path('state'),'hash','tcp',runner=runner,clock=lambda:clock[0],payload=payload,outer_deadline=80,transition_context=ctx)
    except BaseException:r=json.loads((out/'result.json').read_text())
    return calls,r,pending_count[0]
  finally:n.checked=original_checked;n.runpy.run_path=original_runpath
 def test_pending_then_full_positive_before_single_payload(self):
  calls,r,count=self.simulate();self.assertTrue(r['accepted']);self.assertTrue(r['packet_bracketed']);self.assertEqual(count,1);self.assertEqual(calls.count('payload'),1);self.assertLess(calls.index('pending'),calls.index('provenance-before'));self.assertLess(calls.index('provenance-before'),calls.index('payload'));self.assertLess(calls.index('payload'),calls.index('native-after'))
  for p in ('ha','ha_dns','classic','classic_dns'):
   for q in ('tcp','udp'):self.assertIn('guard-before-'+p+'-'+q,calls);self.assertIn('guard-after-'+p+'-'+q,calls)
 def test_unknown_zero_native_or_ha_refusal_has_no_payload(self):
  for kwargs in ({'zero_refused':True},{'ha_refused':True},{'context':False}):
   calls,r,count=self.simulate(**kwargs);self.assertNotIn('payload',calls);self.assertFalse(r['completed']);self.assertIn('native-after',calls);self.assertEqual(count,0)
 def test_payload_or_after_refusal_retains_after_and_never_accepts(self):
  for kwargs in ({'packet_refused':True},{'after_refused':True}):
   calls,r,count=self.simulate(**kwargs);self.assertFalse(r['completed']);self.assertFalse(r['packet_bracketed']);self.assertIn('native-after',calls);self.assertEqual(calls.count('payload'),1)
if __name__=='__main__':unittest.main()
