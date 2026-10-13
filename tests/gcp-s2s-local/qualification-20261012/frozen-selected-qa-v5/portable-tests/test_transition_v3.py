import unittest,runpy,pathlib,json,hashlib,copy
D=pathlib.Path(__file__).parent
m=runpy.run_path(str(D/'transition_contract.py'));s=runpy.run_path(str(D/'strict-settle-transition-v3.py'))
CAP=pathlib.Path('/private/tmp/provider-gcp-cloud-expiry-observer-5121dc33-actual-measured-callbacks-v1/poststart-8cdf4b98b51a437fb7cb7626b0ac3696-guard-before-1.json')
class Tests(unittest.TestCase):
 def test_rfc3339_actual_fractional_precision_and_invalid(self):
  for t in ('2026-10-11T19:07:45.07948Z','2026-10-11T19:07:45.079480113Z','2026-10-11T19:07:45Z'):self.assertIsInstance(m['utc'](t),float)
  for t in ('2026-10-11T19:07:45.1234567890Z','2026-10-11T19:07:45.1','garbage'):
   with self.assertRaises(ValueError):m['utc'](t)
 def fixture(self):
  raw=CAP.read_bytes();cap=json.loads(raw);sha=hashlib.sha256(raw).hexdigest()
  native={'completed':True,'identity':copy.deepcopy(m['IDENTITY']),'journal_projection':{'current_binding':{'DesiredRevision':7}}}
  zero={'completed':True,'guard_transition_qualified':True,'packet_authority':False,'capture_sha256':sha,'source':m['IDENTITY']['source_commit']}
  ha={k:{'completed':True,'capture_sha256':sha,'observation':{'expect':'allow','protocol':k.rsplit('_',1)[1],'source':m['IDENTITY']['source_commit'],'readback':'positive','guard_revision':cap['expected_guard']['Revision'],'guard_digest':cap['expected_guard']['Digest']}}for k in ('ha_tcp','ha_udp','ha_dns_tcp','ha_dns_udp')}
  return [raw,native,zero,ha,'allow','tcp']
 def test_same_capture_zero_authority_both_phases(self):
  for phase in ('allow','deny'):
   f=self.fixture();f[4]=phase;r=m['pending'](*f);self.assertTrue(r['known_transition_pending']);self.assertFalse(r['packet_authority']);self.assertFalse(r['completed'])
 def test_native_nine_fields_and_ha_refusals_terminal(self):
  for key in m['IDENTITY']:
   f=self.fixture();f[1]['identity'][key]='foreign'
   with self.assertRaises(ValueError):m['pending'](*f)
  for key in ('readback','guard_revision','guard_digest','expect','source','protocol'):
   f=self.fixture();f[3]['ha_udp']['observation'][key]='foreign'
   with self.assertRaises(ValueError):m['pending'](*f)
  f=self.fixture();f[2]['packet_authority']=True
  with self.assertRaises(ValueError):m['pending'](*f)
 def test_one_settle_deadline_pending_then_full(self):
  now=[0.];seen=[];calls=[0]
  def verify(raw,end):
   calls[0]+=1
   if calls[0]==1:raise s['KnownPendingCapture']({'known_transition_pending':True,'packet_authority':False})
  result=s['settle_capture'](lambda remaining:seen.append(remaining)or(0,b'raw'),verify,lambda receipt:None,clock=lambda:now[0],sleep=lambda n:now.__setitem__(0,now[0]+n),outer_deadline=80)
  self.assertEqual(result,b'raw');self.assertEqual(seen,[10,9]);self.assertEqual(calls[0],2)
 def test_unknown_refusal_no_retry(self):
  calls=[]
  def refusal(*a):raise ValueError('foreign/native/unknown')
  with self.assertRaises(ValueError):s['settle_capture'](lambda n:calls.append(n)or(0,b'raw'),refusal,lambda r:self.fail('unknown cannot pending'),clock=lambda:0,outer_deadline=80)
  self.assertEqual(calls,[10])
 def test_remaining_outer_budget_and_no_pending_authority(self):
  now=[77.]
  def pending(*a):raise s['KnownPendingCapture']({'known_transition_pending':True,'packet_authority':False})
  with self.assertRaises(TimeoutError):s['settle_capture'](lambda n:(0,b'raw'),pending,lambda r:None,clock=lambda:now[0],sleep=lambda n:now.__setitem__(0,now[0]+n),outer_deadline=80)
  self.assertEqual(now[0],80)
  def unsafe(*a):raise s['KnownPendingCapture']({'known_transition_pending':True,'packet_authority':True})
  with self.assertRaises(ValueError):s['settle_capture'](lambda n:(0,b'raw'),unsafe,lambda r:None,clock=lambda:0,outer_deadline=80)
 def test_original_two_template_grammar_remains_strict(self):
  v={'completed':False,'guard_publication_pending':True,'guard_count':2,'templates':[{'Namespace':'net:[4026531840]','Revision':1,'Digest':'a'*64},{'Namespace':'net:[4026531840]','Revision':2,'Digest':'b'*64}],'source_commit':s['SOURCE'],'container_id':s['CID'],'image_id':s['IMAGE'],'namespace_before':'net:[4026531840]','namespace_after':'net:[4026531840]','reader_sha256':'7156559ea0d2d062a40af33952eb412833a191cb7179e9ad9efe8b146a563d7f','scope':'partial metadata only; no full guard proof or packet acceptance'}
  self.assertEqual(s['pending_metadata'](v),v);v['guard_count']=3
  with self.assertRaises(ValueError):s['pending_metadata'](v)
# Additional mutation contract tests use fixed synthetic documents, never cloud/API.
class MutationTests(unittest.TestCase):
 def fixture(self,phase):
  gid='01a12c5d-1857-7ee2-a9d2-d8f86dd2f23a';grant={'id':gid,'enabled':True,'dst_fqdn_resource_id':'tcpresource'}
  state={'resources':{'tcp':{'id':'tcpresource'},'udp':{'id':'udpresource'}},'grants':{'tcp':grant}if phase=='allow'else{}}
  docs={'result':{'completed':True,'baseline_preserved':True,'mutation_attempted':True,'mutations':1},'attempt':{'method':'POST'if phase=='allow'else'DELETE','path':'/policies'if phase=='allow'else'/policies/'+gid,'replay_forbidden':True},'response':{'status':201 if phase=='allow'else 204,'body':grant if phase=='allow'else None}}
  context={'phase':'create-grant'if phase=='allow'else'delete-grant','protocol':'tcp','grant_id':gid,'state_sha256':'state-hash','confirmed_monotonic':0.,'fixture_end_monotonic':80.}
  raw={k:json.dumps(v).encode()for k,v in docs.items()}
  for k in docs:context[k+'_path']=k;context[k+'_sha256']=hashlib.sha256(raw[k]).hexdigest()
  def read(p,h):
   if hashlib.sha256(raw[p]).hexdigest()!=h:raise ValueError('hash drift')
   return raw[p]
  return context,state,read,raw
 def test_confirmed_create_and_delete_only(self):
  for phase in ('allow','deny'):
   c,state,read,_=self.fixture(phase);self.assertEqual(m['mutation_context'](c,state,'state-hash',phase,'tcp',read),c)
 def test_unknown_foreign_phase_or_changed_state_terminal(self):
  for change in ('phase','state','hash','unknown','grant'):
   c,state,read,raw=self.fixture('allow')
   if change=='phase':c['phase']='delete-grant'
   elif change=='state':c['state_sha256']='foreign'
   elif change=='hash':c['response_sha256']='0'*64
   elif change=='unknown':
    raw['result']=json.dumps({'completed':False,'baseline_preserved':True,'mutation_attempted':True,'mutations':1}).encode();c['result_sha256']=hashlib.sha256(raw['result']).hexdigest()
   else:state['grants']['udp']={'id':'foreign'}
   with self.assertRaises(ValueError):m['mutation_context'](c,state,'state-hash','allow','tcp',read)

if __name__=='__main__':unittest.main()
