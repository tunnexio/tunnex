import pathlib,types,json,tempfile,unittest
P=pathlib.Path('/private/tmp/gcp-grant-transition-readiness-20261012/v5/check-selected-transition-v5.py')
n=types.ModuleType('checker');exec(compile(P.read_text(),str(P),'exec'),n.__dict__);n.PINS['marked']=('mock-qualified-selected','mock-hash')
class Bracket(unittest.TestCase):
 def simulate(self,fail=None,packet=None,late=False):
  calls=[];clock=[0.0];identity={'source_commit':'source','container_id':'cid'};projection={'current_binding':{'DesiredRevision':7},'current_delivery_id':'delivery'}
  obs={'completed':True,'identity':identity,'journal_projection':projection}
  def checked(p,h):return json.dumps({'resources':{'tcp':{'id':'tcpresource'},'udp':{'id':'udpresource'}},'grants':{'tcp':{'id':'tcprule'}}}).encode()
  def runner(args,**kw):
   stage=(pathlib.Path(args[args.index('--receipt')+1]).stem if '--receipt'in args else pathlib.Path(args[args.index('--out')+1]).name if '--out'in args else ('guard-after'if 'native-after'in calls else 'guard-before')+'-'+next(k for k in ('ha','classic','ha_dns','classic_dns','marked')if n.PINS[k][0]==args[0])+'-'+args[args.index('-protocol')+1]);calls.append(stage)
   if '--receipt'in args:pathlib.Path(args[args.index('--receipt')+1]).write_text(json.dumps({'completed':True,'observation':obs})+'\n')
   kw['stdout'].write(json.dumps({'completed':True,'accepted':True,'mutations':0}).encode());return types.SimpleNamespace(returncode=1 if fail==stage else 0)
  def settle(capture,verify,*a,**kw):verify(b'{}',80)
  oldchecked=n.checked;oldpath=n.runpy.run_path;n.checked=checked;n.runpy.run_path=lambda p:{'settle_capture':settle}
  def payload():
   calls.append('payload')
   if late:clock[0]=81
   return packet if packet is not None else {'completed':True,'accepted':True,'case':'allow'}
  try:
   with tempfile.TemporaryDirectory()as d:
    out=pathlib.Path(d)/'proof'
    try:result=n.run(out,'allow',pathlib.Path('state'),'hash','tcp',runner=runner,clock=lambda:clock[0],payload=payload,outer_deadline=80)
    except BaseException:result=json.loads((out/'result.json').read_text())
    return calls,result
  finally:n.checked=oldchecked;n.runpy.run_path=oldpath
 def test_packet_inside_full_before_after(self):
  c,r=self.simulate();self.assertTrue(r['packet_bracketed']);self.assertLess(c.index('provenance-before'),c.index('payload'));self.assertLess(c.index('payload'),c.index('native-after'));self.assertEqual(c[-1],'provenance-after');self.assertEqual(r['exact_resource_ids'],['tcpresource','udpresource']);self.assertEqual(r['selected_resource_ids'],['tcpresource']);self.assertEqual(r['exact_policy_ids'],['tcprule']);self.assertFalse(r['simultaneous_pair_qualified']);self.assertTrue(all('guard-before-'+p+'-'+q in c and 'guard-after-'+p+'-'+q in c for p in ('ha','classic','ha_dns','classic_dns')for q in ('tcp','udp')))
 def test_packet_refusal_still_after(self):
  c,r=self.simulate(packet={'completed':True,'accepted':False,'case':'allow'});self.assertFalse(r['completed']);self.assertFalse(r['packet_bracketed']);self.assertIn('native-after',c);self.assertIn('provenance-after',c)
 def test_before_failure_zero_packet(self):
  c,r=self.simulate(fail='guard-before-marked-tcp');self.assertNotIn('payload',c);self.assertIn('native-after',c);self.assertFalse(r['completed'])
 def test_after_failure_never_accepted(self):
  c,r=self.simulate(fail='guard-after-marked-tcp');self.assertIn('payload',c);self.assertFalse(r['completed']);self.assertFalse(r['packet_bracketed'])
 def test_original_deadline_not_reset(self):
  c,r=self.simulate(late=True);self.assertFalse(r['completed']);self.assertFalse(r['packet_bracketed']);self.assertEqual(r['error_type'],'TimeoutError')
if __name__=='__main__':unittest.main()
